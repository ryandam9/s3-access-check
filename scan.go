package main

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ScanOptions controls a bucket-wide object scan.
type ScanOptions struct {
	Prefix      string // only enumerate keys under this prefix
	MaxObjects  int    // stop after enumerating this many keys (0 = no limit)
	Concurrency int    // number of concurrent anonymous probes
	KeysFrom    string // path to a newline-delimited key list; if set, the S3 API is not used
	Region      string // resolved bucket region
}

// ObjectFinding is the anonymous-access result for a single object.
type ObjectFinding struct {
	Key    string      `json:"key"`
	State  AccessState `json:"state"`
	Status int         `json:"httpStatus,omitempty"`
	S3Code string      `json:"s3Code,omitempty"`
	Err    string      `json:"error,omitempty"`
}

// ScanResult summarizes a bucket scan. Complete distinguishes an exhaustive,
// fully-probed scan from one cut short by truncation, cancellation, or
// inconclusive probes — the difference between "no public objects" and "no
// public objects found in what was actually checked".
type ScanResult struct {
	Bucket            string          `json:"bucket"`
	Region            string          `json:"region"`
	Source            string          `json:"source"` // "s3-api" or "keys-file"
	Complete          bool            `json:"complete"`
	Truncated         bool            `json:"truncated"`
	Cancelled         bool            `json:"cancelled"`
	Enumerated        int             `json:"enumerated"`
	Completed         int             `json:"completed"`
	PublicCount       int             `json:"publicCount"`
	NotPublicCount    int             `json:"notPublicCount"`
	InconclusiveCount int             `json:"inconclusiveCount"`
	PublicObjects     []ObjectFinding `json:"publicObjects"`
	Failures          []ObjectFinding `json:"failures,omitempty"`
}

// ScanBucket enumerates a bucket's objects (via the S3 API using AWS
// credentials, or from a supplied key list) and probes each one anonymously,
// reporting which objects are publicly accessible even when the bucket itself
// is not publicly listable. Enumeration is streamed into a bounded worker pool
// so memory stays flat regardless of bucket size.
func ScanBucket(ctx context.Context, c *http.Client, bucket string, opts ScanOptions) (ScanResult, error) {
	res := ScanResult{Bucket: bucket, Region: opts.Region}
	if opts.KeysFrom != "" {
		res.Source = "keys-file"
	} else {
		res.Source = "s3-api"
	}

	keys := make(chan string, 256)
	var (
		enumerated int
		truncated  bool
		prodErr    error
	)
	prodDone := make(chan struct{})
	go func() {
		defer close(keys)
		defer close(prodDone)
		if opts.KeysFrom != "" {
			enumerated, truncated, prodErr = streamKeysFromFile(ctx, opts.KeysFrom, opts.Prefix, opts.MaxObjects, keys)
		} else {
			enumerated, truncated, prodErr = streamKeysFromS3(ctx, bucket, opts, keys)
		}
	}()

	workers := opts.Concurrency
	if workers < 1 {
		workers = 1
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for key := range keys {
				r, _ := ProbeObject(ctx, c, opts.Region, Target{Bucket: bucket, Key: key})
				f := ObjectFinding{Key: key, State: r.State, Status: r.StatusCode, S3Code: r.S3Code, Err: r.Err}
				mu.Lock()
				res.Completed++
				switch r.State {
				case AccessPublic:
					res.PublicCount++
					res.PublicObjects = append(res.PublicObjects, f)
				case AccessNotPublic:
					res.NotPublicCount++
				default:
					res.InconclusiveCount++
					res.Failures = append(res.Failures, f)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	<-prodDone

	res.Enumerated = enumerated
	res.Truncated = truncated
	res.Cancelled = ctx.Err() != nil

	// A failure to enumerate (denied listing, no credentials, transport error)
	// is a hard error — the scan established nothing.
	if prodErr != nil && !res.Cancelled {
		return res, prodErr
	}

	res.Complete = prodErr == nil && !res.Truncated && !res.Cancelled && res.InconclusiveCount == 0

	sort.Slice(res.PublicObjects, func(i, j int) bool { return res.PublicObjects[i].Key < res.PublicObjects[j].Key })
	sort.Slice(res.Failures, func(i, j int) bool { return res.Failures[i].Key < res.Failures[j].Key })
	return res, nil
}

// streamKeysFromS3 lists object keys using AWS credentials and streams them into
// out. It reads one key beyond MaxObjects to distinguish an exactly-at-limit
// scan (not truncated) from a genuinely truncated one.
func streamKeysFromS3(ctx context.Context, bucket string, opts ScanOptions, out chan<- string) (enumerated int, truncated bool, err error) {
	cfgOpts := []func(*awsconfig.LoadOptions) error{}
	if opts.Region != "" {
		cfgOpts = append(cfgOpts, awsconfig.WithRegion(opts.Region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return 0, false, fmt.Errorf("loading AWS config: %w", err)
	}
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		return 0, false, fmt.Errorf("scanning needs AWS credentials to list objects (or use --keys-from): %w", err)
	}

	client := s3.NewFromConfig(cfg)
	in := &s3.ListObjectsV2Input{Bucket: aws.String(bucket)}
	if opts.Prefix != "" {
		in.Prefix = aws.String(opts.Prefix)
	}
	p := s3.NewListObjectsV2Paginator(client, in)
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return enumerated, truncated, ctx.Err()
			}
			return enumerated, truncated, fmt.Errorf("listing objects: %s", friendlyErr(err))
		}
		for _, o := range page.Contents {
			key := aws.ToString(o.Key)
			if opts.MaxObjects > 0 && enumerated >= opts.MaxObjects {
				// One more key exists beyond the cap: genuinely truncated.
				return enumerated, true, nil
			}
			select {
			case out <- key:
				enumerated++
			case <-ctx.Done():
				return enumerated, truncated, ctx.Err()
			}
		}
	}
	return enumerated, false, nil
}

// streamKeysFromFile reads candidate keys from a newline-delimited file and
// streams them into out. To preserve exact S3 key bytes it trims only a
// trailing CR (from CRLF files) and does not strip leading slashes, spaces, or
// treat any line as a comment. Empty lines are skipped.
func streamKeysFromFile(ctx context.Context, path, prefix string, max int, out chan<- string) (enumerated int, truncated bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false, fmt.Errorf("opening keys file: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		key := strings.TrimSuffix(sc.Text(), "\r")
		if key == "" {
			continue
		}
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			continue
		}
		if max > 0 && enumerated >= max {
			return enumerated, true, nil
		}
		select {
		case out <- key:
			enumerated++
		case <-ctx.Done():
			return enumerated, truncated, ctx.Err()
		}
	}
	return enumerated, false, sc.Err()
}
