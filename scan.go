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
	Prefix          string // only enumerate keys under this prefix
	MaxObjects      int    // stop after enumerating this many keys (0 = no limit)
	Concurrency     int    // number of concurrent anonymous probes
	KeysFrom        string // path to a newline-delimited key list; if set, the S3 API is not used
	IncludeVersions bool   // enumerate every object version, not just current
	Region          string // resolved bucket region
}

// scanKey is one unit of work: an object key and, optionally, a specific
// version to probe.
type scanKey struct {
	Key       string
	VersionID string
}

// ObjectFinding is the anonymous-access result for a single object (version).
type ObjectFinding struct {
	Key       string      `json:"key"`
	VersionID string      `json:"versionId,omitempty"`
	State     AccessState `json:"state"`
	Status    int         `json:"httpStatus,omitempty"`
	S3Code    string      `json:"s3Code,omitempty"`
	Err       string      `json:"error,omitempty"`
}

// ScanResult summarizes a bucket scan. Complete distinguishes an exhaustive,
// fully-probed scan from one cut short by truncation, cancellation, or
// inconclusive probes. Scope records whether all versions were covered — a
// "complete" current-versions scan does not certify noncurrent versions.
type ScanResult struct {
	Bucket            string          `json:"bucket"`
	Region            string          `json:"region"`
	Source            string          `json:"source"` // "s3-api" or "keys-file"
	Scope             string          `json:"scope"`  // "current_versions" or "all_versions"
	Complete          bool            `json:"complete"`
	Truncated         bool            `json:"truncated"`
	Cancelled         bool            `json:"cancelled"`
	Enumerated        int             `json:"enumerated"`
	Completed         int             `json:"completed"`
	PublicCount       int             `json:"publicCount"`
	NotPublicCount    int             `json:"notPublicCount"`
	InconclusiveCount int             `json:"inconclusiveCount"`
	PublicObjects     []ObjectFinding `json:"publicObjects"`
	Failures          []ObjectFinding `json:"failures"`
	Warnings          []string        `json:"warnings,omitempty"`
}

const (
	scopeCurrent = "current_versions"
	scopeAll     = "all_versions"
)

// ScanBucket enumerates a bucket's objects (via the S3 API using AWS
// credentials, or from a supplied key list) and probes each one anonymously,
// reporting which objects are publicly accessible even when the bucket itself
// is not publicly listable. Enumeration is streamed into a bounded worker pool
// so memory stays flat regardless of bucket size.
func ScanBucket(ctx context.Context, c *http.Client, bucket string, opts ScanOptions) (ScanResult, error) {
	res := ScanResult{
		Bucket:        bucket,
		Region:        opts.Region,
		PublicObjects: []ObjectFinding{},
		Failures:      []ObjectFinding{},
	}
	if opts.KeysFrom != "" {
		res.Source = "keys-file"
	} else {
		res.Source = "s3-api"
	}
	if opts.IncludeVersions {
		res.Scope = scopeAll
	} else {
		res.Scope = scopeCurrent
	}

	// When scanning only current versions via the S3 API, warn if the bucket
	// has versioning — noncurrent versions can be independently public.
	if opts.KeysFrom == "" && !opts.IncludeVersions {
		if status, err := bucketVersioningStatus(ctx, bucket, opts.Region); err == nil && status != "" {
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"bucket versioning is %s; noncurrent object versions were NOT scanned — pass --include-versions for a full audit", strings.ToLower(status)))
		}
	}

	keys := make(chan scanKey, 256)
	var (
		enumerated int
		truncated  bool
		prodErr    error
	)
	prodDone := make(chan struct{})
	go func() {
		defer close(keys)
		defer close(prodDone)
		switch {
		case opts.KeysFrom != "":
			enumerated, truncated, prodErr = streamKeysFromFile(ctx, opts.KeysFrom, opts.Prefix, opts.MaxObjects, keys)
		case opts.IncludeVersions:
			enumerated, truncated, prodErr = streamVersionsFromS3(ctx, bucket, opts, keys)
		default:
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
			for k := range keys {
				r, err := ProbeObject(ctx, c, opts.Region, Target{Bucket: bucket, Key: k.Key, VersionID: k.VersionID})
				if err != nil {
					r.State = AccessInconclusive
					r.Err = err.Error()
				}
				f := ObjectFinding{Key: k.Key, VersionID: k.VersionID, State: r.State, Status: r.StatusCode, S3Code: r.S3Code, Err: r.Err}
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

	sort.Slice(res.PublicObjects, func(i, j int) bool { return lessFinding(res.PublicObjects[i], res.PublicObjects[j]) })
	sort.Slice(res.Failures, func(i, j int) bool { return lessFinding(res.Failures[i], res.Failures[j]) })
	return res, nil
}

func lessFinding(a, b ObjectFinding) bool {
	if a.Key != b.Key {
		return a.Key < b.Key
	}
	return a.VersionID < b.VersionID
}

// loadS3Client builds an S3 client from the default credential chain, failing
// with a clear message when no credentials are available.
func loadS3Client(ctx context.Context, region string) (*s3.Client, error) {
	cfgOpts := []func(*awsconfig.LoadOptions) error{}
	if region != "" {
		cfgOpts = append(cfgOpts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		return nil, fmt.Errorf("scanning needs AWS credentials to list objects (or use --keys-from): %w", err)
	}
	return s3.NewFromConfig(cfg), nil
}

// bucketVersioningStatus returns "Enabled", "Suspended", or "" (never
// configured). Errors are returned so the caller can treat detection as
// best-effort.
func bucketVersioningStatus(ctx context.Context, bucket, region string) (string, error) {
	client, err := loadS3Client(ctx, region)
	if err != nil {
		return "", err
	}
	out, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(bucket)})
	if err != nil {
		return "", err
	}
	return string(out.Status), nil
}

// streamKeysFromS3 lists current object keys and streams them into out. It
// stops one key past MaxObjects to distinguish an exactly-at-limit scan (not
// truncated) from a genuinely truncated one.
func streamKeysFromS3(ctx context.Context, bucket string, opts ScanOptions, out chan<- scanKey) (enumerated int, truncated bool, err error) {
	client, err := loadS3Client(ctx, opts.Region)
	if err != nil {
		return 0, false, err
	}
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
			if opts.MaxObjects > 0 && enumerated >= opts.MaxObjects {
				return enumerated, true, nil
			}
			select {
			case out <- scanKey{Key: aws.ToString(o.Key)}:
				enumerated++
			case <-ctx.Done():
				return enumerated, truncated, ctx.Err()
			}
		}
	}
	return enumerated, false, nil
}

// streamVersionsFromS3 lists every object version (excluding delete markers)
// and streams each as a version-qualified probe target.
func streamVersionsFromS3(ctx context.Context, bucket string, opts ScanOptions, out chan<- scanKey) (enumerated int, truncated bool, err error) {
	client, err := loadS3Client(ctx, opts.Region)
	if err != nil {
		return 0, false, err
	}
	in := &s3.ListObjectVersionsInput{Bucket: aws.String(bucket)}
	if opts.Prefix != "" {
		in.Prefix = aws.String(opts.Prefix)
	}
	p := s3.NewListObjectVersionsPaginator(client, in)
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return enumerated, truncated, ctx.Err()
			}
			return enumerated, truncated, fmt.Errorf("listing object versions: %s", friendlyErr(err))
		}
		for _, v := range page.Versions {
			if opts.MaxObjects > 0 && enumerated >= opts.MaxObjects {
				return enumerated, true, nil
			}
			select {
			case out <- scanKey{Key: aws.ToString(v.Key), VersionID: aws.ToString(v.VersionId)}:
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
// treat any line as a comment. Empty lines are skipped. (A newline-delimited
// format cannot represent a key containing a literal newline.)
func streamKeysFromFile(ctx context.Context, path, prefix string, max int, out chan<- scanKey) (enumerated int, truncated bool, err error) {
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
		case out <- scanKey{Key: key}:
			enumerated++
		case <-ctx.Done():
			return enumerated, truncated, ctx.Err()
		}
	}
	return enumerated, false, sc.Err()
}
