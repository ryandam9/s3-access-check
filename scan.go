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
	Key    string `json:"key"`
	Public bool   `json:"public"`
	Status int    `json:"httpStatus"`
	S3Code string `json:"s3Code,omitempty"`
}

// ScanResult summarizes a bucket scan.
type ScanResult struct {
	Bucket        string          `json:"bucket"`
	Region        string          `json:"region"`
	Source        string          `json:"source"` // "s3-api" or "keys-file"
	Enumerated    int             `json:"enumerated"`
	Probed        int             `json:"probed"`
	Truncated     bool            `json:"truncated"` // hit MaxObjects during enumeration
	PublicObjects []ObjectFinding `json:"publicObjects"`
}

// ScanBucket enumerates a bucket's objects (via the S3 API using AWS
// credentials, or from a supplied key list) and probes each one anonymously,
// reporting which objects are publicly accessible even when the bucket itself
// is not publicly listable.
func ScanBucket(ctx context.Context, c *http.Client, bucket string, opts ScanOptions) (ScanResult, error) {
	res := ScanResult{Bucket: bucket, Region: opts.Region}

	var (
		keys []string
		err  error
	)
	if opts.KeysFrom != "" {
		res.Source = "keys-file"
		keys, res.Truncated, err = keysFromFile(opts.KeysFrom, opts.Prefix, opts.MaxObjects)
	} else {
		res.Source = "s3-api"
		keys, res.Truncated, err = keysFromS3(ctx, bucket, opts)
	}
	if err != nil {
		return res, err
	}
	res.Enumerated = len(keys)
	if len(keys) == 0 {
		return res, nil
	}

	host := regionalHost(opts.Region)
	findings := probeKeys(ctx, c, host, opts.Region, bucket, keys, opts.Concurrency)
	res.Probed = len(findings)
	for _, f := range findings {
		if f.Public {
			res.PublicObjects = append(res.PublicObjects, f)
		}
	}
	sort.Slice(res.PublicObjects, func(i, j int) bool {
		return res.PublicObjects[i].Key < res.PublicObjects[j].Key
	})
	return res, nil
}

// keysFromS3 lists object keys using AWS credentials.
func keysFromS3(ctx context.Context, bucket string, opts ScanOptions) (keys []string, truncated bool, err error) {
	cfgOpts := []func(*awsconfig.LoadOptions) error{}
	if opts.Region != "" {
		cfgOpts = append(cfgOpts, awsconfig.WithRegion(opts.Region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return nil, false, fmt.Errorf("loading AWS config: %w", err)
	}
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		return nil, false, fmt.Errorf("scanning needs AWS credentials to list objects (or use --keys-from): %w", err)
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
			return nil, false, fmt.Errorf("listing objects: %s", friendlyErr(err))
		}
		for _, o := range page.Contents {
			keys = append(keys, aws.ToString(o.Key))
			if opts.MaxObjects > 0 && len(keys) >= opts.MaxObjects {
				return keys, true, nil
			}
		}
	}
	return keys, false, nil
}

// keysFromFile reads candidate keys from a newline-delimited file, applying the
// prefix filter and object cap. This path needs no AWS credentials.
func keysFromFile(path, prefix string, max int) (keys []string, truncated bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, fmt.Errorf("opening keys file: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		key := strings.TrimSpace(sc.Text())
		if key == "" || strings.HasPrefix(key, "#") {
			continue
		}
		key = strings.TrimPrefix(key, "/")
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			continue
		}
		keys = append(keys, key)
		if max > 0 && len(keys) >= max {
			return keys, true, sc.Err()
		}
	}
	return keys, false, sc.Err()
}

// probeKeys runs anonymous object probes across a bounded worker pool.
func probeKeys(ctx context.Context, c *http.Client, host, region, bucket string, keys []string, concurrency int) []ObjectFinding {
	if concurrency < 1 {
		concurrency = 1
	}
	findings := make([]ObjectFinding, len(keys))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, key := range keys {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, key string) {
			defer wg.Done()
			defer func() { <-sem }()

			f := ObjectFinding{Key: key}
			r, err := ProbeObject(ctx, c, host, region, Target{Bucket: bucket, Key: key})
			if err != nil {
				f.S3Code = "probe-error"
			} else {
				f.Public = r.Public
				f.Status = r.StatusCode
				f.S3Code = r.S3Code
			}
			findings[i] = f
		}(i, key)
	}
	wg.Wait()
	return findings
}
