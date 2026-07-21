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

// s3ListAPI is the subset of the S3 client used for enumeration. Depending on it
// (rather than the concrete client) lets tests inject a fake to exercise
// pagination, versions, and versioning detection without network access.
type s3ListAPI interface {
	ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	ListObjectVersions(context.Context, *s3.ListObjectVersionsInput, ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error)
	GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
}

// ScanOptions controls a bucket-wide object scan.
type ScanOptions struct {
	Prefix          string // only enumerate keys under this prefix
	MaxObjects      int    // stop after enumerating this many targets (0 = no limit)
	MaxFindings     int    // cap retained public/failure examples (0 = no cap); counts stay exact
	Concurrency     int    // number of concurrent anonymous probes
	KeysFrom        string // path to a newline-delimited key list; if set, the S3 API is not used
	IncludeVersions bool   // enumerate every data-bearing object version, not just current
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

// ScanResult summarizes a bucket scan. It separates mechanical completeness
// (CompleteWithinScope — every enumerated candidate probed conclusively) from
// audit coverage (WholeBucketComplete — that scope was the entire bucket,
// including all object versions). A current-versions scan of a versioned bucket
// can be CompleteWithinScope yet not WholeBucketComplete.
type ScanResult struct {
	Bucket string `json:"bucket"`
	Region string `json:"region"`
	Source string `json:"source"` // "s3-api" or "keys-file"

	Scope          string `json:"scope"` // "current_versions" or "all_versions"
	Prefix         string `json:"prefix,omitempty"`
	EnumeratedUnit string `json:"enumeratedUnit"` // "keys" or "versions"

	VersioningStatus string `json:"versioningStatus,omitempty"` // "Enabled"/"Suspended"/"" (unversioned)
	VersioningKnown  bool   `json:"versioningKnown"`

	CompleteWithinScope bool `json:"completeWithinScope"`
	WholeBucketComplete bool `json:"wholeBucketComplete"`
	Truncated           bool `json:"truncated"`
	Cancelled           bool `json:"cancelled"`
	FindingsTruncated   bool `json:"findingsTruncated"`

	Enumerated            int `json:"enumerated"`
	Completed             int `json:"completed"`
	PublicCount           int `json:"publicCount"`
	NotPublicCount        int `json:"notPublicCount"`
	InconclusiveCount     int `json:"inconclusiveCount"`
	DeleteMarkersObserved int `json:"deleteMarkersObserved,omitempty"`

	PublicObjects []ObjectFinding `json:"publicObjects"`
	Failures      []ObjectFinding `json:"failures"`
	Warnings      []string        `json:"warnings,omitempty"`
}

const (
	scopeCurrent = "current_versions"
	scopeAll     = "all_versions"
)

// ScanBucket enumerates a bucket's objects (via the S3 API using AWS
// credentials, or from a supplied key list) and probes each one anonymously.
// Enumeration is streamed into a bounded worker pool so enumeration memory stays
// flat regardless of bucket size (retained findings are separately capped via
// MaxFindings).
func ScanBucket(ctx context.Context, c *http.Client, bucket string, opts ScanOptions) (ScanResult, error) {
	res := ScanResult{
		Bucket:        bucket,
		Region:        opts.Region,
		Prefix:        opts.Prefix,
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
		res.EnumeratedUnit = "versions"
	} else {
		res.Scope = scopeCurrent
		res.EnumeratedUnit = "keys"
	}

	var lister s3ListAPI
	if opts.KeysFrom == "" {
		client, err := loadS3Client(ctx, opts.Region)
		if err != nil {
			return res, err
		}
		lister = client
		detectVersioning(ctx, lister, bucket, opts, &res)
	}

	return scanWith(ctx, c, bucket, opts, lister, res)
}

// detectVersioning records the bucket's versioning state and warns when
// noncurrent versions are being skipped. A lookup failure is surfaced (not
// silently ignored) and leaves VersioningKnown false, which prevents a
// current-only scan from claiming whole-bucket completeness.
func detectVersioning(ctx context.Context, lister s3ListAPI, bucket string, opts ScanOptions, res *ScanResult) {
	status, err := versioningStatus(ctx, lister, bucket)
	if err != nil {
		res.VersioningKnown = false
		res.Warnings = append(res.Warnings, "could not determine bucket versioning status ("+friendlyErr(err)+"); whole-bucket completeness cannot be established")
		return
	}
	res.VersioningKnown = true
	res.VersioningStatus = status
	if status != "" && !opts.IncludeVersions {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"bucket versioning is %s; noncurrent object versions were NOT scanned — pass --include-versions for a whole-bucket audit", strings.ToLower(status)))
	}
}

// scanWith runs enumeration + probing given an (optional) S3 lister.
func scanWith(ctx context.Context, c *http.Client, bucket string, opts ScanOptions, lister s3ListAPI, res ScanResult) (ScanResult, error) {
	keys := make(chan scanKey, 256)
	var (
		enumerated   int
		truncated    bool
		deleteMarker int
		prodErr      error
	)
	prodDone := make(chan struct{})
	go func() {
		defer close(keys)
		defer close(prodDone)
		switch {
		case opts.KeysFrom != "":
			enumerated, truncated, prodErr = streamKeysFromFile(ctx, opts.KeysFrom, opts.Prefix, opts.MaxObjects, keys)
		case opts.IncludeVersions:
			enumerated, truncated, deleteMarker, prodErr = streamVersionsFromS3(ctx, lister, bucket, opts, keys)
		default:
			enumerated, truncated, prodErr = streamKeysFromS3(ctx, lister, bucket, opts, keys)
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
					res.PublicObjects = appendCapped(res.PublicObjects, f, opts.MaxFindings, &res.FindingsTruncated)
				case AccessNotPublic:
					res.NotPublicCount++
				default:
					res.InconclusiveCount++
					res.Failures = appendCapped(res.Failures, f, opts.MaxFindings, &res.FindingsTruncated)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	<-prodDone

	res.Enumerated = enumerated
	res.Truncated = truncated
	res.DeleteMarkersObserved = deleteMarker
	res.Cancelled = ctx.Err() != nil

	if prodErr != nil && !res.Cancelled {
		return res, prodErr
	}

	res.CompleteWithinScope = prodErr == nil && !res.Truncated && !res.Cancelled && res.InconclusiveCount == 0
	// Whole-bucket completeness additionally requires that the scanned scope was
	// the entire bucket: enumerated (not a candidate file), no prefix filter, and
	// all data-bearing versions covered (either --include-versions, or versioning
	// is known to be off so current == whole).
	allData := opts.IncludeVersions || (res.VersioningKnown && res.VersioningStatus == "")
	res.WholeBucketComplete = res.CompleteWithinScope && opts.KeysFrom == "" && opts.Prefix == "" && allData

	sort.Slice(res.PublicObjects, func(i, j int) bool { return lessFinding(res.PublicObjects[i], res.PublicObjects[j]) })
	sort.Slice(res.Failures, func(i, j int) bool { return lessFinding(res.Failures[i], res.Failures[j]) })
	return res, nil
}

// appendCapped appends f unless the retained slice already holds max examples
// (max == 0 means unbounded). When the cap is hit it flags truncation but leaves
// the caller's counters untouched, so counts stay exact while memory is bounded.
func appendCapped(s []ObjectFinding, f ObjectFinding, max int, truncated *bool) []ObjectFinding {
	if max > 0 && len(s) >= max {
		*truncated = true
		return s
	}
	return append(s, f)
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

// versioningStatus returns "Enabled", "Suspended", or "" (never configured).
func versioningStatus(ctx context.Context, lister s3ListAPI, bucket string) (string, error) {
	out, err := lister.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(bucket)})
	if err != nil {
		return "", err
	}
	return string(out.Status), nil
}

// streamKeysFromS3 lists current object keys and streams them into out. It stops
// one key past MaxObjects to distinguish an exactly-at-limit scan (not
// truncated) from a genuinely truncated one.
func streamKeysFromS3(ctx context.Context, lister s3ListAPI, bucket string, opts ScanOptions, out chan<- scanKey) (enumerated int, truncated bool, err error) {
	in := &s3.ListObjectsV2Input{Bucket: aws.String(bucket)}
	if opts.Prefix != "" {
		in.Prefix = aws.String(opts.Prefix)
	}
	p := s3.NewListObjectsV2Paginator(lister, in)
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

// streamVersionsFromS3 lists every data-bearing object version (delete markers
// are counted but not probed — they have no object body) and streams each as a
// version-qualified probe target.
func streamVersionsFromS3(ctx context.Context, lister s3ListAPI, bucket string, opts ScanOptions, out chan<- scanKey) (enumerated int, truncated bool, deleteMarkers int, err error) {
	in := &s3.ListObjectVersionsInput{Bucket: aws.String(bucket)}
	if opts.Prefix != "" {
		in.Prefix = aws.String(opts.Prefix)
	}
	p := s3.NewListObjectVersionsPaginator(lister, in)
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return enumerated, truncated, deleteMarkers, ctx.Err()
			}
			return enumerated, truncated, deleteMarkers, fmt.Errorf("listing object versions: %s", friendlyErr(err))
		}
		deleteMarkers += len(page.DeleteMarkers)
		for _, v := range page.Versions {
			if opts.MaxObjects > 0 && enumerated >= opts.MaxObjects {
				return enumerated, true, deleteMarkers, nil
			}
			select {
			case out <- scanKey{Key: aws.ToString(v.Key), VersionID: aws.ToString(v.VersionId)}:
				enumerated++
			case <-ctx.Done():
				return enumerated, truncated, deleteMarkers, ctx.Err()
			}
		}
	}
	return enumerated, false, deleteMarkers, nil
}

// streamKeysFromFile reads candidate keys from a newline-delimited file and
// streams them into out. To preserve exact S3 key bytes it trims only a trailing
// CR (from CRLF files) and does not strip leading slashes, spaces, or treat any
// line as a comment. Empty lines are skipped. (A newline-delimited format cannot
// represent a key containing a literal newline.)
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
