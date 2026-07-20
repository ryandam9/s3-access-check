package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Target identifies the S3 resource to check. An empty Key means the request
// targets the bucket itself (a public-listability check); a non-empty Key
// targets a single object (a public-read check).
type Target struct {
	Bucket    string `json:"bucket"`
	Key       string `json:"key,omitempty"`
	Region    string `json:"region,omitempty"` // optional hint parsed from a URL; may be empty
	VersionID string `json:"versionId,omitempty"`
}

// IsObject reports whether the target refers to a specific object rather than
// the bucket as a whole.
func (t Target) IsObject() bool { return t.Key != "" }

func (t Target) String() string {
	if t.IsObject() {
		return fmt.Sprintf("s3://%s/%s", t.Bucket, t.Key)
	}
	return fmt.Sprintf("s3://%s", t.Bucket)
}

var (
	// e.g. "s3", "s3.us-east-1", "s3-eu-west-1", "s3.dualstack.us-east-1"
	regionRe = regexp.MustCompile(`^s3[.-](?:dualstack[.-])?([a-z0-9-]+)$`)
)

// ParseTarget converts a user-supplied string into a Target. It accepts:
//
//	s3://bucket/key
//	https://bucket.s3.region.amazonaws.com/key   (virtual-hosted style)
//	https://s3.region.amazonaws.com/bucket/key   (path style)
//	bucket
//	bucket/key
//
// Only AWS S3 endpoints (*.amazonaws.com) are accepted for URL inputs; an
// unrecognized host is rejected rather than silently reinterpreted as an AWS
// bucket name.
func ParseTarget(input string) (Target, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return Target{}, fmt.Errorf("empty target")
	}

	switch {
	case strings.HasPrefix(raw, "s3://"):
		return parseS3Scheme(raw)
	case strings.HasPrefix(raw, "http://"), strings.HasPrefix(raw, "https://"):
		return parseHTTPURL(raw)
	default:
		return parseBare(raw)
	}
}

func parseS3Scheme(raw string) (Target, error) {
	rest := strings.TrimPrefix(raw, "s3://")
	return splitBucketKey(rest)
}

func parseBare(raw string) (Target, error) {
	return splitBucketKey(raw)
}

func splitBucketKey(rest string) (Target, error) {
	rest = strings.TrimPrefix(rest, "/")
	if rest == "" {
		return Target{}, fmt.Errorf("no bucket in target")
	}
	bucket, key, _ := strings.Cut(rest, "/")
	if bucket == "" {
		return Target{}, fmt.Errorf("no bucket in target")
	}
	if err := validateBucket(bucket); err != nil {
		return Target{}, err
	}
	return Target{Bucket: bucket, Key: key}, nil
}

// authQueryParams are request-signing parameters that must never appear on an
// anonymous probe target; their presence means the user pasted a presigned or
// signed URL.
var authQueryParams = []string{
	"X-Amz-Signature", "X-Amz-Credential", "X-Amz-Security-Token",
	"X-Amz-Algorithm", "AWSAccessKeyId", "Signature",
}

func parseHTTPURL(raw string) (Target, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Target{}, fmt.Errorf("invalid URL: %w", err)
	}
	host := strings.ToLower(u.Hostname())

	// Use the escaped path so encoded separators survive; strip exactly one
	// leading slash without decoding the remainder.
	path := strings.TrimPrefix(u.EscapedPath(), "/")
	key, err := url.PathUnescape(path)
	if err != nil {
		return Target{}, fmt.Errorf("invalid escaped path %q: %w", path, err)
	}

	q := u.Query()
	for _, p := range authQueryParams {
		if q.Has(p) {
			return Target{}, fmt.Errorf("target looks like a signed/presigned URL (%s present); pass an unsigned S3 path instead", p)
		}
	}
	versionID := q.Get("versionId")

	const suffix = ".amazonaws.com"
	if !strings.HasSuffix(host, suffix) {
		return Target{}, fmt.Errorf("unsupported endpoint host %q: only AWS S3 (*.amazonaws.com) URLs are supported", u.Hostname())
	}

	labels := strings.TrimSuffix(host, suffix)
	if region, isPath := matchEndpoint(labels); isPath {
		// path style: https://s3.region.amazonaws.com/bucket/key
		t, err := splitEscapedBucketKey(path)
		if err != nil {
			return Target{}, err
		}
		t.Region = region
		t.VersionID = versionID
		return t, nil
	}
	if bucket, region, ok := matchVirtualHosted(labels); ok {
		// virtual-hosted style: bucket.s3.region.amazonaws.com
		if err := validateBucket(bucket); err != nil {
			return Target{}, err
		}
		return Target{Bucket: bucket, Key: key, Region: region, VersionID: versionID}, nil
	}
	return Target{}, fmt.Errorf("unrecognized S3 endpoint host %q", u.Hostname())
}

// splitEscapedBucketKey splits an escaped path-style "bucket/key" path, decoding
// only the key portion.
func splitEscapedBucketKey(escapedPath string) (Target, error) {
	bucketEsc, keyEsc, _ := strings.Cut(escapedPath, "/")
	bucket, err := url.PathUnescape(bucketEsc)
	if err != nil {
		return Target{}, fmt.Errorf("invalid bucket in path: %w", err)
	}
	key, err := url.PathUnescape(keyEsc)
	if err != nil {
		return Target{}, fmt.Errorf("invalid key in path: %w", err)
	}
	if bucket == "" {
		return Target{}, fmt.Errorf("no bucket in target")
	}
	if err := validateBucket(bucket); err != nil {
		return Target{}, err
	}
	return Target{Bucket: bucket, Key: key}, nil
}

// matchEndpoint reports whether labels (host minus ".amazonaws.com") is a bare
// endpoint with no bucket prefix, returning the region if one is encoded.
func matchEndpoint(labels string) (region string, ok bool) {
	if labels == "s3" {
		return "", true
	}
	if m := regionRe.FindStringSubmatch(labels); m != nil {
		return m[1], true
	}
	return "", false
}

// s3SegmentRe matches a single host label that begins the S3 endpoint portion:
// either bare "s3" (dot form, region follows in later labels) or "s3-region"
// (legacy dash form).
var s3SegmentRe = regexp.MustCompile(`^s3(-[a-z0-9-]+)?$`)

// matchVirtualHosted splits "bucket.s3[.region]" style labels into the bucket
// and region components. The bucket portion may itself contain dots, so it
// locates the endpoint by finding the rightmost label that starts the S3
// endpoint marker and treats everything before it as the bucket.
func matchVirtualHosted(labels string) (bucket, region string, ok bool) {
	segs := strings.Split(labels, ".")
	marker := -1
	for i := len(segs) - 1; i >= 1; i-- { // i>=1: a bucket label must precede it
		if s3SegmentRe.MatchString(segs[i]) {
			marker = i
			break
		}
	}
	if marker == -1 {
		return "", "", false
	}
	bucket = strings.Join(segs[:marker], ".")
	region, _ = matchEndpoint(strings.Join(segs[marker:], "."))
	return bucket, region, bucket != ""
}

// validateBucket applies conservative naming rules. It intentionally accepts
// legacy identifiers (uppercase, underscore) that predate the 2018 rules and
// may still exist, rejecting only what would make safe request construction
// impossible.
func validateBucket(b string) error {
	if len(b) < 3 || len(b) > 63 {
		return fmt.Errorf("bucket name %q must be 3-63 characters", b)
	}
	for _, r := range b {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '-', r == '.', r == '_':
		default:
			return fmt.Errorf("bucket name %q contains invalid character %q", b, r)
		}
	}
	return nil
}
