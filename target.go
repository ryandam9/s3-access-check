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
	Bucket string
	Key    string
	Region string // optional hint parsed from a URL; may be empty
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

// hostStyle matches the host portion of an S3 endpoint and captures the region
// when present. It covers both the modern dot form (s3.us-east-1.amazonaws.com)
// and the legacy dash form (s3-us-west-2.amazonaws.com), with or without a
// bucket prefix for virtual-hosted-style URLs.
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

func parseHTTPURL(raw string) (Target, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Target{}, fmt.Errorf("invalid URL: %w", err)
	}
	host := u.Hostname()
	path := strings.TrimPrefix(u.Path, "/")

	// Try to peel a "*.amazonaws.com" suffix so the remaining labels describe
	// the endpoint. Non-AWS hosts (e.g. custom S3-compatible endpoints) fall
	// back to path-style parsing.
	const suffix = ".amazonaws.com"
	if strings.HasSuffix(host, suffix) {
		labels := strings.TrimSuffix(host, suffix)
		if region, isPath := matchEndpoint(labels); isPath {
			// path style: https://s3.region.amazonaws.com/bucket/key
			t, err := splitBucketKey(path)
			if err != nil {
				return Target{}, err
			}
			t.Region = region
			return t, nil
		}
		// virtual-hosted style: bucket.s3.region.amazonaws.com
		if bucket, region, ok := matchVirtualHosted(labels); ok {
			if err := validateBucket(bucket); err != nil {
				return Target{}, err
			}
			return Target{Bucket: bucket, Key: path, Region: region}, nil
		}
	}

	// Unknown host shape: treat as path-style (bucket is first path segment).
	return splitBucketKey(path)
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

// validateBucket applies the basic S3 bucket naming rules so obviously invalid
// input fails fast with a clear message instead of a confusing HTTP error.
func validateBucket(b string) error {
	if len(b) < 3 || len(b) > 63 {
		return fmt.Errorf("bucket name %q must be 3-63 characters", b)
	}
	for _, r := range b {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return fmt.Errorf("bucket name %q contains invalid character %q", b, r)
		}
	}
	return nil
}
