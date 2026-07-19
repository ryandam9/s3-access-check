package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// AnonResult holds the outcome of an unauthenticated ("anonymous") probe. It
// answers the ground-truth question: does a request with no credentials
// succeed? That is the effective public-access state, independent of how it was
// configured (bucket policy, ACL, or public-access-block settings).
type AnonResult struct {
	Target     Target
	Public     bool   // the anonymous request succeeded
	Exists     *bool  // whether the resource exists, when determinable
	StatusCode int    // HTTP status of the probe
	S3Code     string // S3 <Code> from the error body, when present
	Region     string // region the bucket resolved to
	Operation  string // "ListBucket" or "GetObject"
}

// s3ErrorBody is the standard S3 REST error document.
type s3ErrorBody struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// anonymousClient returns an HTTP client that does not follow redirects, so we
// can read region-hint headers off a 301 response, and that carries no
// credentials of any kind.
func anonymousClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ResolveRegion discovers a bucket's region by issuing an unauthenticated HEAD
// against the global path-style endpoint. S3 returns the region in the
// x-amz-bucket-region header even on 301/403 responses. Path-style is used so
// that bucket names containing dots do not break TLS SNI. Defaults to
// us-east-1 if the header is absent.
func ResolveRegion(ctx context.Context, c *http.Client, bucket string) (string, error) {
	u := "https://s3.amazonaws.com/" + url.PathEscape(bucket)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if region := resp.Header.Get("x-amz-bucket-region"); region != "" {
		return region, nil
	}
	return "us-east-1", nil
}

// regionalHost builds the path-style S3 endpoint host for a region.
func regionalHost(region string) string {
	if region == "" || region == "us-east-1" {
		return "s3.amazonaws.com"
	}
	return "s3." + region + ".amazonaws.com"
}

// CheckAnonymous probes the target without credentials and reports whether it is
// anonymously accessible. For a bucket it attempts an anonymous list; for an
// object it attempts an anonymous read of the first byte.
func CheckAnonymous(ctx context.Context, c *http.Client, t Target) (AnonResult, error) {
	region := t.Region
	if region == "" {
		r, err := ResolveRegion(ctx, c, t.Bucket)
		if err != nil {
			return AnonResult{}, fmt.Errorf("resolving region: %w", err)
		}
		region = r
	}
	res := AnonResult{Target: t, Region: region}

	host := regionalHost(region)
	var reqURL, method string
	if t.IsObject() {
		res.Operation = "GetObject"
		u := &url.URL{Scheme: "https", Host: host, Path: "/" + t.Bucket + "/" + t.Key}
		reqURL, method = u.String(), http.MethodGet
	} else {
		res.Operation = "ListBucket"
		u := &url.URL{Scheme: "https", Host: host, Path: "/" + t.Bucket}
		u.RawQuery = "list-type=2&max-keys=1"
		reqURL, method = u.String(), http.MethodGet
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, nil)
	if err != nil {
		return AnonResult{}, err
	}
	if t.IsObject() {
		// Read at most one byte so a public object is confirmed without
		// downloading its full contents.
		req.Header.Set("Range", "bytes=0-0")
	}

	resp, err := c.Do(req)
	if err != nil {
		return AnonResult{}, fmt.Errorf("%s request: %w", res.Operation, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	res.StatusCode = resp.StatusCode
	if hdr := resp.Header.Get("x-amz-bucket-region"); hdr != "" {
		res.Region = hdr
	}
	res.S3Code = parseS3Code(body)

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		res.Public = true
		res.Exists = boolPtr(true)
	case resp.StatusCode == http.StatusForbidden:
		res.Public = false
		// 403 does not by itself prove existence; leave Exists nil unless the
		// error code is informative.
		if res.S3Code == "AccessDenied" || res.S3Code == "AllAccessDisabled" {
			// Bucket/object exists but access is denied.
			res.Exists = boolPtr(true)
		}
	case resp.StatusCode == http.StatusNotFound:
		res.Public = false
		res.Exists = boolPtr(false)
	default:
		res.Public = false
	}
	return res, nil
}

func parseS3Code(body []byte) string {
	if !strings.Contains(string(body), "<Error") {
		return ""
	}
	var e s3ErrorBody
	if err := xml.Unmarshal(body, &e); err != nil {
		return ""
	}
	return e.Code
}

func boolPtr(b bool) *bool { return &b }
