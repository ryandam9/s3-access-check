package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AnonResult holds the outcome of an unauthenticated ("anonymous") probe. It
// answers the ground-truth question: does a request with no credentials
// succeed? That is the effective public-access state, independent of how it was
// configured (bucket policy, ACL, or public-access-block settings).
type AnonResult struct {
	Target     Target      `json:"target"`
	State      AccessState `json:"state"`
	Exists     *bool       `json:"exists,omitempty"`
	StatusCode int         `json:"httpStatus,omitempty"`
	S3Code     string      `json:"s3Code,omitempty"`
	Region     string      `json:"region,omitempty"`
	Operation  string      `json:"operation"`
	Err        string      `json:"error,omitempty"`
}

// Public reports whether the probe established anonymous access.
func (r AnonResult) Public() bool { return r.State == AccessPublic }

// s3ErrorBody is the standard S3 REST error document.
type s3ErrorBody struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// anonymousClient returns an HTTP client that does not follow redirects, so we
// can read region-hint headers off a 301 response, and that carries no
// credentials of any kind. requestTimeout bounds each individual request.
func anonymousClient(requestTimeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// Reuse connections aggressively so a bucket scan's concurrent probes don't
	// each pay a fresh TLS handshake.
	tr.MaxIdleConns = 100
	tr.MaxIdleConnsPerHost = 100
	return &http.Client{
		Transport: tr,
		Timeout:   requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ResolveRegion discovers a bucket's region by issuing an unauthenticated HEAD
// against the global path-style endpoint. S3 returns the region in the
// x-amz-bucket-region header even on 301/403 responses. Path-style is used so
// that bucket names containing dots do not break TLS SNI. Returns an empty
// string (not an error) when the region cannot be determined, so callers can
// fall back to the probe's own wrong-region retry.
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
	return resp.Header.Get("x-amz-bucket-region"), nil
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
// object it attempts an anonymous HEAD (which needs the same s3:GetObject
// permission as GET, returns no body, and — unlike a ranged GET — is not
// defeated by zero-byte objects).
func CheckAnonymous(ctx context.Context, c *http.Client, t Target) (AnonResult, error) {
	if t.IsObject() {
		return ProbeObject(ctx, c, t.Region, t)
	}
	return ProbeBucket(ctx, c, t.Region, t)
}

// ProbeBucket issues an anonymous ListBucket. region may be empty; the probe
// starts at the global endpoint and follows a single region redirect.
func ProbeBucket(ctx context.Context, c *http.Client, region string, t Target) (AnonResult, error) {
	return probeWithRetry(ctx, c, region, t, http.MethodGet, "/"+t.Bucket, "list-type=2&max-keys=1", "ListBucket", false)
}

// ProbeObject issues an anonymous HEAD against a single object.
func ProbeObject(ctx context.Context, c *http.Client, region string, t Target) (AnonResult, error) {
	rawQuery := ""
	if t.VersionID != "" {
		rawQuery = "versionId=" + url.QueryEscape(t.VersionID)
	}
	return probeWithRetry(ctx, c, region, t, http.MethodHead, "/"+t.Bucket+"/"+t.Key, rawQuery, "GetObject", true)
}

// probeWithRetry performs the anonymous request and, on a wrong-region response
// that advertises the correct region, retries exactly once against it.
func probeWithRetry(ctx context.Context, c *http.Client, region string, t Target, method, path, rawQuery, op string, isObject bool) (AnonResult, error) {
	res := AnonResult{Target: t, Region: region, Operation: op}

	for attempt := 0; attempt < 2; attempt++ {
		u := &url.URL{Scheme: "https", Host: regionalHost(res.Region), Path: path}
		if rawQuery != "" {
			u.RawQuery = rawQuery
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
		if err != nil {
			return AnonResult{}, err
		}

		resp, err := c.Do(req)
		if err != nil {
			// A transport error (timeout, DNS, connection reset) is not evidence
			// of "not public" — it is inconclusive.
			res.State = AccessInconclusive
			res.Err = err.Error()
			return res, nil
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		res.StatusCode = resp.StatusCode
		res.S3Code = parseS3Code(body)
		hdrRegion := resp.Header.Get("x-amz-bucket-region")

		// Wrong-region handling: S3 answers a misdirected request with 301/307
		// (or a 400 endpoint error) and names the correct region in the header.
		// Retry once against it.
		if attempt == 0 && hdrRegion != "" && hdrRegion != res.Region &&
			(resp.StatusCode == http.StatusMovedPermanently ||
				resp.StatusCode == http.StatusTemporaryRedirect ||
				resp.StatusCode == http.StatusBadRequest) {
			res.Region = hdrRegion
			continue
		}

		classify(&res, isObject, hdrRegion)
		return res, nil
	}
	return res, nil
}

// classify maps the final HTTP response to an access state. Only responses that
// actually establish denial (403) or absence (404) are "not public"; everything
// unexpected is inconclusive.
func classify(res *AnonResult, isObject bool, hdrRegion string) {
	if hdrRegion != "" {
		res.Region = hdrRegion
	}
	switch sc := res.StatusCode; {
	case sc >= 200 && sc < 300:
		res.State = AccessPublic
		res.Exists = boolPtr(true)
	case sc == http.StatusForbidden:
		res.State = AccessNotPublic
		// A 403 on an object does not prove the object exists: S3 hides
		// existence from callers lacking s3:ListBucket. Only assert existence
		// for a bucket-level denial.
		if !isObject && (res.S3Code == "AccessDenied" || res.S3Code == "AllAccessDisabled") {
			res.Exists = boolPtr(true)
		}
	case sc == http.StatusNotFound:
		res.State = AccessNotPublic
		res.Exists = boolPtr(false)
	default:
		res.State = AccessInconclusive
		if res.Err == "" {
			res.Err = fmt.Sprintf("unexpected HTTP %d", sc)
			if res.S3Code != "" {
				res.Err += " (" + res.S3Code + ")"
			}
		}
	}
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
