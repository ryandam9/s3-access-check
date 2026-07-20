package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// stubRT returns canned responses based on the request, with no network.
type stubRT struct {
	fn func(*http.Request) *http.Response
}

func (s stubRT) RoundTrip(r *http.Request) (*http.Response, error) { return s.fn(r), nil }

func testClient(fn func(*http.Request) *http.Response) *http.Client {
	return &http.Client{
		Transport:     stubRT{fn},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func resp(status int, headers map[string]string, body string) *http.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body))}
}

const accessDeniedBody = `<?xml version="1.0"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`

func TestProbeObjectClassification(t *testing.T) {
	ctx := context.Background()
	tgt := Target{Bucket: "b-ucket", Key: "k"}

	cases := []struct {
		name      string
		status    int
		body      string
		wantState AccessState
		wantExist *bool
	}{
		{"public", 200, "", AccessPublic, boolPtr(true)},
		{"partial-content", 206, "", AccessPublic, boolPtr(true)},
		{"denied", 403, accessDeniedBody, AccessNotPublic, nil}, // object 403: existence unknown
		{"missing", 404, "", AccessNotPublic, boolPtr(false)},
		{"throttled", 429, "", AccessInconclusive, nil},
		{"server-error", 503, "", AccessInconclusive, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(func(r *http.Request) *http.Response {
				if r.Method != http.MethodGet {
					t.Errorf("object probe should use GET, got %s", r.Method)
				}
				if got := r.Header.Get("Range"); got != "bytes=0-0" {
					t.Errorf("object probe should send Range bytes=0-0, got %q", got)
				}
				return resp(tc.status, nil, tc.body)
			})
			got, err := ProbeObject(ctx, c, "us-east-1", tgt)
			if err != nil {
				t.Fatal(err)
			}
			if got.State != tc.wantState {
				t.Errorf("state = %q, want %q", got.State, tc.wantState)
			}
			if (got.Exists == nil) != (tc.wantExist == nil) {
				t.Errorf("exists = %v, want %v", got.Exists, tc.wantExist)
			} else if got.Exists != nil && *got.Exists != *tc.wantExist {
				t.Errorf("exists = %v, want %v", *got.Exists, *tc.wantExist)
			}
		})
	}
}

func TestProbeBucketDeniedExists(t *testing.T) {
	c := testClient(func(r *http.Request) *http.Response {
		return resp(403, nil, accessDeniedBody)
	})
	got, err := ProbeBucket(context.Background(), c, "us-east-1", Target{Bucket: "b-ucket"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != AccessNotPublic {
		t.Fatalf("state = %q, want not_public", got.State)
	}
	if got.Exists == nil || !*got.Exists {
		t.Errorf("bucket AccessDenied should imply existence, got %v", got.Exists)
	}
}

func TestProbeWrongRegionRetry(t *testing.T) {
	var calls int
	c := testClient(func(r *http.Request) *http.Response {
		calls++
		if r.URL.Host == "s3.amazonaws.com" {
			// misdirected: name the correct region, no follow-up expected here
			return resp(301, map[string]string{"x-amz-bucket-region": "eu-west-1"}, "")
		}
		if r.URL.Host == "s3.eu-west-1.amazonaws.com" {
			return resp(200, map[string]string{"x-amz-bucket-region": "eu-west-1"}, "")
		}
		t.Fatalf("unexpected host %q", r.URL.Host)
		return nil
	})
	got, err := ProbeObject(context.Background(), c, "", Target{Bucket: "b-ucket", Key: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("expected exactly one retry (2 calls), got %d", calls)
	}
	if got.State != AccessPublic {
		t.Errorf("state = %q, want public after region retry", got.State)
	}
	if got.Region != "eu-west-1" {
		t.Errorf("region = %q, want eu-west-1", got.Region)
	}
}

func TestProbeObjectZeroByteFallback(t *testing.T) {
	// A zero-byte object cannot satisfy Range: bytes=0-0 (416); the probe must
	// fall back to a rangeless GET and classify the 200 as public.
	var ranged, full int
	c := testClient(func(r *http.Request) *http.Response {
		if r.Header.Get("Range") != "" {
			ranged++
			return resp(416, nil, `<?xml version="1.0"?><Error><Code>InvalidRange</Code></Error>`)
		}
		full++
		return resp(200, nil, "")
	})
	got, err := ProbeObject(context.Background(), c, "us-east-1", Target{Bucket: "b-ucket", Key: "empty"})
	if err != nil {
		t.Fatal(err)
	}
	if ranged != 1 || full != 1 {
		t.Errorf("expected 1 ranged + 1 full GET, got %d + %d", ranged, full)
	}
	if got.State != AccessPublic {
		t.Errorf("zero-byte public object should be public, got %q", got.State)
	}
}

func TestProbeBucketListPrefix(t *testing.T) {
	c := testClient(func(r *http.Request) *http.Response {
		if got := r.URL.Query().Get("prefix"); got != "public/" {
			t.Errorf("prefix = %q, want public/", got)
		}
		return resp(200, nil, "")
	})
	got, err := ProbeBucket(context.Background(), c, "us-east-1", Target{Bucket: "b-ucket"}, "public/")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != AccessPublic {
		t.Errorf("state = %q, want public", got.State)
	}
}

func TestProbeVersionIDInQuery(t *testing.T) {
	c := testClient(func(r *http.Request) *http.Response {
		if got := r.URL.Query().Get("versionId"); got != "v9" {
			t.Errorf("versionId = %q, want v9", got)
		}
		return resp(200, nil, "")
	})
	if _, err := ProbeObject(context.Background(), c, "us-east-1", Target{Bucket: "b-ucket", Key: "k", VersionID: "v9"}); err != nil {
		t.Fatal(err)
	}
}
