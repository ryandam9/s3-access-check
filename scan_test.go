package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
)

func writeKeysFile(t *testing.T, lines string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "keys.txt")
	if err := os.WriteFile(p, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// publicFor returns a stub client that treats the given keys as public (200)
// and everything else as denied (403), recording every key it was asked about.
func publicFor(public map[string]bool, seen *[]string, mu *sync.Mutex) *http.Client {
	return testClient(func(r *http.Request) *http.Response {
		// Path is /bucket/key; recover the key.
		key := r.URL.Path
		if i := len("/b-ucket/"); len(key) >= i {
			key = key[i:]
		}
		mu.Lock()
		*seen = append(*seen, key)
		mu.Unlock()
		if public[key] {
			return resp(200, nil, "")
		}
		return resp(403, nil, accessDeniedBody)
	})
}

func TestScanKeysFromFindsPublic(t *testing.T) {
	kf := writeKeysFile(t, "public/x\nprivate/y\nprivate/z\n")
	var seen []string
	var mu sync.Mutex
	c := publicFor(map[string]bool{"public/x": true}, &seen, &mu)

	res, err := ScanBucket(context.Background(), c, "b-ucket", ScanOptions{
		Concurrency: 4, Region: "us-east-1", KeysFrom: kf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.PublicCount != 1 || len(res.PublicObjects) != 1 || res.PublicObjects[0].Key != "public/x" {
		t.Errorf("public = %d %+v, want 1 [public/x]", res.PublicCount, res.PublicObjects)
	}
	if res.NotPublicCount != 2 {
		t.Errorf("notPublic = %d, want 2", res.NotPublicCount)
	}
	if res.Completed != 3 || res.Enumerated != 3 {
		t.Errorf("completed/enumerated = %d/%d, want 3/3", res.Completed, res.Enumerated)
	}
	if !res.CompleteWithinScope {
		t.Errorf("expected CompleteWithinScope=true")
	}
}

func TestScanPreservesExactKeys(t *testing.T) {
	// Leading slash, spaces, and '#' must survive verbatim.
	kf := writeKeysFile(t, "/leading-slash\n  spaced key  \n#not-a-comment\n")
	var seen []string
	var mu sync.Mutex
	c := publicFor(map[string]bool{}, &seen, &mu)

	if _, err := ScanBucket(context.Background(), c, "b-ucket", ScanOptions{
		Concurrency: 1, Region: "us-east-1", KeysFrom: kf,
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(seen)
	want := []string{"#not-a-comment", "/leading-slash", "  spaced key  "}
	sort.Strings(want)
	if len(seen) != len(want) {
		t.Fatalf("seen %d keys %q, want %d %q", len(seen), seen, len(want), want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("key[%d] = %q, want %q", i, seen[i], want[i])
		}
	}
}

func TestScanTruncationExactVsOver(t *testing.T) {
	var seen []string
	var mu sync.Mutex

	// Exactly at the limit: not truncated, complete.
	kf := writeKeysFile(t, "a\nb\n")
	res, err := ScanBucket(context.Background(), publicFor(nil, &seen, &mu), "b-ucket", ScanOptions{
		Concurrency: 2, Region: "us-east-1", KeysFrom: kf, MaxObjects: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Truncated {
		t.Errorf("exactly-at-limit scan should not be truncated")
	}
	if !res.CompleteWithinScope {
		t.Errorf("exactly-at-limit scan should be complete")
	}

	// One over the limit: truncated, incomplete.
	kf2 := writeKeysFile(t, "a\nb\nc\n")
	res2, err := ScanBucket(context.Background(), publicFor(nil, &seen, &mu), "b-ucket", ScanOptions{
		Concurrency: 2, Region: "us-east-1", KeysFrom: kf2, MaxObjects: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res2.Truncated {
		t.Errorf("over-limit scan should be truncated")
	}
	if res2.CompleteWithinScope {
		t.Errorf("truncated scan must not be complete-within-scope")
	}
	if res2.Enumerated != 2 {
		t.Errorf("enumerated = %d, want 2", res2.Enumerated)
	}
}

func TestScanInconclusiveNotComplete(t *testing.T) {
	kf := writeKeysFile(t, "boom\n")
	c := testClient(func(r *http.Request) *http.Response { return resp(500, nil, "") })
	res, err := ScanBucket(context.Background(), c, "b-ucket", ScanOptions{
		Concurrency: 1, Region: "us-east-1", KeysFrom: kf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.InconclusiveCount != 1 || len(res.Failures) != 1 {
		t.Errorf("inconclusive = %d failures = %d, want 1/1", res.InconclusiveCount, len(res.Failures))
	}
	if res.CompleteWithinScope {
		t.Errorf("a scan with an inconclusive probe must not be complete-within-scope")
	}
}
