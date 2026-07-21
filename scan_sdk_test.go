package main

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// fakeS3 implements s3ListAPI for deterministic, network-free scan tests.
type fakeS3 struct {
	objectPages   [][]string // ListObjectsV2 pages of keys
	versions      [][]s3types.ObjectVersion
	deleteMarks   [][]s3types.DeleteMarkerEntry
	versioning    s3types.BucketVersioningStatus
	versioningErr error
	listErr       error
}

func (f *fakeS3) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	// Token encodes the next page index.
	idx := 0
	if in.ContinuationToken != nil {
		idx = int((*in.ContinuationToken)[0] - '0')
	}
	page := f.objectPages[idx]
	contents := make([]s3types.Object, len(page))
	for i, k := range page {
		contents[i] = s3types.Object{Key: aws.String(k)}
	}
	out := &s3.ListObjectsV2Output{Contents: contents}
	if idx+1 < len(f.objectPages) {
		next := string(rune('0' + idx + 1))
		out.IsTruncated = aws.Bool(true)
		out.NextContinuationToken = aws.String(next)
	}
	return out, nil
}

func (f *fakeS3) ListObjectVersions(_ context.Context, in *s3.ListObjectVersionsInput, _ ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	idx := 0
	if in.KeyMarker != nil {
		idx = int((*in.KeyMarker)[0] - '0')
	}
	out := &s3.ListObjectVersionsOutput{Versions: f.versions[idx]}
	if idx < len(f.deleteMarks) {
		out.DeleteMarkers = f.deleteMarks[idx]
	}
	if idx+1 < len(f.versions) {
		next := string(rune('0' + idx + 1))
		out.IsTruncated = aws.Bool(true)
		out.NextKeyMarker = aws.String(next)
	}
	return out, nil
}

func (f *fakeS3) GetBucketVersioning(_ context.Context, _ *s3.GetBucketVersioningInput, _ ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	if f.versioningErr != nil {
		return nil, f.versioningErr
	}
	return &s3.GetBucketVersioningOutput{Status: f.versioning}, nil
}

func drainKeys(t *testing.T, stream func(chan<- scanKey) (int, bool, error)) ([]scanKey, int, bool, error) {
	t.Helper()
	ch := make(chan scanKey, 64)
	var got []scanKey
	done := make(chan struct{})
	go func() {
		for k := range ch {
			got = append(got, k)
		}
		close(done)
	}()
	n, trunc, err := stream(ch)
	close(ch)
	<-done
	return got, n, trunc, err
}

func TestStreamKeysFromS3Pagination(t *testing.T) {
	f := &fakeS3{objectPages: [][]string{{"a", "b"}, {"c"}}}
	keys, n, trunc, err := drainKeys(t, func(ch chan<- scanKey) (int, bool, error) {
		return streamKeysFromS3(context.Background(), f, "b-ucket", ScanOptions{}, ch)
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || trunc || len(keys) != 3 {
		t.Fatalf("got n=%d trunc=%v keys=%v, want 3 keys across 2 pages", n, trunc, keys)
	}
	if keys[0].Key != "a" || keys[2].Key != "c" {
		t.Errorf("unexpected keys: %v", keys)
	}
}

func TestStreamVersionsFromS3(t *testing.T) {
	f := &fakeS3{
		versions: [][]s3types.ObjectVersion{
			{{Key: aws.String("k"), VersionId: aws.String("v1")}, {Key: aws.String("k"), VersionId: aws.String("v2")}},
			{{Key: aws.String("m"), VersionId: aws.String("v3")}},
		},
		deleteMarks: [][]s3types.DeleteMarkerEntry{
			{{Key: aws.String("k"), VersionId: aws.String("dm")}},
		},
	}
	ch := make(chan scanKey, 64)
	var got []scanKey
	done := make(chan struct{})
	go func() {
		for k := range ch {
			got = append(got, k)
		}
		close(done)
	}()
	n, trunc, dm, err := streamVersionsFromS3(context.Background(), f, "b-ucket", ScanOptions{}, ch)
	close(ch)
	<-done
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || trunc || dm != 1 || len(got) != 3 {
		t.Fatalf("got n=%d trunc=%v deleteMarkers=%d keys=%d, want 3/false/1/3", n, trunc, dm, len(got))
	}
	if got[0].VersionID != "v1" || got[2].Key != "m" || got[2].VersionID != "v3" {
		t.Errorf("unexpected version targets: %v", got)
	}
}

func TestVersioningStatusKnownAndUnknown(t *testing.T) {
	// Known-enabled: current-only scope should not be whole-bucket complete.
	f := &fakeS3{versioning: s3types.BucketVersioningStatusEnabled}
	status, err := versioningStatus(context.Background(), f, "b")
	if err != nil || status != "Enabled" {
		t.Fatalf("status=%q err=%v, want Enabled/nil", status, err)
	}

	// Lookup failure must surface as an error (not be swallowed).
	fe := &fakeS3{versioningErr: context.DeadlineExceeded}
	if _, err := versioningStatus(context.Background(), fe, "b"); err == nil {
		t.Errorf("expected versioning error to propagate")
	}
}
