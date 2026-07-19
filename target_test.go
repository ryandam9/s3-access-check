package main

import "testing"

func TestParseTarget(t *testing.T) {
	tests := []struct {
		in      string
		bucket  string
		key     string
		region  string
		wantErr bool
	}{
		{in: "s3://my-bucket", bucket: "my-bucket"},
		{in: "s3://my-bucket/", bucket: "my-bucket"},
		{in: "s3://my-bucket/path/to/obj.txt", bucket: "my-bucket", key: "path/to/obj.txt"},
		{in: "my-bucket", bucket: "my-bucket"},
		{in: "my-bucket/a/b.txt", bucket: "my-bucket", key: "a/b.txt"},
		// virtual-hosted, global endpoint (no region)
		{in: "https://noaa-goes16.s3.amazonaws.com/index.html", bucket: "noaa-goes16", key: "index.html"},
		// virtual-hosted, regional dot form
		{in: "https://my-bucket.s3.us-west-2.amazonaws.com/k", bucket: "my-bucket", key: "k", region: "us-west-2"},
		// virtual-hosted, legacy dash form
		{in: "https://my-bucket.s3-eu-west-1.amazonaws.com/k", bucket: "my-bucket", key: "k", region: "eu-west-1"},
		// dualstack
		{in: "https://my-bucket.s3.dualstack.ap-south-1.amazonaws.com/k", bucket: "my-bucket", key: "k", region: "ap-south-1"},
		// bucket name containing dots
		{in: "https://my.dotted.bucket.s3.amazonaws.com/k", bucket: "my.dotted.bucket", key: "k"},
		// path style
		{in: "https://s3.us-east-1.amazonaws.com/my-bucket/k", bucket: "my-bucket", key: "k", region: "us-east-1"},
		{in: "https://s3.amazonaws.com/my-bucket/deep/key", bucket: "my-bucket", key: "deep/key"},
		// errors
		{in: "", wantErr: true},
		{in: "s3://", wantErr: true},
		{in: "ab", wantErr: true}, // too short
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseTarget(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Bucket != tc.bucket || got.Key != tc.key {
				t.Errorf("bucket/key = %q/%q, want %q/%q", got.Bucket, got.Key, tc.bucket, tc.key)
			}
			if tc.region != "" && got.Region != tc.region {
				t.Errorf("region = %q, want %q", got.Region, tc.region)
			}
		})
	}
}
