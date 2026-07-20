package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunFlagValidation(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantExit int
		wantErr  string // substring expected on stderr (empty = don't check)
	}{
		{"no args", nil, exitError, ""},
		{"version", []string{"--version"}, exitNotPublic, ""},
		{"prefix requires scan", []string{"--prefix=x", "s3://my-bucket"}, exitError, "--prefix requires --scan"},
		{"keys-from requires scan", []string{"--keys-from=k.txt", "s3://my-bucket"}, exitError, "--keys-from requires --scan"},
		{"inspect with scan", []string{"--inspect", "--scan", "s3://my-bucket"}, exitError, "--inspect is not supported with --scan"},
		{"bad concurrency", []string{"--scan", "--concurrency=0", "s3://my-bucket"}, exitError, "--concurrency must be between 1 and 256"},
		{"negative max", []string{"--scan", "--max-objects=-1", "s3://my-bucket"}, exitError, "--max-objects must be >= 0"},
		{"zero timeout", []string{"--timeout=0", "s3://my-bucket"}, exitError, "must be positive"},
		{"scan on object", []string{"--scan", "s3://my-bucket/key"}, exitError, "--scan operates on a bucket"},
		{"unknown host", []string{"https://minio.example/b/k"}, exitError, "unsupported endpoint host"},
		{"signed url", []string{"https://b-ucket.s3.amazonaws.com/k?X-Amz-Signature=x"}, exitError, "signed/presigned"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			got := run(tc.args, &out, &errb)
			if got != tc.wantExit {
				t.Errorf("exit = %d, want %d (stderr: %s)", got, tc.wantExit, errb.String())
			}
			if tc.wantErr != "" && !strings.Contains(errb.String(), tc.wantErr) {
				t.Errorf("stderr %q does not contain %q", errb.String(), tc.wantErr)
			}
		})
	}
}

func TestVersionOutput(t *testing.T) {
	var out, errb bytes.Buffer
	if got := run([]string{"--version"}, &out, &errb); got != exitNotPublic {
		t.Fatalf("exit = %d", got)
	}
	if !strings.Contains(out.String(), "s3-access-check") {
		t.Errorf("version output = %q", out.String())
	}
}

func TestScanExitCode(t *testing.T) {
	cases := []struct {
		name         string
		res          ScanResult
		failIfPublic bool
		allowPartial bool
		want         int
	}{
		{"whole-bucket clean", ScanResult{WholeBucketComplete: true}, true, false, exitNotPublic},
		{"public wins", ScanResult{WholeBucketComplete: true, PublicCount: 1}, true, false, exitPublic},
		{"not whole-bucket, no public, fails closed", ScanResult{WholeBucketComplete: false}, true, false, exitError},
		{"not whole-bucket, allow-partial", ScanResult{WholeBucketComplete: false}, true, true, exitNotPublic},
		// R2-H-01: fail-if-public=false must not hide incompleteness.
		{"incomplete + public + failIfPublic=false", ScanResult{WholeBucketComplete: false, PublicCount: 1, InconclusiveCount: 1}, false, false, exitError},
		// A confirmed public finding still wins when failing on public.
		{"incomplete + public + failIfPublic=true", ScanResult{WholeBucketComplete: false, PublicCount: 1}, true, false, exitPublic},
	}
	for _, tc := range cases {
		if got := scanExitCode(tc.res, tc.failIfPublic, tc.allowPartial); got != tc.want {
			t.Errorf("%s: scanExitCode = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestSafeDisplay(t *testing.T) {
	if got := safeDisplay("normal/key"); got != "normal/key" {
		t.Errorf("plain key changed: %q", got)
	}
	got := safeDisplay("evil\nStatus: complete")
	if strings.Contains(got, "\n") {
		t.Errorf("newline not escaped: %q", got)
	}
	if got := safeDisplay("esc\x1b[2J"); strings.Contains(got, "\x1b") {
		t.Errorf("ANSI escape not neutralized: %q", got)
	}
	// Unicode presentation controls must be neutralized too.
	for _, bad := range []string{"a‮b", "a⁦b", "a​b"} {
		if got := safeDisplay(bad); got == bad {
			t.Errorf("unicode format control not escaped in %q", bad)
		}
	}
}

func TestExitForState(t *testing.T) {
	cases := []struct {
		state        AccessState
		failIfPublic bool
		want         int
	}{
		{AccessPublic, true, exitPublic},
		{AccessPublic, false, exitNotPublic},
		{AccessNotPublic, true, exitNotPublic},
		{AccessInconclusive, true, exitError},
	}
	for _, tc := range cases {
		if got := exitForState(tc.state, tc.failIfPublic); got != tc.want {
			t.Errorf("exitForState(%q, %v) = %d, want %d", tc.state, tc.failIfPublic, got, tc.want)
		}
	}
}
