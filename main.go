// Command s3-access-check reports whether an S3 bucket or object is anonymously
// (publicly) accessible. Its primary check is a black-box, unauthenticated
// probe that reflects the resource's real, effective access state. With
// --inspect it additionally reads the AWS configuration (Block Public Access,
// bucket policy status, and ACLs) to explain why; with --scan it enumerates a
// bucket's objects and probes each anonymously.
//
// Use it only against buckets and objects you own or are authorized to test.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "dev"

// schemaVersion identifies the JSON output contract so automation can detect
// breaking changes. v2 added tri-state fields, scan scope/versions, and the
// caller-account BPA rename.
const schemaVersion = 2

// Exit codes let the tool drive scripts and CI:
//
//	0  not public (definitively)
//	1  public (anonymously accessible)
//	2  inconclusive, usage, or runtime error
const (
	exitNotPublic = 0
	exitPublic    = 1
	exitError     = 2
)

// Report is the combined machine-readable output for a single-target check.
type Report struct {
	SchemaVersion int            `json:"schemaVersion"`
	ToolVersion   string         `json:"toolVersion"`
	Target        string         `json:"target"`
	State         AccessState    `json:"state"`
	Public        bool           `json:"public"`
	Operation     string         `json:"operation"`
	Region        string         `json:"region"`
	Status        int            `json:"httpStatus,omitempty"`
	S3Code        string         `json:"s3Code,omitempty"`
	Exists        *bool          `json:"exists,omitempty"`
	Error         string         `json:"error,omitempty"`
	Inspect       *InspectResult `json:"inspect,omitempty"`
}

// ScanReport wraps a ScanResult with output metadata.
type ScanReport struct {
	SchemaVersion int    `json:"schemaVersion"`
	ToolVersion   string `json:"toolVersion"`
	ScanResult
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("s3-access-check", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		inspect        = fs.Bool("inspect", false, "also read AWS config (Block Public Access, policy status, ACLs) to explain the result; requires AWS credentials")
		asJSON         = fs.Bool("json", false, "emit the result as JSON")
		region         = fs.String("region", "", "override the S3 region instead of auto-detecting it")
		requestTimeout = fs.Duration("request-timeout", 15*time.Second, "timeout for each anonymous HTTP request (AWS SDK calls are bounded by --timeout)")
		timeout        = fs.Duration("timeout", 60*time.Second, "overall timeout for the whole operation (raise this for large scans)")
		failIfPublic   = fs.Bool("fail-if-public", true, "exit 1 when the target (or, in scan mode, any object) is public")
		showVersion    = fs.Bool("version", false, "print version and exit")

		listPrefix = fs.String("list-prefix", "", "for a single bucket check, test anonymous ListBucket scoped to this prefix (some policies grant listing only under a prefix)")

		scan            = fs.Bool("scan", false, "scan every object in a bucket and report which are anonymously accessible (even when the bucket is not publicly listable)")
		prefix          = fs.String("prefix", "", "with --scan, only enumerate keys under this prefix")
		maxObjects      = fs.Int("max-objects", 1000, "with --scan, stop after enumerating this many objects (0 = no limit)")
		concurrency     = fs.Int("concurrency", 16, "with --scan, number of concurrent anonymous probes (1-256)")
		keysFrom        = fs.String("keys-from", "", "with --scan, read candidate keys from this file instead of the S3 API (no AWS credentials required)")
		includeVersions = fs.Bool("include-versions", false, "with --scan (S3 API source), enumerate all object versions via ListObjectVersions, not just current versions")
		allowPartial    = fs.Bool("allow-partial", false, "with --scan, exit 0 for a truncated/incomplete scan that found no public object (default: incomplete scans exit 2)")
	)
	fs.Usage = func() { usage(stderr, fs) }

	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if *showVersion {
		fmt.Fprintf(stdout, "s3-access-check %s\n", version)
		return exitNotPublic
	}

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	if fs.NArg() != 1 {
		usage(stderr, fs)
		return exitError
	}

	// Validate flag values and combinations.
	if *timeout <= 0 || *requestTimeout <= 0 {
		fmt.Fprintln(stderr, "error: --timeout and --request-timeout must be positive")
		return exitError
	}
	if *region != "" && !validRegion(*region) {
		fmt.Fprintf(stderr, "error: invalid --region %q\n", *region)
		return exitError
	}
	if err := validateScanFlags(*scan, *inspect, *maxObjects, *concurrency, *keysFrom, *includeVersions, set); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}

	target, err := ParseTarget(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}
	if *region != "" {
		target.Region = *region
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	client := anonymousClient(*requestTimeout)

	if *scan {
		if target.IsObject() {
			fmt.Fprintln(stderr, "error: --scan operates on a bucket; drop the object key from the target")
			return exitError
		}
		return runScan(ctx, stdout, stderr, client, target, *asJSON, *failIfPublic, *allowPartial, ScanOptions{
			Prefix:          *prefix,
			MaxObjects:      *maxObjects,
			Concurrency:     *concurrency,
			KeysFrom:        *keysFrom,
			IncludeVersions: *includeVersions,
			Region:          target.Region,
		})
	}

	return runCheck(ctx, stdout, stderr, client, target, *inspect, *asJSON, *failIfPublic, *listPrefix)
}

// validRegion accepts conservative AWS region tokens (e.g. us-east-1,
// ap-south-2), rejecting whitespace, separators, and malformed values.
var regionTokenRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)+$`)

func validRegion(r string) bool { return regionTokenRe.MatchString(r) }

func validateScanFlags(scan, inspect bool, maxObjects, concurrency int, keysFrom string, includeVersions bool, set map[string]bool) error {
	if scan {
		if inspect {
			return fmt.Errorf("--inspect is not supported with --scan")
		}
		if maxObjects < 0 {
			return fmt.Errorf("--max-objects must be >= 0")
		}
		if concurrency < 1 || concurrency > 256 {
			return fmt.Errorf("--concurrency must be between 1 and 256")
		}
		if includeVersions && keysFrom != "" {
			return fmt.Errorf("--include-versions requires the S3 API source and cannot be combined with --keys-from")
		}
		return nil
	}
	// Reject scan-only flags outside scan mode so a user is never misled into
	// thinking a limit or filter was applied.
	for _, name := range []string{"prefix", "max-objects", "concurrency", "keys-from", "include-versions", "allow-partial"} {
		if set[name] {
			return fmt.Errorf("--%s requires --scan", name)
		}
	}
	return nil
}

func runCheck(ctx context.Context, stdout, stderr io.Writer, client *http.Client, target Target, inspect, asJSON, failIfPublic bool, listPrefix string) int {
	anon, err := CheckAnonymous(ctx, client, target, listPrefix)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}

	report := Report{
		SchemaVersion: schemaVersion,
		ToolVersion:   version,
		Target:        target.String(),
		State:         anon.State,
		Public:        anon.Public(),
		Operation:     anon.Operation,
		Region:        anon.Region,
		Status:        anon.StatusCode,
		S3Code:        anon.S3Code,
		Exists:        anon.Exists,
		Error:         anon.Err,
	}

	if inspect {
		ins, err := Inspect(ctx, target, anon.Region)
		if err != nil {
			fmt.Fprintf(stderr, "warning: config inspection skipped: %v\n", err)
			report.Inspect = &InspectResult{Target: target, Errors: map[string]string{"inspection": err.Error()}}
		} else {
			report.Inspect = &ins
		}
	}

	if asJSON {
		if err := writeJSON(stdout, report); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitError
		}
	} else {
		printHuman(stdout, report, anon)
	}

	return exitForState(anon.State, failIfPublic)
}

func exitForState(state AccessState, failIfPublic bool) int {
	switch state {
	case AccessPublic:
		if failIfPublic {
			return exitPublic
		}
		return exitNotPublic
	case AccessNotPublic:
		return exitNotPublic
	default:
		return exitError
	}
}

func runScan(ctx context.Context, stdout, stderr io.Writer, client *http.Client, target Target, asJSON, failIfPublic, allowPartial bool, opts ScanOptions) int {
	// Resolve region once up front so the per-object probes reuse it.
	if opts.Region == "" {
		r, err := ResolveRegion(ctx, client, target.Bucket)
		if err != nil {
			fmt.Fprintf(stderr, "error: resolving region: %v\n", err)
			return exitError
		}
		opts.Region = r
	}

	res, err := ScanBucket(ctx, client, target.Bucket, opts)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}

	if asJSON {
		if err := writeJSON(stdout, ScanReport{SchemaVersion: schemaVersion, ToolVersion: version, ScanResult: res}); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitError
		}
	} else {
		printScan(stdout, res)
	}

	return scanExitCode(res, failIfPublic, allowPartial)
}

// scanExitCode maps a scan result to an exit code. A confirmed public object is
// actionable regardless of completeness, so it takes precedence. Crucially,
// --fail-if-public=false must NOT suppress an incomplete-scan error:
// completeness is checked independently.
func scanExitCode(res ScanResult, failIfPublic, allowPartial bool) int {
	if res.PublicCount > 0 && failIfPublic {
		return exitPublic
	}
	if !res.Complete && !allowPartial {
		return exitError
	}
	return exitNotPublic
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printHuman(w io.Writer, r Report, anon AnonResult) {
	kind := "bucket"
	if anon.Target.IsObject() {
		kind = "object"
	}

	fmt.Fprintf(w, "Target:    %s (%s)\n", safeDisplay(r.Target), kind)
	fmt.Fprintf(w, "Region:    %s\n", r.Region)
	fmt.Fprintf(w, "Anonymous: %s  (%s -> HTTP %d", r.State.Verdict(), r.Operation, r.Status)
	if r.S3Code != "" {
		fmt.Fprintf(w, " %s", r.S3Code)
	}
	fmt.Fprint(w, ")\n")

	if r.State == AccessInconclusive {
		fmt.Fprintf(w, "Note:      result is INCONCLUSIVE — could not determine access (%s)\n", r.Error)
	}
	if r.Exists != nil && !*r.Exists {
		fmt.Fprintln(w, "Note:      the resource does not appear to exist")
	}

	if r.Public {
		if anon.Target.IsObject() {
			fmt.Fprintln(w, "Meaning:   this unsigned request retrieved the object — it is anonymously downloadable")
		} else {
			fmt.Fprintln(w, "Meaning:   this unsigned request listed the bucket — it is anonymously listable")
			fmt.Fprintln(w, "           (individual objects may have different, separate permissions)")
		}
		fmt.Fprintln(w, "           Note: reflects this request's context; policies conditioned on source IP,")
		fmt.Fprintln(w, "           headers, or time may differ for other anonymous callers.")
	}

	if r.Inspect != nil {
		printInspect(w, *r.Inspect)
	}
}

// safeDisplay escapes control characters so untrusted object keys cannot inject
// newlines or ANSI escape sequences into terminal or CI-log output.
func safeDisplay(s string) string {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return strconv.QuoteToASCII(s)
		}
	}
	return s
}

func printInspect(w io.Writer, ins InspectResult) {
	fmt.Fprintln(w, "\nConfiguration (authenticated):")
	printPAB(w, "  Bucket Block Public Access:", ins.BucketPublicAccessBlock)
	printPAB(w, "  Caller-account Block Public Access:", ins.CallerAccountPublicAccessBlock)

	if ins.BucketPolicy.Present {
		if ins.BucketPolicy.Public != nil {
			fmt.Fprintf(w, "  Bucket policy:        present, public=%t\n", *ins.BucketPolicy.Public)
		} else {
			fmt.Fprintln(w, "  Bucket policy:        present")
		}
	} else {
		fmt.Fprintln(w, "  Bucket policy:        none")
	}

	if ins.ACL.AllowsAnonymousOperation != nil {
		fmt.Fprintf(w, "  ACL allows checked operation anonymously: %t\n", *ins.ACL.AllowsAnonymousOperation)
	}
	if len(ins.ACL.AnonymousGrants) > 0 {
		fmt.Fprintf(w, "  Anonymous ACL grants: %v\n", ins.ACL.AnonymousGrants)
	}
	if len(ins.ACL.AuthenticatedAWSUsersGrants) > 0 {
		fmt.Fprintf(w, "  AuthenticatedUsers ACL grants (any AWS account, not anonymous): %v\n", ins.ACL.AuthenticatedAWSUsersGrants)
	}

	for _, warn := range ins.Warnings {
		fmt.Fprintf(w, "  warning: %s\n", warn)
	}
	// Deterministic ordering for stable output.
	keys := make([]string, 0, len(ins.Errors))
	for k := range ins.Errors {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "  %s: unavailable (%s)\n", k, ins.Errors[k])
	}
}

func printPAB(w io.Writer, label string, pab *PublicAccessBlock) {
	if pab == nil {
		fmt.Fprintf(w, "%s unknown\n", label)
		return
	}
	if !pab.Configured {
		fmt.Fprintf(w, "%s not configured\n", label)
		return
	}
	fmt.Fprintf(w, "%s acls=%t ignoreAcls=%t policy=%t restrict=%t\n",
		label, pab.BlockPublicACLs, pab.IgnorePublicACLs, pab.BlockPublicPolicy, pab.RestrictPublicBuckets)
}

func printScan(w io.Writer, r ScanResult) {
	fmt.Fprintf(w, "Bucket:    s3://%s\n", r.Bucket)
	fmt.Fprintf(w, "Region:    %s\n", r.Region)
	fmt.Fprintf(w, "Source:    %s\n", r.Source)
	fmt.Fprintf(w, "Scope:     %s\n", r.Scope)
	fmt.Fprintf(w, "Coverage:  enumerated %d, completed %d (public %d, not-public %d, inconclusive %d)\n",
		r.Enumerated, r.Completed, r.PublicCount, r.NotPublicCount, r.InconclusiveCount)
	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "Warning:   %s\n", warn)
	}

	if !r.Complete {
		reasons := []string{}
		if r.Truncated {
			reasons = append(reasons, "hit --max-objects limit")
		}
		if r.Cancelled {
			reasons = append(reasons, "timed out / cancelled")
		}
		if r.InconclusiveCount > 0 {
			reasons = append(reasons, fmt.Sprintf("%d probe(s) inconclusive", r.InconclusiveCount))
		}
		fmt.Fprintf(w, "Status:    INCOMPLETE (%s) — a clean result here does NOT certify the bucket\n", joinReasons(reasons))
	} else {
		fmt.Fprintln(w, "Status:    complete")
	}

	if len(r.PublicObjects) == 0 {
		fmt.Fprintln(w, "Result:    no anonymously accessible objects found in what was checked")
	} else {
		fmt.Fprintf(w, "Result:    %d PUBLIC object(s) found:\n", len(r.PublicObjects))
		for _, o := range r.PublicObjects {
			fmt.Fprintf(w, "  PUBLIC  s3://%s/%s%s  (HTTP %d)\n", r.Bucket, safeDisplay(o.Key), versionSuffix(o.VersionID), o.Status)
		}
	}
	if len(r.Failures) > 0 {
		fmt.Fprintf(w, "  %d object(s) could not be checked (inconclusive):\n", len(r.Failures))
		for _, o := range r.Failures {
			fmt.Fprintf(w, "  INCONCLUSIVE  s3://%s/%s%s  (%s)\n", r.Bucket, safeDisplay(o.Key), versionSuffix(o.VersionID), o.Err)
		}
	}
}

func versionSuffix(v string) string {
	if v == "" {
		return ""
	}
	return "?versionId=" + v
}

func joinReasons(reasons []string) string {
	if len(reasons) == 0 {
		return "incomplete"
	}
	out := reasons[0]
	for _, r := range reasons[1:] {
		out += "; " + r
	}
	return out
}

func usage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintf(w, `s3-access-check - report whether an S3 bucket or object is anonymously accessible

Usage:
  s3-access-check [flags] <target>

Target formats:
  s3://bucket/key
  https://bucket.s3.region.amazonaws.com/key
  https://s3.region.amazonaws.com/bucket/key
  bucket
  bucket/key

Scan a whole bucket for publicly accessible objects (even when the bucket
itself is not publicly listable):
  s3-access-check --scan s3://my-bucket                 # enumerate via S3 API (needs AWS creds)
  s3-access-check --scan --keys-from keys.txt s3://my-bucket   # probe known keys, no creds

Flags:
`)
	fs.PrintDefaults()
	fmt.Fprintf(w, `
Exit codes:
  0  not public (definitively)
  1  public
  2  inconclusive, usage, or error

Only run this against buckets and objects you own or are authorized to test.
`)
}
