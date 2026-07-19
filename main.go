// Command s3-access-check reports whether an S3 bucket or object is anonymously
// (publicly) accessible. Its primary check is a black-box, unauthenticated
// probe that reflects the resource's real, effective access state. With
// --inspect it additionally reads the AWS configuration (Block Public Access,
// bucket policy status, and ACLs) to explain why.
//
// Use it only against buckets and objects you own or are authorized to test.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

// Exit codes let the tool drive scripts and CI:
//
//	0  not public
//	1  public (anonymously accessible)
//	2  usage or runtime error
const (
	exitNotPublic = 0
	exitPublic    = 1
	exitError     = 2
)

// Report is the combined machine-readable output (--json).
type Report struct {
	Target    string         `json:"target"`
	Public    bool           `json:"public"`
	Operation string         `json:"operation"`
	Region    string         `json:"region"`
	Status    int            `json:"httpStatus"`
	S3Code    string         `json:"s3Code,omitempty"`
	Exists    *bool          `json:"exists,omitempty"`
	Inspect   *InspectResult `json:"inspect,omitempty"`
}

func main() {
	os.Exit(run())
}

func run() int {
	var (
		inspect      = flag.Bool("inspect", false, "also read AWS config (Block Public Access, policy status, ACLs) to explain the result; requires AWS credentials")
		asJSON       = flag.Bool("json", false, "emit the result as JSON")
		region       = flag.String("region", "", "override the S3 region instead of auto-detecting it")
		timeout      = flag.Duration("timeout", 15*time.Second, "overall timeout for network requests")
		failIfPublic = flag.Bool("fail-if-public", true, "exit 1 when the target is public (set to false to always exit 0 on success)")

		scan        = flag.Bool("scan", false, "scan every object in a bucket and report which are anonymously accessible (even when the bucket is not publicly listable)")
		prefix      = flag.String("prefix", "", "with --scan, only enumerate keys under this prefix")
		maxObjects  = flag.Int("max-objects", 1000, "with --scan, stop after enumerating this many objects (0 = no limit)")
		concurrency = flag.Int("concurrency", 16, "with --scan, number of concurrent anonymous probes")
		keysFrom    = flag.String("keys-from", "", "with --scan, read candidate keys from this file instead of the S3 API (no AWS credentials required)")
	)
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 1 {
		usage()
		return exitError
	}

	target, err := ParseTarget(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	if *region != "" {
		target.Region = *region
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if *scan {
		if target.IsObject() {
			fmt.Fprintln(os.Stderr, "error: --scan operates on a bucket; drop the object key from the target")
			return exitError
		}
		return runScan(ctx, target, *asJSON, *failIfPublic, ScanOptions{
			Prefix:      *prefix,
			MaxObjects:  *maxObjects,
			Concurrency: *concurrency,
			KeysFrom:    *keysFrom,
			Region:      target.Region,
		})
	}

	anon, err := CheckAnonymous(ctx, anonymousClient(), target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}

	report := Report{
		Target:    target.String(),
		Public:    anon.Public,
		Operation: anon.Operation,
		Region:    anon.Region,
		Status:    anon.StatusCode,
		S3Code:    anon.S3Code,
		Exists:    anon.Exists,
	}

	if *inspect {
		ins, err := Inspect(ctx, target, anon.Region)
		if err != nil {
			// Inspection is best-effort; surface the reason but do not fail the
			// whole run — the anonymous verdict still stands.
			fmt.Fprintf(os.Stderr, "warning: config inspection skipped: %v\n", err)
		} else {
			report.Inspect = &ins
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return exitError
		}
	} else {
		printHuman(report, anon)
	}

	if anon.Public && *failIfPublic {
		return exitPublic
	}
	return exitNotPublic
}

func runScan(ctx context.Context, target Target, asJSON, failIfPublic bool, opts ScanOptions) int {
	// Resolve region once up front so the per-object probes reuse it.
	if opts.Region == "" {
		r, err := ResolveRegion(ctx, anonymousClient(), target.Bucket)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: resolving region: %v\n", err)
			return exitError
		}
		opts.Region = r
	}

	res, err := ScanBucket(ctx, anonymousClient(), target.Bucket, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return exitError
		}
	} else {
		printScan(res)
	}

	if len(res.PublicObjects) > 0 && failIfPublic {
		return exitPublic
	}
	return exitNotPublic
}

func printScan(r ScanResult) {
	fmt.Printf("Bucket:    s3://%s\n", r.Bucket)
	fmt.Printf("Region:    %s\n", r.Region)
	fmt.Printf("Source:    %s (enumerated %d, probed %d objects)\n", r.Source, r.Enumerated, r.Probed)
	if r.Truncated {
		fmt.Println("Note:      enumeration hit the --max-objects limit; more objects were not scanned")
	}
	if len(r.PublicObjects) == 0 {
		fmt.Println("Result:    no anonymously accessible objects found")
		return
	}
	fmt.Printf("Result:    %d PUBLIC object(s) found:\n", len(r.PublicObjects))
	for _, o := range r.PublicObjects {
		fmt.Printf("  PUBLIC  s3://%s/%s  (HTTP %d)\n", r.Bucket, o.Key, o.Status)
	}
}

func printHuman(r Report, anon AnonResult) {
	verdict := "NOT PUBLIC"
	if r.Public {
		verdict = "PUBLIC"
	}
	kind := "bucket"
	if anon.Target.IsObject() {
		kind = "object"
	}

	fmt.Printf("Target:    %s (%s)\n", r.Target, kind)
	fmt.Printf("Region:    %s\n", r.Region)
	fmt.Printf("Anonymous: %s  (%s -> HTTP %d", verdict, r.Operation, r.Status)
	if r.S3Code != "" {
		fmt.Printf(" %s", r.S3Code)
	}
	fmt.Print(")\n")

	if r.Exists != nil && !*r.Exists {
		fmt.Println("Note:      the resource does not appear to exist")
	}

	if r.Public {
		if anon.Target.IsObject() {
			fmt.Println("Meaning:   anyone can download this object without credentials")
		} else {
			fmt.Println("Meaning:   anyone can list this bucket's contents without credentials")
			fmt.Println("           (individual objects may have different, separate permissions)")
		}
	}

	if r.Inspect != nil {
		printInspect(*r.Inspect)
	}
}

func printInspect(ins InspectResult) {
	fmt.Println("\nConfiguration (authenticated):")
	if pab := ins.PublicAccessBlock; pab != nil {
		fmt.Printf("  Block Public Access: acls=%t ignoreAcls=%t policy=%t restrict=%t\n",
			pab.BlockPublicACLs, pab.IgnorePublicACLs, pab.BlockPublicPolicy, pab.RestrictPublicBuckets)
	}
	if ins.PolicyIsPublic != nil {
		fmt.Printf("  Bucket policy public: %t\n", *ins.PolicyIsPublic)
	}
	if ins.ACLGrantsPublic != nil {
		fmt.Printf("  ACL grants public:    %t\n", *ins.ACLGrantsPublic)
		if len(ins.ACLGrantees) > 0 {
			fmt.Printf("  Public grantees:      %v\n", ins.ACLGrantees)
		}
	}
	for check, msg := range ins.Errors {
		fmt.Printf("  %s: unavailable (%s)\n", check, msg)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `s3-access-check - report whether an S3 bucket or object is anonymously accessible

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
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Exit codes:
  0  not public
  1  public
  2  error

Only run this against buckets and objects you own or are authorized to test.
`)
}
