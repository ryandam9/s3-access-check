# s3-access-check

[![CI](https://github.com/ryandam9/s3-access-check/actions/workflows/ci.yml/badge.svg)](https://github.com/ryandam9/s3-access-check/actions/workflows/ci.yml)

A small, dependency-light Go CLI that answers one question precisely:

> **Can an anonymous caller — someone with no AWS credentials — access this S3 bucket or object right now?**

It works as a **black-box probe**: it makes a real, unauthenticated request to S3
and reads the result. That reflects the resource's *effective* access state —
the same thing a random visitor on the internet would experience — regardless of
*how* the access was configured (bucket policy, ACL, or Block Public Access).
Optionally it can also read your AWS configuration to explain *why* (`--inspect`)
and sweep every object in a bucket (`--scan`).

> ⚠️ **Use responsibly.** Only run this against buckets and objects you own or are
> explicitly authorized to test. Pointed at arbitrary buckets, an access probe is
> reconnaissance.

---

## Table of contents

- [Why a black-box probe](#why-a-black-box-probe)
- [Install](#install)
- [Quick start](#quick-start)
- [Core concepts](#core-concepts)
  - [Three-valued results](#three-valued-results)
  - [Exit codes](#exit-codes)
  - [Bucket vs. object; listable vs. downloadable](#bucket-vs-object-listable-vs-downloadable)
  - [Request-context caveat](#request-context-caveat)
- [Target formats](#target-formats)
- [Checking a single bucket or object](#checking-a-single-bucket-or-object)
- [Scanning a bucket](#scanning-a-bucket)
  - [Two key sources](#two-key-sources)
  - [Scan completeness: within-scope vs. whole-bucket](#scan-completeness-within-scope-vs-whole-bucket)
  - [Object versions](#object-versions)
- [Explaining the result with `--inspect`](#explaining-the-result-with---inspect)
- [JSON output](#json-output)
- [Flag reference](#flag-reference)
- [Using it in CI](#using-it-in-ci)
- [Least-privilege IAM](#least-privilege-iam)
- [Supported resources](#supported-resources)
- [How it works](#how-it-works)
- [Troubleshooting & FAQ](#troubleshooting--faq)
- [Development](#development)
- [Security](#security)
- [License](#license)

---

## Why a black-box probe

"Is this public?" has two very different answers:

1. **What the configuration says** — bucket policy, ACLs, and Block Public Access
   settings, combined by AWS's evaluation rules. Reading these requires
   credentials and careful interpretation.
2. **What actually happens** when an anonymous request arrives.

`s3-access-check` prioritizes **(2)**, because that is the answer that matters for
exposure. It makes the unauthenticated request and reports what S3 did. `(1)` is
available on demand via `--inspect` to *explain* the result — but the verdict
itself never depends on parsing policy.

A guiding principle throughout the tool:

> **Failure to prove public access is not the same as proving a resource is not public.**

That is why results are three-valued (below), and why bucket scans *fail closed*.

---

## Install

With Go 1.25+:

```sh
go install github.com/ryandam9/s3-access-check@latest
```

### Build from source

```sh
git clone https://github.com/ryandam9/s3-access-check
cd s3-access-check
go build -o s3-access-check .
```

Or use the **Makefile**, which stamps version/commit/date into the binary via
`-ldflags` (so `-version` reports real build metadata):

```sh
make build                 # -> bin/s3-access-check
make install               # build + copy to ~/.local/bin (on PATH) or /usr/local/bin
make install PREFIX=~/bin  # ...or an explicit destination
```

`make help` lists every target (`fmt`, `vet`, `test`, `build`, `install`,
`clean`, `run`, `tidy`, `lint`). See [Development](#development) for the rest.

Check the version:

```sh
$ s3-access-check -version
s3-access-check v1.2.0 (commit 3f33af5, built 2026-07-22T07:38:52Z)
```

(A plain `go build` without the ldflags reports `dev` / `none` / `unknown` —
use `make build` or `go install` at a tag for real metadata.)

---

## Quick start

None of these need AWS credentials — they probe a public AWS Open Data bucket:

```sh
# Is this bucket anonymously listable?
s3-access-check s3://noaa-goes16
#  → Anonymous: PUBLIC  (ListBucket -> HTTP 200)   exit 1

# Is this specific object anonymously downloadable?
s3-access-check https://noaa-goes16.s3.amazonaws.com/index.html
#  → Anonymous: PUBLIC  (GetObject -> HTTP 206)     exit 1

# A private bucket
s3-access-check s3://elasticbeanstalk-us-east-1-123456789012
#  → Anonymous: NOT PUBLIC  (ListBucket -> HTTP 403 AccessDenied)   exit 0

# Machine-readable
s3-access-check -json s3://noaa-goes16
```

Against **your own** bucket (uses your AWS credentials for the optional modes):

```sh
s3-access-check -inspect s3://my-bucket          # explain why it is / isn't public
s3-access-check -scan s3://my-bucket             # probe every object
s3-access-check -scan -include-versions s3://my-bucket   # ...including old versions
```

---

## Core concepts

### Three-valued results

Because this is a security tool, it never conflates "proven not public" with
"couldn't tell". Every check yields exactly one state:

| State | Meaning | Exit code |
| --- | --- | --- |
| **public** | an anonymous request succeeded (`2xx`) | `1` |
| **not_public** | an anonymous request was definitively denied (`403`) or the resource is absent (`404`) | `0` |
| **inconclusive** | access could not be determined — a redirect loop, throttling (`429`), `5xx`, a timeout, a transport error, or any other unexpected status | `2` |

An `inconclusive` result (exit `2`) **must not be read as "safe"**. It means the
check did not complete, not that the resource is private.

### Exit codes

Designed so you can gate scripts and CI on them:

| Code | Meaning |
| --- | --- |
| `0` | **not public** — for a single check, a definitive `403`/`404`; for a scan, *no public object across a whole-bucket audit* |
| `1` | **public** — anonymously accessible |
| `2` | **inconclusive**, an incomplete/partial scan, or a usage/runtime error |

For scans, exit `0` requires a **whole-bucket** audit (see
[completeness](#scan-completeness-within-scope-vs-whole-bucket)); a clean but
partial scan exits `2` unless you pass `-allow-partial`.

### Bucket vs. object; listable vs. downloadable

These are **separate permissions**:

- A **bucket** target (no key) is checked for public **listability** — can an
  anonymous caller enumerate its contents (`ListBucket`)?
- An **object** target (with a key) is checked for public **downloadability** —
  can an anonymous caller retrieve it (`GetObject`)?

A private (non-listable) bucket can still contain individually public objects,
and a listable bucket can contain private objects. Checking one does not check
the other — that is exactly what [`-scan`](#scanning-a-bucket) is for.

The object check uses a real **data-plane `GET`** (requesting only the first
byte, `Range: bytes=0-0`), not a metadata-only `HEAD`. This matters: an object
whose bucket policy grants anonymous `s3:GetObject` but which still can't be
*retrieved* — because it needs SSE-KMS decryption the anonymous caller lacks, or
it's in an archived/unrestored storage class — is correctly reported **not
downloadable**, instead of the false "public" a `HEAD` would report.

### Request-context caveat

A `public` result reflects **this request's context**. S3 policies can condition
access on source IP, headers, referrer, time of day, or VPC endpoint, so another
anonymous caller from a different network might get a different answer. The
verdict means precisely:

> *"This unsigned request, from here, right now, succeeded."*

That is strong evidence of exposure — but it is not a proof about every possible
caller. The human output prints this caveat alongside every `PUBLIC` verdict.

---

## Target formats

The target can be given in whichever form you have on hand:

| Format | Example |
| --- | --- |
| `s3://` URI | `s3://my-bucket/path/key.txt` |
| Virtual-hosted URL | `https://my-bucket.s3.us-east-1.amazonaws.com/key.txt` |
| Path-style URL | `https://s3.us-east-1.amazonaws.com/my-bucket/key.txt` |
| Bare bucket | `my-bucket` |
| Bucket + key | `my-bucket/key.txt` |

Notes:

- Only AWS S3 hosts (`*.amazonaws.com`) are accepted in URLs; an unknown host is
  **rejected**, never silently reinterpreted as an AWS bucket name.
- **Signed / presigned URLs are rejected** — the tool must remain anonymous.
- A `versionId` query parameter is honored for object checks
  (`...&versionId=abc123`, or `versionId=null` for the null version). Any other
  query parameter is rejected.
- Key bytes are preserved. For `s3://` and bare inputs the key is literal (matching
  AWS CLI convention); for `https://` URLs the path is percent-decoded per URL
  rules.

---

## Checking a single bucket or object

**A listable bucket:**

```console
$ s3-access-check s3://noaa-goes16
Target:    s3://noaa-goes16 (bucket)
Region:    us-east-1
Anonymous: PUBLIC  (ListBucket -> HTTP 200)
Meaning:   this unsigned request listed the bucket — it is anonymously listable
           (individual objects may have different, separate permissions)
           Note: reflects this request's context; policies conditioned on source IP,
           headers, or time may differ for other anonymous callers.
```

**A downloadable object:**

```console
$ s3-access-check https://noaa-goes16.s3.amazonaws.com/index.html
Target:    s3://noaa-goes16/index.html (object)
Region:    us-east-1
Anonymous: PUBLIC  (GetObject -> HTTP 206)
Meaning:   this unsigned request retrieved the object — it is anonymously downloadable
```

**A private bucket / a missing one:**

```console
$ s3-access-check s3://my-private-bucket
Anonymous: NOT PUBLIC  (ListBucket -> HTTP 403 AccessDenied)

$ s3-access-check s3://this-bucket-does-not-exist-xyz
Anonymous: NOT PUBLIC  (ListBucket -> HTTP 404 NoSuchBucket)
Note:      the resource does not appear to exist
```

**Prefix-conditioned listing.** Some policies grant anonymous `ListBucket` only
under a specific prefix. Test that explicitly — the tested prefix is bound to the
verdict:

```console
$ s3-access-check -list-prefix public/ s3://my-bucket
Anonymous: PUBLIC  (ListBucket -> HTTP 200)
Prefix:    public/
Meaning:   this unsigned request listed objects under prefix public/ — that prefix is anonymously listable
```

`-list-prefix` is for a single **bucket** check; it is rejected for an object
target or with `-scan` (use `-prefix` to scope a scan).

---

## Scanning a bucket

A bucket that is **not** publicly listable can still contain individually public
objects. `-scan` finds them by enumerating the bucket's keys and probing each one
anonymously.

*Enumeration* is streamed through a bounded worker pool, so enumeration memory
stays flat regardless of bucket size. The number of retained public/inconclusive
**examples** in the output is bounded separately by `-max-findings` (counts stay
exact).

### Two key sources

Because you cannot enumerate a non-listable bucket anonymously, key discovery
uses one of two sources:

**1. The S3 API (default)** — lists objects with your AWS credentials
(`s3:ListBucket`). Use this to audit your own buckets:

```sh
s3-access-check -scan s3://my-bucket
s3-access-check -scan -prefix logs/ -max-objects 5000 s3://my-bucket
```

**2. A candidate key list (`-keys-from`)** — probes a newline-delimited file of
keys with **no credentials required**. Keys are used **verbatim** (only a trailing
CR is stripped); leading slashes, spaces, and `#` are all valid key bytes and are
preserved; blank lines are skipped:

```sh
printf '%s\n' index.html backups/db.sql > keys.txt
s3-access-check -scan -keys-from keys.txt s3://my-bucket
```

Example output:

```console
$ s3-access-check -scan -keys-from keys.txt s3://my-bucket
Bucket:    s3://my-bucket
Region:    us-east-1
Source:    keys-file
Scope:     current_versions (unit: keys)
Coverage:  enumerated 2, completed 2 (public 1, not-public 1, inconclusive 0)
Status:    complete WITHIN SCOPE, but this is NOT a whole-bucket audit
           (a clean result here does NOT certify the entire bucket)
Result:    1 PUBLIC object(s) found (showing 1):
  PUBLIC  s3://my-bucket/index.html  (HTTP 206)
```

### Scan completeness: within-scope vs. whole-bucket

A scan separates **mechanical** completeness from **audit** coverage. This is the
most important thing to understand about scan results:

- **`completeWithinScope`** — every enumerated candidate was probed conclusively
  (not truncated, not cancelled, no inconclusive probe).
- **`wholeBucketComplete`** — that scope *was the entire bucket*: enumerated via
  the S3 API (not a key file), no `-prefix`, and all data-bearing versions
  covered (either `-include-versions`, or versioning is known to be off so
  current == whole).

The tool **fails closed**: **exit `0` requires `wholeBucketComplete`.** A scan
that is clean but only partial — a prefix, a `-keys-from` candidate list, or
current-versions-only on a versioned/unknown bucket — exits `2` unless you pass
`-allow-partial`. This prevents *"I checked some things and found nothing"* from
being mistaken for *"the bucket has no anonymous exposure."*

The output states this plainly:

```
Status:    complete — whole-bucket audit                          # exit 0 on a clean result
Status:    complete WITHIN SCOPE, but this is NOT a whole-bucket audit   # exit 2 unless --allow-partial
Status:    INCOMPLETE within scope (hit --max-objects limit; 2 probe(s) inconclusive)   # exit 2
```

A confirmed public object always makes the scan exit `1` (when `-fail-if-public`
is on), regardless of coverage — a real finding is actionable immediately.

### Object versions

By default a scan covers **current** object versions only (`scope:
current_versions`). In a versioning-enabled bucket, a *noncurrent* version can be
independently public — a different ACL, or an old version hidden behind a delete
marker. So the default scan detects versioning (`GetBucketVersioning`) and
**warns** that noncurrent versions were not checked:

```
Versioning: Enabled
Warning:   bucket versioning is enabled; noncurrent object versions were NOT scanned — pass --include-versions for a whole-bucket audit
```

If that versioning lookup itself *fails* (e.g. missing `s3:GetBucketVersioning`),
the failure is **surfaced**, and the scan cannot claim `wholeBucketComplete` — so
it will not exit `0` without `-allow-partial`.

Pass `-include-versions` to enumerate every **data-bearing** version via
`ListObjectVersions` (`scope: all_versions`). Findings then carry a `versionId`,
and delete markers are counted (`deleteMarkersObserved`) but not probed, since
they have no object body:

```sh
s3-access-check -scan -include-versions s3://my-bucket
```

> Note on units: `-max-objects` counts **targets** — current keys by default, or
> *versions* with `-include-versions`. A bucket with deep version history reaches
> the limit in fewer keys.

---

## Explaining the result with `--inspect`

`-inspect` uses your AWS credentials to read the configuration that governs public
access and print it alongside the black-box verdict. It's for buckets in your own
account.

```console
$ s3-access-check -inspect s3://my-bucket
Target:    s3://my-bucket (bucket)
Region:    us-east-1
Anonymous: NOT PUBLIC  (ListBucket -> HTTP 403 AccessDenied)

Configuration (authenticated):
  Bucket Block Public Access: acls=true ignoreAcls=true policy=true restrict=true
  Caller-account Block Public Access: acls=true ignoreAcls=true policy=true restrict=true
  Bucket policy:        none
  ACL allows checked operation anonymously: false
```

What it reads:

- **Block Public Access** at both the **bucket** and **caller-account** level
  (the latter via STS + S3 Control).
- **Bucket policy status** (`GetBucketPolicyStatus`) — present / public.
- **ACL grants**, evaluated **operation-aware**: an `AllUsers` grant of
  `READ`/`FULL_CONTROL` counts as anonymous read, but `READ_ACP`/`WRITE_ACP` do
  not (they're reported separately). `AuthenticatedUsers` grants (any AWS account,
  *not* anonymous) are also reported separately.

Each check is best-effort: a missing permission or a genuinely absent
configuration (no policy, no BPA) is reported as such rather than failing the run.

**Caveats it emits as warnings:**

- The account-level BPA is the **authenticated caller's** account, not verified to
  be the bucket owner's — for a cross-account bucket it may not describe the owning
  account.
- That account-level result may be enforced by an AWS Organizations S3 policy; the
  API does not identify the source.

---

## JSON output

Add `-json` to any check for machine-readable output. Every document carries a
`schemaVersion` (currently **3**) and `toolVersion` so automation can detect
changes.

**Single check:**

```json
{
  "schemaVersion": 3,
  "toolVersion": "1.0.0",
  "target": "s3://noaa-goes16",
  "targetRef": { "bucket": "noaa-goes16" },
  "state": "public",
  "public": true,
  "operation": "ListBucket",
  "region": "us-east-1",
  "httpStatus": 200,
  "exists": true
}
```

`targetRef` (structured `bucket`/`key`/`versionId`) is the **authoritative
identity**; `target` is a convenience display string and is not guaranteed
round-trippable for keys with reserved characters.

**Scan:**

```json
{
  "schemaVersion": 3,
  "toolVersion": "1.0.0",
  "bucket": "my-bucket",
  "region": "us-east-1",
  "source": "s3-api",
  "scope": "current_versions",
  "enumeratedUnit": "keys",
  "versioningStatus": "Enabled",
  "versioningKnown": true,
  "completeWithinScope": true,
  "wholeBucketComplete": false,
  "truncated": false,
  "cancelled": false,
  "findingsTruncated": false,
  "enumerated": 1240,
  "completed": 1240,
  "publicCount": 2,
  "notPublicCount": 1238,
  "inconclusiveCount": 0,
  "publicObjects": [
    { "key": "public/logo.png", "state": "public", "httpStatus": 206 }
  ],
  "failures": [],
  "warnings": [
    "bucket versioning is enabled; noncurrent object versions were NOT scanned — pass --include-versions for a whole-bucket audit"
  ]
}
```

Key fields for automation: gate on `publicCount > 0` for exposure, and on
`wholeBucketComplete` before trusting a clean result as bucket-wide.

---

## Flag reference

| Flag | Default | Description |
| --- | --- | --- |
| `-inspect` | `false` | Also read AWS config (Block Public Access at bucket **and** caller-account level, bucket policy status, ACLs) to explain the result. Requires AWS credentials. |
| `-list-prefix` | — | For a single bucket check, test anonymous `ListBucket` scoped to this prefix. |
| `-scan` | `false` | Scan the objects in a bucket and report which are anonymously accessible. |
| `-prefix` | — | With `-scan`, only enumerate keys under this prefix. |
| `-max-objects` | `1000` | With `-scan`, stop after enumerating this many **targets** — current keys, or versions with `-include-versions` (`0` = no limit). A coverage limit, not just performance. |
| `-max-findings` | `1000` | With `-scan`, cap the number of public/inconclusive **examples retained** in output (`0` = no cap). Counts stay exact. |
| `-concurrency` | `16` | With `-scan`, number of concurrent anonymous probes (1–256). |
| `-keys-from` | — | With `-scan`, read candidate keys from a file instead of the S3 API (no AWS credentials required). |
| `-include-versions` | `false` | With `-scan` (S3 API source), enumerate all data-bearing object versions, not just current. |
| `-allow-partial` | `false` | With `-scan`, exit `0` for a clean scan that did not fully cover the whole bucket. Default: such scans exit `2`. |
| `-json` | `false` | Emit the result as JSON (includes `schemaVersion` / `toolVersion`). |
| `-region` | auto | Override the S3 region instead of auto-detecting it. |
| `-request-timeout` | `15s` | Timeout for each anonymous HTTP request (AWS SDK calls are bounded by `-timeout`). |
| `-timeout` | `60s` | Overall timeout for the whole operation. **Raise this for large scans.** |
| `-fail-if-public` | `true` | Exit `1` when the target (or any scanned object) is public. Does **not** suppress the incomplete-scan exit `2`. |
| `-version` | | Print version and exit. |

---

## Using it in CI

The tool is built for pipelines: it makes no changes, needs no credentials for
the core check, and its exit codes are meaningful.

**Fail a build if a bucket is anonymously listable:**

```sh
# exit 1 = public, 0 = not public, 2 = inconclusive/error
s3-access-check s3://my-public-assets || {
  code=$?
  [ "$code" = 1 ] && { echo "::error::bucket is publicly listable"; exit 1; }
  [ "$code" = 2 ] && { echo "::warning::check was inconclusive"; exit 1; }
}
```

**Audit a whole bucket for public objects (credentialed job):**

```sh
# Exit 1 if any object is public; exit 2 if the audit couldn't cover the whole
# bucket (so a clean pass is trustworthy). --include-versions makes it exhaustive.
s3-access-check -scan -include-versions -timeout 10m s3://my-bucket
```

**Parse JSON for a dashboard:**

```sh
s3-access-check -scan -json s3://my-bucket \
  | jq '{public: .publicCount, whole: .wholeBucketComplete, keys: [.publicObjects[].key]}'
```

Tips:

- Raise `-timeout` for large scans (default `60s`) — otherwise a big bucket may
  come back incomplete (exit `2`), which is the safe-but-noisy outcome.
- Treat exit `2` as "needs attention," not "pass."
- Object keys can contain sensitive names; control characters and Unicode
  bidi/format characters in keys are escaped in human output, but be mindful of
  what lands in shared logs.

---

## Least-privilege IAM

The anonymous probe needs **no** AWS permissions at all. The optional modes do:

**Scan enumeration** (`-scan` via the S3 API; add `s3:ListBucketVersions` for
`-include-versions`, and `s3:GetBucketVersioning` for versioning detection):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketVersioning"],
      "Resource": "arn:aws:s3:::example-bucket"
    }
  ]
}
```

**Config inspection** (`-inspect`; add `s3:GetObjectVersionAcl` when checking a
specific object `versionId`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketAcl",
        "s3:GetObjectAcl",
        "s3:GetObjectVersionAcl",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

Credentials are resolved through the standard AWS SDK chain (environment,
`~/.aws/config` / `AWS_PROFILE`, SSO, instance/role, etc.).

---

## Supported resources

- **Supported:** general-purpose AWS S3 buckets via standard commercial
  (`*.amazonaws.com`) REST endpoints — path-style and virtual-hosted, including
  the legacy `s3-region` dash form and dualstack.
- **Not currently supported / untested:** access points, Multi-Region Access
  Points, Object Lambda, S3 Express directory buckets, transfer-acceleration and
  FIPS endpoints, the China (`amazonaws.com.cn`) partition, S3 website endpoints,
  and non-AWS S3-compatible services (MinIO, Ceph, etc.).

---

## How it works

1. **Region resolution** — an unauthenticated `HEAD` to the global endpoint reads
   the `x-amz-bucket-region` response header.
2. **Bucket check** — anonymous `GET /?list-type=2` (`ListBucket`), optionally
   scoped to `-list-prefix`.
3. **Object check** — anonymous ranged `GET` (`Range: bytes=0-0`), with a bounded
   full-`GET` fallback on `416` for zero-byte objects.
4. **Wrong-region handling** — a `301`/`307`/`400` that advertises the correct
   region triggers exactly one retry against it.
5. **Classification** — only `2xx` → *public*; `403`/`404` → *not public*; every
   other status → *inconclusive*.
6. **(Optional) `-inspect`** — reads bucket and caller-account Block Public
   Access, bucket policy status, and operation-aware ACL grants.
7. **(Optional) `-scan`** — streams enumeration (`ListObjectsV2`, or
   `ListObjectVersions` with `-include-versions`) into concurrent anonymous
   probes and tracks both completeness dimensions.

---

## Troubleshooting & FAQ

**A scan found no public objects but exited `2`, not `0`. Why?**
The scan was *complete within its scope* but not a *whole-bucket* audit — e.g. you
used `-keys-from`, `-prefix`, or scanned only current versions of a versioned
bucket. That is fail-closed by design. Add `-allow-partial` to accept a partial
clean result as exit `0`, or make it exhaustive with `-include-versions` and no
prefix.

**I get `INCONCLUSIVE` / exit `2` on a single check.**
S3 returned something other than a clean `2xx`/`403`/`404` — often throttling
(`429`), a `5xx`, or a timeout. Re-run; raise `-request-timeout` / `-timeout`;
check connectivity. Inconclusive never means "safe."

**"scanning needs AWS credentials to list objects (or use `--keys-from`)."**
`-scan` without `-keys-from` enumerates via the S3 API and needs credentials with
`s3:ListBucket`. Either configure credentials or supply a candidate key file.

**"error: unsupported endpoint host …" or "target looks like a signed/presigned URL".**
Only `*.amazonaws.com` hosts are accepted, and signed URLs are rejected so the
probe stays anonymous. Pass a plain `s3://`, bare `bucket/key`, or unsigned S3
URL.

**The `Region:` line is blank for an object.**
S3 doesn't always return `x-amz-bucket-region` on a successful object `GET`; the
verdict is unaffected. Pass `-region` to set it explicitly.

**Does it download the whole object?**
No — object checks request a single byte (`Range: bytes=0-0`); the zero-byte
fallback reads an empty body. It confirms retrievability without downloading data.

**Can I point it at MinIO / another S3-compatible service?**
Not currently — only AWS S3 endpoints are supported.

---

## Development

A [`Makefile`](Makefile) wraps the common tasks:

```sh
make build     # build bin/s3-access-check with version/commit/date stamped in
make test      # go test -race -count=1 ./...  (network-free; stubbed clients)
make vet       # go vet ./...
make fmt       # go fmt ./...
make lint      # golangci-lint (skipped if not installed)
make tidy      # go mod tidy
make run ARGS="s3://noaa-goes16"   # build + run against a target
make clean     # remove the binary and bin/
make all       # fmt + vet + test + build + install
```

Equivalent raw commands if you prefer:

```sh
go build ./...
go test -race ./...
go vet ./...
gofmt -l .                  # should print nothing
```

CI (GitHub Actions) runs a lint job (gofmt/vet/`go mod verify`), a
Linux/macOS/Windows test matrix with the race detector, and `govulncheck` on the
latest Go toolchain.

---

## Security

Report suspected vulnerabilities privately via GitHub's "Report a vulnerability"
(see [`SECURITY.md`](SECURITY.md)) rather than a public issue. And again: only run
this tool against resources you own or are authorized to test.

---

## License

[MIT](LICENSE).
