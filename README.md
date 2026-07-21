# s3-access-check

A small Go CLI that reports whether an Amazon S3 **bucket** or **object** is
**anonymously (publicly) accessible**.

Its primary check is a black-box, unauthenticated probe: it makes a request with
no credentials and reads the result. This reflects the resource's real,
effective access state — the same thing an anonymous visitor on the internet
would experience — regardless of *how* that access was configured (bucket
policy, ACL, or Block Public Access). With `--inspect` it can additionally read
the AWS configuration to explain *why*, and with `--scan` it can enumerate and
probe the objects in a bucket.

> **Use responsibly.** Only run this against buckets and objects you own or are
> explicitly authorized to test. Pointed at arbitrary buckets, an access probe
> is reconnaissance.

## Results are three-valued

Because this is a security tool, it never conflates "proven not public" with
"couldn't tell". Every check yields one of:

| State | Meaning | Exit code |
| --- | --- | --- |
| **public** | an anonymous request succeeded | `1` |
| **not_public** | an anonymous request was definitively denied (`403`) or the resource is absent (`404`) | `0` |
| **inconclusive** | the check could not determine access — redirect loop, throttling (`429`), `5xx`, timeout, transport error, or any unexpected status | `2` |

> **Failure to prove public access is not the same as proving a resource is not
> public.** An `inconclusive` result (exit `2`) must not be read as "safe".

A `public` result reflects **this request's context**. S3 policies can condition
access on source IP, headers, referrer, time, or VPC, so another anonymous
caller may get a different answer. The verdict means "this unsigned request, from
here, now, succeeded" — it is strong evidence, not a proof about every caller.

## Install

```sh
go install github.com/ryandam9/s3-access-check@latest
```

or build from source (Go 1.25+):

```sh
go build -o s3-access-check .
```

## Usage

```sh
s3-access-check [flags] <target>
```

Accepted target formats:

| Format | Example |
| --- | --- |
| `s3://` URI | `s3://my-bucket/path/key.txt` |
| Virtual-hosted URL | `https://my-bucket.s3.us-east-1.amazonaws.com/key.txt` |
| Path-style URL | `https://s3.us-east-1.amazonaws.com/my-bucket/key.txt` |
| Bare bucket | `my-bucket` |
| Bucket + key | `my-bucket/key.txt` |

Only AWS S3 hosts (`*.amazonaws.com`) are accepted in URLs; an unknown host is
rejected rather than silently reinterpreted as an AWS bucket name. Signed or
presigned URLs are rejected — the tool must remain anonymous. A `versionId`
query parameter is honored for object checks.

If the target has no key, the **bucket** is checked for public *listability*.
If it has a key, that **object** is checked for public *downloadability* via an
anonymous data-plane `GET` requesting only the first byte (`Range: bytes=0-0`).
This exercises the real download path — so an object whose bucket policy allows
anonymous `s3:GetObject` but which cannot actually be retrieved (SSE-KMS decrypt
required, or an archived/unrestored storage class) is correctly reported *not*
downloadable, rather than the false "public" a metadata-only `HEAD` would give.
A zero-byte object (which can't satisfy the range) falls back to a bounded full
`GET`. Bucket listability and object readability are separate permissions — a
private bucket can hold public objects and vice versa.

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `-inspect` | `false` | Also read AWS config (Block Public Access at bucket **and** caller-account level, bucket policy status, ACLs) to explain the result. Requires AWS credentials; intended for buckets in your account. |
| `-list-prefix` | — | For a single bucket check, test anonymous `ListBucket` scoped to this prefix (some policies grant listing only under a prefix). |
| `-scan` | `false` | Scan every object in a bucket and report which are anonymously accessible. See below. |
| `-prefix` | — | With `-scan`, only enumerate keys under this prefix. |
| `-max-objects` | `1000` | With `-scan`, stop after enumerating this many **targets** — current keys, or versions with `-include-versions` (`0` = no limit). **This is a coverage limit, not just a performance knob** — see completeness below. |
| `-max-findings` | `1000` | With `-scan`, cap the number of public/inconclusive **examples retained** in output (`0` = no cap). Counts stay exact; only the listed examples are bounded. |
| `-concurrency` | `16` | With `-scan`, number of concurrent anonymous probes (1–256). |
| `-keys-from` | — | With `-scan`, read candidate keys from a file instead of the S3 API (no AWS credentials required). |
| `-include-versions` | `false` | With `-scan` (S3 API source), enumerate **all data-bearing** object versions via `ListObjectVersions`, not just current versions. |
| `-allow-partial` | `false` | With `-scan`, exit `0` for a clean scan that did not fully cover the whole bucket (truncated/cancelled/inconclusive, or a prefix/key-file/current-only scope). Default: such scans exit `2`. |
| `-json` | `false` | Emit the result as JSON (includes `schemaVersion` and `toolVersion`). |
| `-region` | auto | Override the region instead of auto-detecting it. |
| `-request-timeout` | `15s` | Timeout for each anonymous HTTP request (AWS SDK calls are bounded by `-timeout`). |
| `-timeout` | `60s` | Overall timeout for the whole operation. **Raise this for large scans.** |
| `-fail-if-public` | `true` | Exit `1` when the target (or, in scan mode, any object) is public. Does **not** suppress the incomplete-scan exit `2`. |
| `-version` | | Print version and exit. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | not public — for a single check, a definitive `403`/`404`; for a scan, **no public object across a whole-bucket audit** |
| `1` | public (anonymously accessible) |
| `2` | inconclusive, incomplete/partial scan, usage, or runtime error |

For scans, exit `0` requires a **whole-bucket** audit (see below); a clean but
partial scan exits `2` unless `--allow-partial`.

## Scanning a bucket for public objects

A bucket that is **not** publicly *listable* can still contain individually
public *objects*. `-scan` finds them by enumerating the bucket's keys and probing
each one anonymously. *Enumeration* is streamed into a bounded worker pool, so
enumeration memory stays flat regardless of bucket size; the number of retained
public/inconclusive **findings** is bounded separately by `--max-findings`.

Because you cannot enumerate a non-listable bucket anonymously, key discovery
uses one of two sources:

- **S3 API (default)** — lists objects with your AWS credentials
  (`s3:ListBucket`). Use this to audit your own buckets.

  ```sh
  s3-access-check --scan s3://my-bucket
  s3-access-check --scan --prefix logs/ --max-objects 5000 s3://my-bucket
  ```

- **Key list (`--keys-from`)** — probes a newline-delimited file of candidate
  keys, no credentials required. Keys are used **verbatim** (only a trailing
  CR is stripped); leading slashes, spaces, and `#` are all valid key bytes and
  are preserved. Blank lines are skipped.

  ```sh
  s3-access-check --scan --keys-from keys.txt s3://my-bucket
  ```

### Scan completeness — two distinct dimensions

A scan separates *mechanical* completeness from *audit* coverage:

- **`completeWithinScope`** — every enumerated candidate was probed
  conclusively (not truncated, not cancelled, no inconclusive probe).
- **`wholeBucketComplete`** — that scope *was the entire bucket*: enumerated via
  the S3 API (not a key file), no `--prefix`, and all data-bearing versions
  covered (either `--include-versions`, or versioning is known to be off so
  current == whole).

The tool **fails closed**: exit `0` requires `wholeBucketComplete`. A scan that
is clean but only partial — a prefix, a `--keys-from` candidate list, or
current-versions-only on a versioned/unknown bucket — exits `2` unless you pass
`--allow-partial`. This prevents "I checked some things and found nothing" from
being mistaken for "the bucket has no anonymous exposure".

```
Scope:     current_versions (unit: keys)
Versioning: Enabled
Status:    complete WITHIN SCOPE, but this is NOT a whole-bucket audit
           (a clean result here does NOT certify the entire bucket)
```

### Version scope

By default a scan covers **current** object versions only (`scope:
current_versions`). In a versioning-enabled bucket, a noncurrent version can be
independently public (different ACL, or hidden behind a delete marker) — so the
default scan detects versioning (`GetBucketVersioning`) and **warns** that
noncurrent versions were not checked. If that versioning lookup *fails*, the
failure is surfaced and the scan cannot claim `wholeBucketComplete` (it will not
exit `0` without `--allow-partial`).

Pass `--include-versions` to enumerate every **data-bearing** version via
`ListObjectVersions` (`scope: all_versions`); findings then carry a `versionId`,
and delete markers are counted (`deleteMarkersObserved`) but not probed since
they have no object body.

## Supported resources

- **Supported:** general-purpose AWS S3 buckets via standard commercial
  (`*.amazonaws.com`) REST endpoints, path-style and virtual-hosted, including
  the legacy `s3-region` dash form and dualstack.
- **Not currently supported / untested:** access points, Multi-Region Access
  Points, Object Lambda, S3 Express directory buckets, transfer-acceleration and
  FIPS endpoints, the China (`amazonaws.com.cn`) partition, S3 website endpoints,
  and non-AWS S3-compatible services (MinIO, etc.).

## Least-privilege IAM

The anonymous probe needs **no** AWS permissions. The optional modes do:

Scan enumeration (`--scan` via the S3 API; add `s3:ListBucketVersions` for
`--include-versions`, and `s3:GetBucketVersioning` for the versioning warning):

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

Config inspection (`--inspect`; add `s3:GetObjectVersionAcl` when checking a
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

The `--inspect` account-level Block Public Access result is the **authenticated
caller's** account (via STS + S3 Control), not verified to be the bucket owner's
account — for a cross-account bucket it may not describe the owning account. The
result is the effective caller-account configuration and may be enforced by an
AWS Organizations S3 policy; the API does not identify the source. Both caveats
are emitted as warnings.

## How it works

1. **Region resolution** — an unauthenticated `HEAD` to the global endpoint
   reads the `x-amz-bucket-region` response header.
2. **Bucket check** — anonymous `GET /?list-type=2` (`ListBucket`), optionally
   scoped to `--list-prefix`.
3. **Object check** — anonymous ranged `GET` (`Range: bytes=0-0`), with a bounded
   full-`GET` fallback on `416` for zero-byte objects.
4. **Wrong-region handling** — a `301`/`307`/`400` that advertises the correct
   region triggers exactly one retry against it.
5. **Classification** — only `2xx` → public, `403`/`404` → not public; every
   other status → inconclusive.
6. **(Optional) `--inspect`** — reads bucket and account Block Public Access,
   bucket policy status, and operation-aware ACL grants.
7. **(Optional) `--scan`** — streams enumeration into concurrent anonymous
   probes and tracks completeness.

## Notes and limitations

- Results reflect live state at the moment you run it, not stored config.
- Bucket names and object keys can reveal business information — be careful when
  writing output to shared CI logs.
- ACL evaluation is operation-aware: an `AllUsers` grant of `READ_ACP`/`WRITE_ACP`
  is reported but does **not** count as anonymous read; `AuthenticatedUsers`
  grants (any AWS account, not anonymous) are reported separately.
