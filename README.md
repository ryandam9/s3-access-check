# s3-access-check

A small Go CLI that reports whether an Amazon S3 **bucket** or **object** is
**anonymously (publicly) accessible**.

Its primary check is a black-box, unauthenticated probe: it makes a request with
no credentials and reads the result. This reflects the resource's real,
effective access state — the same thing an anonymous visitor on the internet
would experience — regardless of *how* that access was configured (bucket
policy, ACL, or Block Public Access). With `--inspect` it can additionally read
the AWS configuration to explain *why*.

> **Use responsibly.** Only run this against buckets and objects you own or are
> explicitly authorized to test. Pointed at arbitrary buckets, an access probe
> is reconnaissance.

## Install / build

```sh
go build -o s3-access-check .
```

Requires Go 1.24+.

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

If the target has no key, the **bucket** is checked for public *listability*.
If it has a key, that **object** is checked for public *readability*. These are
separate permissions — a private bucket can hold public objects and vice versa.

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `-inspect` | `false` | Also read AWS config (Block Public Access, bucket policy status, ACLs) to explain the result. Requires AWS credentials and read permissions; only works on buckets in your account. |
| `-json` | `false` | Emit the result as JSON. |
| `-region` | auto | Override the region instead of auto-detecting it. |
| `-timeout` | `15s` | Overall network timeout. |
| `-fail-if-public` | `true` | Exit `1` when the target is public. Set `-fail-if-public=false` to always exit `0` on success. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Not public |
| `1` | Public (anonymously accessible) |
| `2` | Usage or runtime error |

This makes the tool easy to gate on in CI or scripts.

## Examples

```sh
# Is this bucket publicly listable?
s3-access-check s3://my-bucket

# Is this specific object publicly readable?
s3-access-check https://my-bucket.s3.amazonaws.com/reports/2026.pdf

# Machine-readable output
s3-access-check --json s3://my-bucket

# Explain why (needs AWS credentials)
s3-access-check --inspect s3://my-bucket
```

## How it works

1. **Region resolution** — an unauthenticated `HEAD` to the global endpoint
   reads the `x-amz-bucket-region` response header (returned even on 3xx/403).
2. **Bucket check** — an anonymous `GET /?list-type=2` (`ListBucket`).
   `200` = publicly listable; `403 AccessDenied` = not; `404 NoSuchBucket` =
   missing.
3. **Object check** — an anonymous `GET` with `Range: bytes=0-0` (`GetObject`),
   so a public object is confirmed by a `200`/`206` without downloading it in
   full; `403` = private; `404` = missing.
4. **(Optional) `--inspect`** — uses the AWS SDK to read
   `GetPublicAccessBlock`, `GetBucketPolicyStatus`, and the bucket/object ACL,
   reporting each best-effort (a missing permission is noted, not fatal).

## Caveats

- The anonymous check is the ground truth for *effective* access, but it tests
  one operation at a time (list vs. read). Checking a bucket does not check
  every object inside it.
- Results reflect live state at the moment you run it, not stored config.
- Requires outbound HTTPS to the S3 endpoints.
