# Security Policy

## Supported versions

This project is pre-1.0. Security fixes are applied to the latest `main` and the
most recent tagged release only.

## Reporting a vulnerability

Please report suspected vulnerabilities privately using GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
("Report a vulnerability" under the repository's **Security** tab) rather than
opening a public issue.

Please include:

- a description of the issue and its impact,
- steps to reproduce, and
- affected version or commit.

## Scope and responsible use

`s3-access-check` makes real, unauthenticated requests to S3 endpoints. Only run
it against buckets and objects you own or are explicitly authorized to test.
Using it to probe third-party resources may constitute unauthorized
reconnaissance.
