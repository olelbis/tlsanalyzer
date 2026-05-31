# Feedback and Compatibility Reports

`tlsanalyzer` is in beta-readiness review. The most useful external feedback is
real-world evidence from endpoints, CI runs and package installations that the
maintainers cannot reproduce locally.

## What To Report

Please open an issue when you see:

- TLS version support that differs from another trusted scanner.
- TLS 1.3 raw-probe evidence that is inconclusive, unstable or hard to interpret.
- Certificate validation, public key, signature or expiry details that look wrong.
- Policy checks that fail or pass unexpectedly.
- JSON, SARIF, JUnit or Markdown output that is hard to consume in automation.
- Release binary, Linux package, container image or attestation verification
  problems.

## Useful Commands

For endpoint compatibility reports:

```bash
tlsanalyzer --host example.com --sni example.com --json
tlsanalyzer --host example.com --sni example.com --markdown tlsanalyzer-report.md
tlsanalyzer --host example.com --sni example.com --policy modern
```

For TLS 1.3 raw-probe evidence, enable full cipher probing:

```bash
tlsanalyzer --host example.com --sni example.com --force-cipher-check --json
```

For installation and release verification reports:

```bash
tlsanalyzer --version
gh attestation verify tlsanalyzer-linux-amd64 --repo olelbis/tlsanalyzer
```

## What To Include

Include as much of this information as possible:

- `tlsanalyzer --version` output.
- Host, port and SNI used for the scan.
- Whether the endpoint is public or private.
- Exact command line.
- Console, JSON or Markdown output excerpt.
- Operating system, architecture and installation method.
- Comparison output from OpenSSL, a browser or another TLS scanner when available.

Redact private hostnames, IP addresses, certificate subjects or SANs if needed.
For JSON reports, try to preserve field names and status values even when values
are redacted.

## Expected Drift

Public TLS endpoints can change certificates, CDN routing, TLS policy, ALPN
behavior and cipher preferences without notice. A compatibility report does not
need to prove that `tlsanalyzer` is wrong; a clear reproducible difference is
enough to start investigation.

The documented compatibility contracts are in the
[compatibility policy](compatibility-policy.md) and [JSON schema v1](json-schema-v1.md).
