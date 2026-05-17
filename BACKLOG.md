# Backlog

This backlog is ordered by implementation priority. The goal is to keep `tlsanalyzer` small and dependency-free while improving correctness, testability and release quality.

## P1 - Correctness and Trust - Done

### Separate TLS support from certificate validation

Problem: a certificate validation failure currently looks like an unsupported TLS version.

Status: done.

Acceptance criteria:

- Report protocol support separately from certificate trust status.
- Preserve certificate validation by default.
- Add an explicit option for insecure scanning, such as `--skip-verify`, with clear output when it is used.
- Markdown output includes certificate validation status and TLS handshake status.

### Validate CLI input before scanning

Problem: invalid runtime values can produce confusing network behavior.

Status: done.

Acceptance criteria:

- Reject `--timeout` values lower than 1.
- Validate `--port` as a numeric TCP port in range `1..65535`.
- Trim and validate `--host` once, then pass the normalized value through the whole scan.
- Return clear non-zero exit codes for invalid CLI input.

### Rename TLS 1.3 cipher output to observed ciphers

Problem: Go cannot force individual TLS 1.3 cipher suites through `tls.Config.CipherSuites`, so "supported cipher suites" can overstate certainty.

Status: done.

Acceptance criteria:

- Console output says "Observed cipher suites" for TLS 1.3.
- Markdown output uses the same wording.
- README and changelog remain consistent with the behavior.

## P2 - Architecture and Testability - Done

### Introduce scan options and structured results

Problem: scan code reads global flags and prints directly, which makes it harder to test and reuse.

Status: done.

Acceptance criteria:

- Add a `scan.Options` struct for host, port, timeout, minimum TLS version, force-cipher behavior and certificate verification behavior.
- Move all user-facing printing out of the `scan` package.
- Return structured errors or statuses for unsupported protocol, network error, timeout and certificate validation failure.

### Return errors from certificate output helpers

Problem: `certs.SaveOrPrintCertToFile` exits the process directly.

Status: done.

Acceptance criteria:

- Certificate helpers return errors instead of calling `os.Exit`.
- `main` owns all process exit behavior.
- Existing console behavior remains unchanged for successful runs.

### Add local TLS integration tests

Problem: unit tests cover pure helpers, but not real TLS handshake behavior.

Status: done.

Acceptance criteria:

- Add tests using local TLS servers from the Go standard library.
- Cover at least TLS 1.2 support, TLS 1.3 support, invalid certificate behavior and timeout/error reporting.
- Tests do not require internet access.

## P3 - CLI and Reporting - Done

### Add machine-readable output

Problem: current output is optimized for humans, not automation.

Status: done.

Acceptance criteria:

- Add `--json` output.
- JSON includes host, port, TLS versions, cipher suites, certificate details, validation status and scan errors.
- JSON output is stable enough for scripts.

### Add a no-clear option

Problem: clearing the terminal is awkward in CI, logs and copy/paste workflows.

Status: done.

Acceptance criteria:

- Add `--no-clear`.
- Default behavior can remain unchanged.
- README documents the flag.

### Improve Markdown reports

Problem: the report only includes certificate details from the first supported TLS result.

Status: done.

Acceptance criteria:

- Include certificate details per supported TLS version when they differ.
- Avoid duplicating identical certificates unnecessarily.
- Add generation timestamp and scanner version.

## P4 - Release and Documentation - Done

### Add CI for tests and vetting

Problem: the current workflow only runs on release tags and focuses on builds.

Status: done.

Acceptance criteria:

- Add a CI workflow for pushes and pull requests.
- Run `go test ./...`, `go test -race ./...` and `go vet ./...`.
- Keep the release workflow focused on tagged releases.

### Move generated sample report into docs

Problem: `example.com.md` looks like generated output at the repository root.

Status: done.

Acceptance criteria:

- Move it to `docs/example-report.md`.
- Regenerate or update it after report format changes.
- Link it from the README.

### Generate release notes from the changelog

Problem: release notes are duplicated in the workflow body and `CHANGELOG.md`.

Status: done.

Acceptance criteria:

- Use the relevant changelog section as the GitHub release body.
- Avoid hard-coded historical release notes in the workflow.
- Document the release checklist in the README or a dedicated release document.

## P5 - Reliability and Product Maturity - Done

### Version the JSON schema

Problem: `--json` is useful for automation, but consumers need a stable contract.

Status: done.

Acceptance criteria:

- Add a `schema_version` field to JSON output.
- Document the JSON fields and compatibility expectations.
- Add tests that lock representative JSON output shape.

### Improve scan semantics and metadata

Problem: supported, observed and inferred scan data are not always explicit enough for audit-style usage.

Status: done.

Acceptance criteria:

- Distinguish negotiated, probed and observed cipher data in structured output.
- Include scan duration and handshake attempt metadata where useful.
- Preserve clear warnings for TLS 1.3 cipher observations and Go runtime limitations.

### Improve Markdown report readability

Problem: Markdown reports are correct, but still read like raw scan output.

Status: done.

Acceptance criteria:

- Add a concise summary section with protocol, certificate and cipher findings.
- Use tables for TLS versions and cipher suites.
- Keep detailed certificate data available without duplicating identical certificates.

### Add policy/fail mode for CI

Problem: CI users need a simple way to fail builds on weak TLS posture.

Status: done.

Acceptance criteria:

- Add policy options such as `--policy modern` or targeted `--fail-on` controls.
- Return a non-zero exit code when policy checks fail.
- Report policy failures in human, Markdown and JSON output.

## P6 - Evidence and Policy Hardening - Done

### Harden certificate policy checks

Problem: policy checks should not pass when certificate validation is skipped or unavailable.

Status: done.

Acceptance criteria:

- `invalid-cert` fails on invalid, skipped and unavailable certificate validation.
- `--policy modern` cannot silently pass certificate posture when `--skip-verify` is used.
- Tests cover skipped and unavailable validation in policy mode.

### Make cipher summaries evidence-aware

Problem: "no weak cipher suites detected" can overstate certainty when only negotiated cipher evidence exists.

Status: done.

Acceptance criteria:

- Human and Markdown summaries include the cipher evidence mode.
- Negotiated, probed, observed and mixed evidence are distinguished.
- Tests cover the summary wording.

### Make report certificate expiry deterministic

Problem: generated reports calculate days until expiry with wall-clock time during rendering.

Status: done.

Acceptance criteria:

- Markdown and JSON reports calculate days until expiry relative to the report generation timestamp.
- Tests cover deterministic JSON certificate expiry.

### Split cipher severity from display labels

Problem: policy decisions should not depend on emoji or human-readable classification strings.

Status: done.

Acceptance criteria:

- Cipher suites have typed severities.
- Policy checks use typed severities.
- Output can still use friendly display labels.

### Add explicit SNI support

Problem: scanning IPs, load balancers and internal endpoints often requires a TLS server name different from the TCP address.

Status: done.

Acceptance criteria:

- Add `--sni` for TLS Server Name Indication and certificate validation name.
- Validate `--sni` before scanning.
- Document the flag and add tests.

## P7 - Pre-Beta Contract Tightening - Done

### Include SNI in reports

Problem: reports should preserve the TLS server name used for SNI and certificate validation.

Status: done.

Acceptance criteria:

- JSON includes `server_name` when `--sni` is used.
- Markdown reports include the server name when `--sni` is used.
- Tests cover SNI report metadata.

### Test SNI with a real local TLS handshake

Problem: SNI support should be covered beyond CLI parsing and helper fallback behavior.

Status: done.

Acceptance criteria:

- Add a local TLS test that requires the expected SNI value.
- Keep the test offline and standard-library only.

### Treat unknown cipher suites as policy evidence

Problem: unclassified cipher suites should not silently pass modern weak-cipher checks.

Status: done.

Acceptance criteria:

- Weak-cipher policy checks fail on unclassified cipher suites.
- Human summaries report unknown cipher evidence explicitly.
- Tests cover policy and summary behavior.

### Document JSON schema v1

Problem: JSON consumers need a field-level contract beyond prose in the manual.

Status: done.

Acceptance criteria:

- Add a dedicated JSON schema v1 document.
- Link it from the README and user manual.

## P8 - Preview Readiness - Done

### Clean up source comments

Problem: low-value file header comments add noise while a few subtle semantics need focused comments.

Status: done.

Acceptance criteria:

- Remove redundant `// File:` comments.
- Keep comments in English.
- Add focused comments for TLS 1.3 cipher observation and cipher severity policy semantics.

### Publish preview stability guarantees

Problem: users need to know what is stable before treating the project as a preview release.

Status: done.

Acceptance criteria:

- Update README status from experimental to preview.
- Document JSON compatibility expectations.
- Document TLS 1.3 cipher observation and conservative policy behavior.

## P9 - TLS 1.3 Raw Probe Library - Done

### Design an internal TLS 1.3 probe package

Problem: Go's `crypto/tls` package does not allow callers to force individual TLS 1.3 cipher suites, so the current scanner can only report TLS 1.3 ciphers as observed handshake evidence.

Status: done for MVP.

Acceptance criteria:

- Add an internal package, such as `internal/tlsprobe`, with a small public surface inside the repository.
- Keep the implementation focused on handshake probing, not on building a full TLS stack.
- Define structured probe statuses such as supported, rejected, hello-retry-request, alert, timeout and inconclusive.
- Keep the API independent enough that it can later move to a standalone Go module.

### Implement minimal raw ClientHello probing for TLS 1.3

Problem: TLS 1.3 cipher support should be probed directly by offering one cipher suite at a time instead of relying only on normal negotiated handshakes.

Status: done for MVP.

Acceptance criteria:

- Build and send a minimal TLS 1.3 `ClientHello` over a raw TCP connection.
- Support SNI and optional ALPN in the probe input.
- Offer one TLS 1.3 cipher suite per probe attempt.
- Parse `ServerHello`, TLS alerts, connection close and timeout outcomes.
- Recognize `HelloRetryRequest` explicitly, even if it is initially reported as inconclusive.
- Cover the implementation with offline tests using local TCP/TLS test servers or recorded handshake fixtures.

### Integrate TLS 1.3 probe evidence into reports

Problem: once direct TLS 1.3 probing exists, reports should distinguish raw-probed cipher support from observed handshake evidence.

Status: done for MVP.

Acceptance criteria:

- Add JSON fields for TLS 1.3 raw probe method, per-cipher result and probe errors.
- Keep schema compatibility by adding optional fields under the existing JSON schema version rules, or bump the schema version if fields need to be renamed.
- Update console and Markdown output to label TLS 1.3 cipher evidence as raw-probed when available.
- Keep the existing observed-cipher fallback when raw probing is disabled or inconclusive.

## P10 - Raw Probe Hardening - Done

### Retry TLS 1.3 HelloRetryRequest

Problem: the raw probe recognizes `HelloRetryRequest`, but the MVP does not retry with the requested key share.

Status: done.

Acceptance criteria:

- Parse the selected group from a TLS 1.3 `HelloRetryRequest`.
- Retry the probe on the same connection with a matching key share when the requested group is supported.
- Preserve `hello-retry-request` as the result status when the requested group cannot be retried.
- Cover the retry path with a local TLS test.

### Add raw parser fixtures

Problem: raw TLS parser behavior should be locked with deterministic fixtures, not only live local TLS servers.

Status: done.

Acceptance criteria:

- Add fixture-style tests for supported `ServerHello` parsing.
- Add fixture-style tests for `HelloRetryRequest` parsing.
- Add fixture-style tests for TLS alert parsing.
- Keep parser errors stable enough for tests and JSON consumers.

### Reduce raw probe test noise

Problem: local TLS probe tests can print expected handshake errors when the raw probe stops after `ServerHello`.

Status: done.

Acceptance criteria:

- Silence expected local TLS server handshake logs in tests.
- Keep unexpected test failures visible through assertions.

## P11 - Report Quality - Done

### Clarify supported TLS version counts

Problem: `Supported TLS versions: 1` can be ambiguous when the scan intentionally tests only one TLS version.

Status: done.

Acceptance criteria:

- Console summaries show both supported and tested TLS version counts.
- Markdown summaries use the same supported/tested wording.
- Tests cover the summary wording.

### Make raw probe evidence easier to read

Problem: raw probe details are available in JSON, but human reports do not summarize per-cipher probe status clearly.

Status: done.

Acceptance criteria:

- Add a Markdown table for `cipher_probe_results`.
- Add a concise console summary such as `raw probe: 3/3 supported`.
- Document that raw probes do not complete full TLS handshakes.
- Consider a JSON field that explicitly states whether the raw probe completed a full handshake.

## P12 - Security Depth - Done

### Expand TLS posture evidence

Problem: protocol and cipher evidence are useful, but deeper TLS posture depends on groups, signatures and application negotiation.

Status: done.

Acceptance criteria:

- Report supported or negotiated key exchange groups where feasible.
- Summarize certificate key type and signature algorithm.
- Capture ALPN negotiation evidence.
- Keep non-TLS HTTP checks out of scope unless explicitly promoted later.

## P13 - Supply Chain and Release Trust - Done

### Strengthen release artifacts

Problem: release binaries are built automatically, but consumers need stronger artifact integrity signals and Linux users should be able to install packaged builds cleanly.

Status: done.

Acceptance criteria:

- Publish checksum files with releases.
- Publish Linux `.deb` and `.rpm` packages for `amd64` and `arm64`.
- Include a man page in Linux packages.
- Publish an SPDX SBOM with releases.
- Publish GitHub artifact attestations for release assets.
- Document release verification steps.

## P14 - Product Polish - Planned

### Improve day-to-day CLI ergonomics

Problem: the scanner is usable, but common CLI polish is still missing.

Status: planned.

Acceptance criteria:

- Add `--version`.
- Add a quiet or compact output mode.
- Document exit codes more prominently.
- Consider output format controls for table or compact console output.
