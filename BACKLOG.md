# Backlog

This backlog is ordered by implementation priority. The goal is to keep `tlsanalyzer` small and dependency-free while improving correctness, testability and release quality.

## Current Focus - v0.29.x Beta-Readiness Review

The feature backlog from P1 through P29 is complete. The `v0.29.x` line is now focused on beta-readiness review: bug fixes, documentation updates, compatibility-preserving hardening and final contract audits before a future beta/v1 decision.

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

## P14 - Product Polish - Done

### Improve day-to-day CLI ergonomics

Problem: the scanner is usable, but common CLI polish is still missing.

Status: done.

Acceptance criteria:

- Add `--version`.
- Add a quiet or compact output mode.
- Document exit codes more prominently.
- Consider output format controls for table or compact console output.

## P15 - Policy Depth - Done

### Add richer configurable policy checks

Problem: the current policy mode is useful for basic CI gates, but mature environments often need more granular posture requirements.

Status: done.

Acceptance criteria:

- Add policy checks for minimum certificate public key size.
- Add policy checks for required or forbidden TLS versions, including requiring TLS 1.3 when requested.
- Add policy checks for allowed or forbidden ALPN protocols.
- Add configurable certificate expiry thresholds.
- Keep defaults conservative and avoid surprising users who only enable `--policy modern`.

## P16 - Installation Channels - Done

### Expand distribution beyond GitHub release assets

Problem: release binaries and Linux packages are available, but users still need to manually download assets from GitHub.

Status: done for container publishing and documented package-manager evaluation.

Acceptance criteria:

- Evaluate and document a Homebrew tap for macOS and Linux users.
- Evaluate Scoop or WinGet distribution for Windows users.
- Evaluate publishing a container image for CI usage.
- Keep release provenance, checksums and SBOM expectations consistent across channels.

## P17 - Raw Probe Library Extraction - Done

### Prepare the TLS 1.3 raw probe for reuse

Problem: the raw TLS 1.3 probe is useful inside `tlsanalyzer`, but it may become valuable as a standalone library.

Status: done, kept internal while the API matures.

Acceptance criteria:

- Define a small public API for the raw probe package.
- Separate reusable protocol logic from CLI/reporting assumptions.
- Add package-level documentation and examples.
- Decide whether to keep it internal or publish it as a separate Go module.

## P18 - CLI Runner Refactor - Done

### Separate orchestration from CLI parsing

Problem: `tlsanalyzer.go` currently owns CLI parsing, validation, scan orchestration, policy evaluation, output rendering and exit code mapping, which makes the main flow harder to test and extend.

Status: done.

Acceptance criteria:

- Introduce a small runner layer that accepts validated options and returns structured execution results.
- Keep `main` focused on argument parsing, I/O wiring and process exit codes.
- Preserve existing CLI behavior, output and exit codes.
- Add tests for runner behavior without relying only on full CLI invocations.
- Keep the refactor mechanical and dependency-free.

## P19 - Config File and Profiles - Done

### Support repeatable scan configuration

Problem: repeated scans currently require long CLI invocations, which is awkward for teams and CI templates.

Status: done.

Acceptance criteria:

- Add a JSON config file for common scan options using only the Go standard library.
- Support named policy profiles.
- Support reusable target definitions.
- Keep CLI flags able to override config file values explicitly.
- Document the config schema and include a minimal example.
- Do not introduce YAML, TOML or third-party config dependencies.

## P20 - Report Formats - Done

### Add integrations for downstream tools

Problem: Markdown and JSON cover humans and scripts, but CI/security platforms often consume specialized formats.

Status: done for SARIF and JUnit XML; self-contained HTML remains deferred.

Acceptance criteria:

- Add SARIF output for security dashboards.
- Add JUnit-style output for CI test reports.
- Defer a self-contained HTML report until there is a clearer use case.
- Keep JSON as the canonical machine-readable contract.

## P21 - Operational Hardening - Done

### Improve CI and batch-scan reliability

Problem: `tlsanalyzer` is useful for one target at a time, but operational use often needs predictable behavior across many endpoints and occasionally unreliable networks.

Status: done.

Acceptance criteria:

- Add support for scanning multiple targets from a JSON file.
- Add bounded parallel scanning with a configurable concurrency limit.
- Add retry/backoff controls for transient network failures.
- Preserve per-target exit evidence in JSON, SARIF and JUnit reports.
- Keep terminal output readable for both single-target and batch modes.
- Document operational limits, timeout behavior and recommended CI defaults.

## P22 - Public Raw Probe Library - Done

### Extract the TLS 1.3 raw probe when the API is stable

Problem: the raw TLS 1.3 probe has standalone value, but publishing it too early would freeze an API that is still maturing inside `tlsanalyzer`.

Status: done as a preview public package in this module.

Acceptance criteria:

- Move `internal/tlsprobe` to the public `tlsprobe` package.
- Keep the package in this module for the first public preview; defer a separate module until the API has user feedback.
- Add typed `ConfigError` values for invalid probe options.
- Add offline examples and package documentation suitable for `go doc`.
- Add fixture coverage for rejected ServerHello, malformed handshakes, malformed HelloRetryRequest data, unexpected record types, closed connections and timeout classification.
- Document preview compatibility expectations, status semantics and current limits.

## P23 - Public Analyzer API - Done

### Make the scan orchestration package usable by Go callers

Problem: the scan orchestration was extracted into `analyzer`, but library callers still needed clearer defaults, examples and error semantics.

Status: done.

Acceptance criteria:

- Add CLI-like default options for package callers.
- Document the analyzer API in Go package docs, README and user manual.
- Return typed hook errors while keeping operational target failures as structured scan results.
- Add examples suitable for `go doc`.
- Add tests for defaults and hook error wrapping.

## P24 - Beta and Library Readiness Audit - Done

### Freeze feature growth before public raw-probe extraction

Problem: the project is feature-complete for preview use, but the next major step exposes library API that should not be published without a compatibility review.

Status: done.

Acceptance criteria:

- Audit CLI, reporting, policy, release and raw-probe-library readiness.
- Document the P22 blockers before exposing the raw probe publicly.
- Tighten raw-probe option validation for malformed TCP addresses and invalid timeouts.
- Add tests for the tightened raw-probe validation.
- Make release creation idempotent if duplicate tag-release runs start for the same version.
- Link the audit from the README.

## P25 - TLS 1.3 Raw Probe Evidence Hardening - Done

### Harden parser and report evidence

Problem: the public raw TLS 1.3 probe was useful, but its evidence could be clearer and the parser needed stronger fixture coverage before any future standalone-library decision.

Status: done.

Acceptance criteria:

- Reassemble fragmented TLS handshake records before classifying ServerHello evidence.
- Add configurable key share groups while keeping conservative defaults.
- Expose selected key share group, HelloRetryRequest retry status, raw alert codes and evidence level in probe results.
- Carry the new evidence into JSON, Markdown and console summaries without claiming full-handshake completion.
- Cover the new behavior with offline tests.

## P26 - Console Output Clarity - Done

### Clarify negotiated and probed cipher evidence

Problem: verbose console output printed the negotiated cipher suite once in the certificate summary and again as a negotiated cipher list, which made a single selected handshake cipher look like an exhaustive support list.

Status: done.

Acceptance criteria:

- Print the negotiated cipher suite once and label it as selected in the current handshake.
- Suppress duplicate negotiated cipher lists in verbose output.
- Label probed, observed and raw-probed cipher lists with evidence-specific wording.
- Preserve TLS 1.3 raw-probe wording as ClientHello-only support evidence.
- Cover the console wording with focused tests.

## P27 - Hardening, Examples and Real-world Validation - Done

### Raise preview confidence without adding large features

Problem: the CLI is feature-complete for preview use, but maintainers and users need clearer examples, repeatable manual validation and a small amount of extra config hardening before relying on release evidence.

Status: done.

Acceptance criteria:

- Add curated output examples for console, JSON, Markdown and CI report formats.
- Add a real-world validation matrix that documents expected drift for public TLS endpoints.
- Add a manual validation script that exercises version output, TLS 1.3 handshakes, TLS 1.3 raw probes, JSON shape, Markdown output, policy output and invalid-certificate evidence.
- Harden config parsing tests for nested unknown fields and multiple JSON objects.
- Link the new validation and example documentation from the README and GitHub Pages docs.

## P28 - Preview Stabilization Contracts - Done

### Make compatibility promises explicit and testable

Problem: the project had stable behavior in practice, but automation users needed a clearer compatibility policy before relying on CLI exit codes, JSON schema v1, policy semantics and TLS 1.3 evidence labels.

Status: done.

Acceptance criteria:

- Add a dedicated compatibility policy document.
- Link compatibility guidance from the README, user manual and GitHub Pages docs.
- Replace raw exit-code numbers in the CLI flow with named constants.
- Add tests that lock the documented exit-code contract.
- Move project status to the `v0.28.x` preview stabilization line.

## P29 - Beta-Readiness Audit - Done

### Audit public contracts before beta

Problem: after stabilizing preview contracts, the project needed one more pass over documentation, JSON policy semantics, validation confidence and public package documentation before a future beta decision.

Status: done.

Acceptance criteria:

- Verify CLI/docs/man page alignment for public flags and exit codes.
- Clarify JSON policy output for all enabled policy gates.
- Document JSON policy failure object fields.
- Add an explicit P29 audit document.
- Fix discovered CLI documentation drift.
- Tighten real-world validation to assert the exact scanner version.
- Add missing package docs for public Go packages used by consumers.
- Move project status to the `v0.29.x` beta-readiness review line.
