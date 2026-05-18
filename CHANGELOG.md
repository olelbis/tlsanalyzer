# Changelog

All notable changes to `tlsanalyzer` are documented here.

## v0.23.1 - 2026-05-19

### Fixed

- Made release creation idempotent when GitHub starts duplicate tag-release runs for the same version.

## v0.23.0 - 2026-05-19

### Added

- Added a P24 readiness audit for beta/v1 planning and future raw-probe-library extraction.
- Linked the readiness audit from the README documentation section.

### Changed

- Tightened raw TLS 1.3 probe option validation for malformed `host:port` addresses, invalid TCP ports, address whitespace and negative timeouts.
- Marked P24 complete in the backlog with the remaining P22 library extraction blockers documented.

### Tests

- Added raw-probe validation tests for malformed addresses and pre-dial configuration errors.

## v0.22.0 - 2026-05-18

### Added

- Added `analyzer.DefaultOptions` and documented analyzer defaults for library callers.
- Added `analyzer.HookError` with unwrap support so callers can distinguish hook failures from operational scan evidence.
- Added analyzer package examples for Go documentation.
- Documented package usage in the README and user manual.

### Tests

- Added coverage for analyzer defaults and hook error wrapping.

## v0.21.0 - 2026-05-18

### Changed

- Extracted scan orchestration and policy evaluation into the new `analyzer` package as the first public core boundary toward a future library API.
- Centralized scan execution and transient-status predicates in the `scan` package to avoid duplicated status logic across CLI and reports.
- Split JSON report generation into a dedicated output file while preserving the existing report API and JSON schema.
- Hardened SARIF target URIs with URL path escaping and refreshed SARIF comments to include scan execution findings.

### Tests

- Added analyzer and scan status predicate coverage, then reran the full test suite and vet checks.

## v0.20.1 - 2026-05-18

### Fixed

- Return exit code `1` when a target cannot be scanned because all attempted TLS versions end in scan execution errors.
- Reject unknown fields in batch target files so typos such as `server_name` do not silently drop SNI settings.
- Limit batch concurrency to a documented maximum of 64 workers.
- Include scan execution errors such as `network_error`, `timeout` and `handshake_error` in SARIF output.
- Document the batch JSON shape alongside the single-target JSON contract.

### Tests

- Added coverage for unreachable single-target and batch runs, strict batch target parsing, excessive concurrency rejection and SARIF scan-error output.

## v0.20.0 - 2026-05-18

### Added

- Added `--targets-file` for dependency-free JSON batch scans.
- Added `--concurrency`, `--retries` and `--retry-backoff` to control batch parallelism and transient network retries.
- Added aggregate batch JSON output with embedded per-target scan reports.
- Added batch SARIF and JUnit XML report generation for CI/security workflows.

### Changed

- Documented batch target files, retry behavior and batch report limitations in the README, user manual and man page.
- Marked operational hardening work complete in the backlog.

### Tests

- Added tests for batch JSON output, target-file normalization, default batch SNI, config-driven batch settings and retryable scan detection.

## v0.19.0 - 2026-05-18

### Added

- Added `--sarif` to write SARIF v2.1.0 policy finding reports for security dashboards.
- Added `--junit` to write JUnit XML scan and policy reports for CI systems.
- Added JSON config support for SARIF and JUnit report paths.

### Changed

- Marked report-format work complete for SARIF and JUnit XML while deferring self-contained HTML reports.
- Updated README, user manual and man page examples for CI report output.

### Tests

- Added tests for SARIF report generation, empty SARIF output, JUnit scan errors and policy failures, and CLI report flags.

## v0.18.0 - 2026-05-18

### Added

- Added `--config` for dependency-free JSON configuration files.
- Added `--target` for selecting reusable targets from a JSON config file.
- Added `--profile` for selecting reusable policy profiles from a JSON config file.

### Changed

- Refactored scan orchestration into a small runner layer so CLI parsing and scan execution are easier to test independently.
- Updated container documentation examples to the current release tag.

### Tests

- Added coverage for JSON config loading, CLI override behavior and runner execution against a local TLS server.

## v0.17.0 - 2026-05-18

### Added

- Added package-level documentation and examples for the internal TLS 1.3 raw probe package.
- Added explicit TLS probe option validation and a reusable supported TLS 1.3 cipher suite list.

### Changed

- Kept the raw TLS 1.3 probe internal while tightening its small exported API for future extraction.
- Updated the scanner integration to use the probe package's supported cipher list directly.

## v0.16.0 - 2026-05-18

### Added

- Added a minimal runtime container image build for `linux/amd64` and `linux/arm64`.
- Added GitHub Container Registry publishing on release tags with version, semver and `latest` tags.
- Added container SBOM and provenance attestations through the release workflow.
- Documented container usage and installation channel evaluation.

## v0.15.1 - 2026-05-18

### Fixed

- Updated the release attestation action to a Node 24-compatible version to remove GitHub Actions deprecation warnings.

## v0.15.0 - 2026-05-18

### Added

- Added configurable policy gates for required and forbidden TLS versions, required and forbidden ALPN protocols, minimum certificate public key size and minimum certificate validity days.
- Documented the expanded policy controls in the README, user manual and man page.

## v0.14.1 - 2026-05-18

### Changed

- Refined README badges to highlight verifiable releases, Linux packages, SBOMs and checksums.

## v0.14.0 - 2026-05-18

### Added

- Added `--version` for quick version checks.
- Added `--compact` for concise human-readable console output.
- Documented exit codes more explicitly in README, user manual and man page.
- Added future roadmap items for policy depth, installation channels, raw probe extraction, additional report formats and config profiles.

## v0.13.0 - 2026-05-18

### Added

- Added SHA256 checksums for release assets.
- Added Linux `.deb` and `.rpm` packages for `amd64` and `arm64`.
- Added a `tlsanalyzer(1)` man page to Linux packages.
- Added an SPDX SBOM release asset.
- Added GitHub artifact attestations for release assets.

## v0.12.0 - 2026-05-17

### Added

- Added negotiated key exchange group evidence to console, Markdown and JSON output.
- Added ALPN negotiation evidence to console, Markdown and JSON output.
- Added certificate public key and signature algorithm metadata to console, Markdown and JSON output.

## v0.11.0 - 2026-05-17

### Added

- Added Markdown tables for per-cipher raw probe results.
- Added a concise console summary for TLS 1.3 raw probe support counts.
- Added optional JSON `raw_probe_completed_full_handshake` metadata for raw-probed results.

### Changed

- Documented raw probe evidence more clearly as ClientHello-only and not a full TLS handshake.

## v0.10.2 - 2026-05-17

### Changed

- Clarified supported TLS version summaries to show supported and tested counts.

## v0.10.1 - 2026-05-17

### Changed

- Made the TLS 1.3 raw probe retry `HelloRetryRequest` with the requested key share when supported.
- Stabilized raw probe network error messages.
- Reduced expected local TLS probe noise in tests.

### Tests

- Added fixture-style tests for `ServerHello`, `HelloRetryRequest` and TLS alert parsing.

## v0.10.0 - 2026-05-17

### Added

- Added an internal TLS 1.3 raw ClientHello probe for per-cipher support checks.
- Added JSON `cipher_probe_results` details for raw probe statuses.

### Changed

- Bumped the JSON schema version to `1.1` for the new TLS 1.3 raw probe evidence value.
- TLS 1.3 cipher probing now reports `raw-probed` evidence when ServerHello confirms support.
- TLS 1.3 probing falls back to observed handshakes when raw probing is inconclusive.

## v0.9.3 - 2026-05-17

### Changed

- Made cipher severity and Markdown cipher labels account for the negotiated TLS version.
- Added protocol findings to console and Markdown summaries.
- Improved console spacing before supported TLS version results.

## v0.9.2 - 2026-05-17

### Added

- Added a pixel art project logo to the README.

## v0.9.1 - 2026-05-17

### Added

- Added backlog items for a future internal TLS 1.3 raw probe library.

## v0.9.0 - 2026-05-17

### Changed

- Updated project status from experimental to preview.
- Documented stability guarantees for JSON output, TLS 1.3 cipher evidence, policy behavior and runtime dependencies.
- Cleaned up low-value source and workflow comments.
- Added focused source comments for TLS 1.3 cipher observation and cipher severity policy semantics.

## v0.8.13 - 2026-05-17

### Added

- Added `server_name` to JSON output when `--sni` is used.
- Added SNI details to Markdown reports when `--sni` is used.
- Added JSON schema v1 documentation.
- Added a local TLS test that verifies SNI is sent during the handshake.

### Changed

- Made weak-cipher policy checks fail on unclassified cipher suites.
- Made scan summaries report unknown cipher evidence explicitly.

## v0.8.12 - 2026-05-17

### Added

- Added `--sni` to scan an address while using a separate TLS Server Name Indication and certificate validation name.
- Added typed cipher severity metadata for policy decisions.

### Changed

- Made policy certificate checks fail when certificate validation is skipped or unavailable.
- Made cipher summaries state the evidence mode used for the finding.
- Made Markdown and JSON certificate expiry days relative to the report generation timestamp.

## v0.8.11 - 2026-05-17

### Added

- Added a stable JSON golden test for the machine-readable report contract.
- Added a human-readable scan summary to console output.
- Added a release alignment check script and scheduled GitHub Actions workflow.

## v0.8.10 - 2026-05-17

### Changed

- Changed default scans to report only the negotiated cipher suite unless cipher probing is requested.
- Made `--force-ciphers` the explicit switch for full TLS 1.0, 1.1 and 1.2 cipher probing and TLS 1.3 cipher observation.
- Made weak-cipher policy checks automatically enable cipher probing to avoid false policy passes.
- Documented policy exit behavior and cipher probing semantics.

## v0.8.9 - 2026-05-17

### Added

- Added JSON schema version `1.0` to machine-readable output.
- Added scan metadata for duration, handshake attempts, cipher discovery mode, negotiated cipher and warnings.
- Added `--policy modern` and `--fail-on` policy failure controls for CI workflows.

### Changed

- Improved Markdown reports with a summary, TLS version table, cipher tables and policy failure details.
- Documented JSON schema expectations, cipher discovery semantics and policy mode.

### Tests

- Added policy tests and expanded JSON, Markdown and scan metadata coverage.

## v0.8.8 - 2026-05-17

### Changed

- Updated the sample Markdown report in `docs/example-report.md`.

## v0.8.7 - 2026-05-16

### Changed

- Refactored the CLI entrypoint into a testable `run(args, stdout, stderr) int` flow.
- Replaced process-global CLI flags with isolated per-run flag parsing.
- Routed human-readable CLI output through injected writers.

### Tests

- Added CLI tests for exit codes, usage output, flag combination validation and independent flag parsing.

## v0.8.6 - 2026-05-16

### Changed

- Changed the project license from GPLv3 to MIT.
- Documented the project as experimental in the README.
- Made Markdown report write failures exit with a non-zero status.
- Made `--json --cert` require `--output` and save PEM chains without corrupting JSON stdout.
- Added a distinct `handshake_error` scan status for non-protocol TLS handshake failures.
- Updated the Go toolchain target from 1.23.4 to 1.26.3.
- Refined the README as a concise project overview.
- Added CI, release, version, dependency and platform badges to the README.
- Moved detailed usage documentation into `docs/user-manual.md`.

## v0.8.5 - 2026-05-16

### Added

- Added a CI workflow for tests, race tests and `go vet`.
- Added a sample Markdown report under `docs/`.

### Changed

- Release notes are now extracted from `CHANGELOG.md` instead of being duplicated in the release workflow.
- Documented the release checklist in the README.

## v0.8.4 - 2026-05-16

### Added

- Added `--json` for machine-readable scan output.
- Added `--no-clear` for CI, logs and copy/paste workflows.

### Changed

- Markdown reports now include generation timestamp and scanner version.
- Markdown reports now group unique certificates by TLS version instead of only reporting the first certificate.

## v0.8.3 - 2026-05-16

### Changed

- Introduced `scan.Options` and structured scan result statuses.
- Moved user-facing scan progress messages out of the `scan` package.
- Changed certificate output helpers to return errors instead of exiting the process.

### Tests

- Added local TLS integration tests for TLS 1.2, TLS 1.3, invalid certificates, unsupported protocols and timeouts.

## v0.8.2 - 2026-05-16

### Changed

- Report certificate validation status separately from TLS protocol support.
- Report TLS 1.3 cipher suites as observed cipher suites.
- Validate host, port and timeout inputs before scanning.

### Added

- Added `--skip-verify` for intentionally skipping certificate validation.

### Tests

- Added tests for CLI input validation and certificate validation status reporting.

## v0.8.1 - 2026-05-16

### Changed

- Aligned the Go module path with `github.com/olelbis/tlsanalyzer`.
- Reused the normalized host value throughout scan and report generation.
- Made cipher suite output deterministic.
- Added timeouts to TLS 1.3 cipher probing.
- Documented the TLS 1.3 cipher probing limitation from Go's TLS API.

### Fixed

- Corrected certificate expiration day calculation.
- Avoided reporting every TLS 1.3 cipher suite as supported when Go cannot force them individually.
- Added explicit release workflow permissions for publishing GitHub releases.

### Tests

- Added unit tests for TLS version parsing, TLS version filtering, cipher compatibility, Markdown report generation and certificate expiry calculation.

## v0.8.0 - 2025-07-21

- Code modularity refactor.

## v0.7.0 - 2025-07-20

- Code cleanup.

## v0.6.9 - 2025-07-18

- Added full build shell script.

## v0.6.2 - 2025-07-17

- Bugfix release.

## v0.6.1 - 2025-07-16

- Extended force-cipher behavior to TLS 1.3 scan attempts.

## v0.6.0 - 2025-07-16

- Added force-cipher negotiation.

## v0.5.2 - 2025-07-16

- Scan fixes.

## v0.5.1 - 2025-07-13

- GitHub Actions test release.

## v0.5.0 - 2025-07-13

- Renamed the project to `tlsanalyzer`.

## v0.4.0

- Added Markdown report export.

## v0.3.0

- Added goroutines to improve scanning performance.

## v0.2.0

- Added terminal screen cleanup.

## v0.1.0

- First release.
