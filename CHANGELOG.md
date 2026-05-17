# Changelog

All notable changes to `tlsanalyzer` are documented here.

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
