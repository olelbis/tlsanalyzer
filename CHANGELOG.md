# Changelog

All notable changes to `tlsanalyzer` are documented here.

## Unreleased

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
