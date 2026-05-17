<p align="center">
  <img src="docs/assets/tlsanalyzer-logo.png" alt="tlsanalyzer pixel art logo" width="180">
</p>

<h1 align="center">tlsanalyzer</h1>

[![CI](https://github.com/olelbis/tlsanalyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/olelbis/tlsanalyzer/actions/workflows/ci.yml)
[![Release](https://github.com/olelbis/tlsanalyzer/actions/workflows/release.yml/badge.svg)](https://github.com/olelbis/tlsanalyzer/actions/workflows/release.yml)
[![Release Alignment](https://github.com/olelbis/tlsanalyzer/actions/workflows/release-alignment.yml/badge.svg)](https://github.com/olelbis/tlsanalyzer/actions/workflows/release-alignment.yml)
[![Latest Release](https://img.shields.io/github/v/release/olelbis/tlsanalyzer?sort=semver)](https://github.com/olelbis/tlsanalyzer/releases/latest)
[![Status: Preview](https://img.shields.io/badge/status-preview-yellowgreen.svg)](BACKLOG.md)
[![Go Version](https://img.shields.io/badge/Go-1.26.3-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Runtime Deps](https://img.shields.io/badge/runtime%20deps-standard%20library-only)](https://pkg.go.dev/std)
[![Packages](https://img.shields.io/badge/packages-deb%20%7C%20rpm-2ea44f?logo=linux&logoColor=white)](https://github.com/olelbis/tlsanalyzer/releases/latest)
[![SBOM](https://img.shields.io/badge/SBOM-SPDX-6f42c1)](https://github.com/olelbis/tlsanalyzer/releases/latest)
[![Checksums](https://img.shields.io/badge/checksums-SHA256-555555)](https://github.com/olelbis/tlsanalyzer/releases/latest)
[![Provenance](https://img.shields.io/badge/provenance-attested-0f6ab4)](https://github.com/olelbis/tlsanalyzer/attestations)

`tlsanalyzer` is a small, dependency-free TLS inspection CLI inspired by `sslscan`.

It is built for environments where the scanner should be easy to carry, easy to audit and able to run without installing extra packages or fetching runtime dependencies.

## What It Does

- Tests TLS protocol support from TLS 1.0 through TLS 1.3.
- Reports negotiated and supported cipher suites.
- Raw-probes TLS 1.3 cipher support when full cipher probing is enabled.
- Reports negotiated key exchange group, ALPN protocol and certificate key/signature metadata.
- Keeps TLS support separate from certificate validation status.
- Supports explicit SNI/certificate name overrides for IP and load balancer scans.
- Prints certificate summaries and optional PEM certificate chains.
- Exports human-readable Markdown reports.
- Emits JSON for scripts and automation.
- Evaluates simple TLS policy checks for CI workflows.
- Prints a concise summary for supported TLS versions, certificate validation and cipher findings.
- Builds multi-platform release binaries, Linux packages and verifiable release metadata with GitHub Actions.

## Quick Start

Download a binary from the [GitHub releases page](https://github.com/olelbis/tlsanalyzer/releases), then run:

```bash
tlsanalyzer --host example.com
```

Common examples:

```bash
tlsanalyzer --host example.com --min-version 1.2
tlsanalyzer --host example.com --json
tlsanalyzer --host example.com --markdown example.com.md
tlsanalyzer --host example.com --policy modern
tlsanalyzer --host example.com --compact
tlsanalyzer --host example.com --cert --output example.pem
tlsanalyzer --host 203.0.113.10 --sni example.com
tlsanalyzer --version
```

Exit codes are stable for CI: `0` means success, `1` means input/runtime/report failure, `2` means CLI flag parsing failed and `3` means enabled policy checks failed. Certificate policy checks fail when validation is invalid, skipped or unavailable.

## Documentation

- [User manual](docs/user-manual.md): installation, flags, examples, output formats and operational notes.
- [JSON schema v1](docs/json-schema-v1.md): machine-readable output contract.
- [Sample Markdown report](docs/example-report.md): example of the generated report format.
- [Changelog](CHANGELOG.md): release history.
- [Backlog](BACKLOG.md): prioritized future work.

## Build From Source

Requirements:

- Go 1.26.3 or newer

```bash
CGO_ENABLED=0 go build -v -ldflags="-X 'github.com/olelbis/tlsanalyzer/build.Version=$(cat VERSION)' -X 'github.com/olelbis/tlsanalyzer/build.BuildUser=Team tlsanalyzer' -X 'github.com/olelbis/tlsanalyzer/build.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)'" -o tlsanalyzer .
```

Or use the build script:

```bash
./scripts/build.sh
./scripts/build.sh --all
```

## Project Status

`tlsanalyzer` is preview software. The core workflow is covered by unit tests, local TLS integration tests, CI and automated release builds, and the JSON v1 output contract is documented for automation consumers.

The scanner is suitable for controlled operational checks and CI policy gates, but findings should still be validated before using them as the sole basis for compliance, audit or production security decisions.

## Stability & Guarantees

- JSON output uses `schema_version: "1.1"` and follows the documented [JSON schema v1](docs/json-schema-v1.md) contract.
- Minor releases may add optional JSON fields; removing or renaming fields requires a new schema version.
- TLS 1.3 cipher suites are raw-probed with minimal ClientHello handshakes when cipher probing is enabled, with per-cipher report evidence and observed-handshake fallback for inconclusive raw probes.
- `--policy modern` is intentionally conservative: invalid, skipped or unavailable certificate validation fails certificate policy checks, and unclassified cipher suites fail weak-cipher checks.
- The project remains dependency-free at runtime and uses only the Go standard library.

## Release Process

Releases are created by pushing a semantic version tag:

```bash
git tag -a vX.Y.Z -m "tlsanalyzer release vX.Y.Z"
git push origin vX.Y.Z
```

Release checklist:

1. Update `VERSION`, `build/build.go` and `CHANGELOG.md`.
2. Run `go test ./...`, `go test -race ./...` and `go vet ./...`.
3. Commit the release preparation changes.
4. Create and push an annotated tag.
5. Run `scripts/check-release-alignment.sh` to confirm `main` points at the latest release tag.

GitHub Actions builds Linux, macOS and Windows binaries for `amd64` and `arm64`, Linux `.deb` and `.rpm` packages, an SPDX SBOM, SHA256 checksums and GitHub artifact attestations. The matching `CHANGELOG.md` section is used as the GitHub release body.

## Verifying Releases

Download the release assets you need together with `checksums.txt`, then verify the files:

```bash
sha256sum --ignore-missing -c checksums.txt
```

GitHub artifact attestations can be verified with the GitHub CLI:

```bash
gh attestation verify tlsanalyzer-linux-amd64 --repo olelbis/tlsanalyzer
```

Linux packages include the `tlsanalyzer(1)` man page:

```bash
sudo dpkg -i tlsanalyzer_*.deb
sudo rpm -i tlsanalyzer-*.rpm
man tlsanalyzer
```
