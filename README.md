# tlsanalyzer

[![CI](https://github.com/olelbis/tlsanalyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/olelbis/tlsanalyzer/actions/workflows/ci.yml)
[![Release](https://github.com/olelbis/tlsanalyzer/actions/workflows/release.yml/badge.svg)](https://github.com/olelbis/tlsanalyzer/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/olelbis/tlsanalyzer?sort=semver)](https://github.com/olelbis/tlsanalyzer/releases/latest)
[![Status: Experimental](https://img.shields.io/badge/status-experimental-orange.svg)](BACKLOG.md)
[![Go Version](https://img.shields.io/badge/Go-1.26.3-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-standard%20library-only)](https://pkg.go.dev/std)
[![OS - Linux](https://img.shields.io/badge/OS-Linux-blue?logo=linux&logoColor=white)](https://www.linux.org/)
[![OS - macOS](https://img.shields.io/badge/OS-macOS-blue?logo=Apple&logoColor=white)](https://apple.com/)
[![OS - Windows](https://img.shields.io/badge/OS-Windows-blue?logo=windows&logoColor=white)](https://www.microsoft.com/windows)

`tlsanalyzer` is a small, dependency-free TLS inspection CLI inspired by `sslscan`.

It is built for environments where the scanner should be easy to carry, easy to audit and able to run without installing extra packages or fetching runtime dependencies.

## What It Does

- Tests TLS protocol support from TLS 1.0 through TLS 1.3.
- Reports negotiated and supported cipher suites.
- Keeps TLS support separate from certificate validation status.
- Prints certificate summaries and optional PEM certificate chains.
- Exports human-readable Markdown reports.
- Emits JSON for scripts and automation.
- Evaluates simple TLS policy checks for CI workflows.
- Builds multi-platform release binaries with GitHub Actions.

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
tlsanalyzer --host example.com --cert --output example.pem
```

Policy failures return exit code `3`, which makes `--policy modern` useful in CI.

## Documentation

- [User manual](docs/user-manual.md): installation, flags, examples, output formats and operational notes.
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

`tlsanalyzer` is experimental software. The core workflow is covered by unit tests, local TLS integration tests, CI and automated release builds, but scan accuracy and output semantics should still be validated before relying on it for compliance, audit or production security decisions.

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

GitHub Actions builds Linux, macOS and Windows binaries for `amd64` and `arm64`, then uses the matching `CHANGELOG.md` section as the GitHub release body.
