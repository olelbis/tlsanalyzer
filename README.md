# tlsanalyzer

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![OS - Linux](https://img.shields.io/badge/OS-Linux-blue?logo=linux&logoColor=white)](https://www.linux.org/)
[![OS - macOS](https://img.shields.io/badge/OS-macOS-blue?logo=Apple&logoColor=white)](https://apple.com/)

`tlsanalyzer` is a small TLS inspection CLI inspired by `sslscan`. It is intentionally self-contained and uses only the Go standard library, making it useful in environments where installing extra tools or fetching dependencies is restricted.

The project is in early development.

## Features

- Test TLS protocol support from TLS 1.0 through TLS 1.3.
- Choose the minimum TLS version to scan.
- Show the negotiated cipher suite for each supported TLS version.
- Probe supported cipher suites for TLS 1.0, 1.1 and 1.2.
- Report observed TLS 1.3 cipher suites from repeated handshakes.
- Print certificate summary and optional certificate chain.
- Check days until certificate expiration.
- Export scan results to Markdown.
- Build multi-platform binaries through GitHub Actions.

## Install

Download a binary from the [GitHub releases page](https://github.com/olelbis/tlsanalyzer/releases), or build from source.

## Build From Source

Requirements:

- Go 1.23.4 or newer

Build for the current platform:

```bash
CGO_ENABLED=0 go build -v -ldflags="-X 'github.com/olelbis/tlsanalyzer/build.Version=$(cat VERSION)' -X 'github.com/olelbis/tlsanalyzer/build.BuildUser=Team tlsanalyzer' -X 'github.com/olelbis/tlsanalyzer/build.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)'" -o tlsanalyzer .
```

Or use the build script:

```bash
./scripts/build.sh
```

Build all release targets:

```bash
./scripts/build.sh --all
```

## Usage

```bash
tlsanalyzer --host example.com
```

Flags:

```text
  --host string
        Hostname or server IP to scan (required)
  --port string
        TLS server port (default "443")
  --timeout int
        Connection timeout in seconds (default 5)
  --min-version string
        Minimum TLS version to test: 1.0, 1.1, 1.2 or 1.3 (default "1.0")
  --cert
        Print certificate chain
  --output string
        File to save PEM output to; only used with --cert
  --checkcert
        Print days until certificate expiration
  --force-ciphers
        Force cipher suites during TLS 1.0, 1.1 and 1.2 scans
  --skip-verify
        Skip certificate validation and report TLS handshake support only
  --json
        Write scan result as JSON to stdout
  --no-clear
        Do not clear the terminal before scanning
  --markdown string
        Write scan result to a Markdown file
```

Examples:

```bash
tlsanalyzer --host example.com --min-version 1.2
tlsanalyzer --host example.com --cert --output example.pem
tlsanalyzer --host example.com --checkcert --markdown example.com.md
tlsanalyzer --host example.com --force-ciphers
tlsanalyzer --host expired.example.com --skip-verify
tlsanalyzer --host example.com --json
tlsanalyzer --host example.com --no-clear
```

## Output

A basic run prints each tested TLS version, whether it is supported, the negotiated cipher suite, certificate details and supported cipher suites when they can be probed.

Markdown reports include:

- Supported and unsupported TLS versions
- Cipher suites grouped by TLS version
- Cipher classification labels
- Generation timestamp and scanner version
- Unique certificate details grouped by TLS version
- Certificate subject, issuer, validity, validation status and DNS names

## Notes

- Certificate validation is enabled by default and reported separately from TLS protocol support. Use `--skip-verify` only when you intentionally want to inspect the TLS handshake without validating trust.
- Go does not allow forcing individual TLS 1.3 cipher suites through `tls.Config.CipherSuites`. For TLS 1.3, `tlsanalyzer` reports cipher suites observed across repeated handshakes.
- Some legacy TLS versions and cipher suites may be disabled by the remote server or by the Go runtime.

## Release Process

Releases are created by pushing a semantic version tag:

```bash
git tag -a v0.8.1 -m "tlsanalyzer release v0.8.1"
git push origin v0.8.1
```

The release workflow builds binaries for Linux, macOS and Windows on `amd64` and `arm64`, then attaches them to the GitHub release.

See [CHANGELOG.md](CHANGELOG.md) for release history.

## Roadmap

See [BACKLOG.md](BACKLOG.md) for prioritized improvements and acceptance criteria.
