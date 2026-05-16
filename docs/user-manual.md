# User Manual

This manual covers day-to-day usage of `tlsanalyzer`.

## Installation

The easiest path is to download a binary from the [GitHub releases page](https://github.com/olelbis/tlsanalyzer/releases).

You can also build from source:

```bash
CGO_ENABLED=0 go build -v -ldflags="-X 'github.com/olelbis/tlsanalyzer/build.Version=$(cat VERSION)' -X 'github.com/olelbis/tlsanalyzer/build.BuildUser=Team tlsanalyzer' -X 'github.com/olelbis/tlsanalyzer/build.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)'" -o tlsanalyzer .
```

Or use the build script:

```bash
./scripts/build.sh
./scripts/build.sh --all
```

## Basic Usage

```bash
tlsanalyzer --host example.com
```

Scan a different port:

```bash
tlsanalyzer --host example.com --port 8443
```

Start from TLS 1.2:

```bash
tlsanalyzer --host example.com --min-version 1.2
```

## Flags

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

## Common Workflows

### Human-readable scan

```bash
tlsanalyzer --host example.com --no-clear
```

Use `--no-clear` when running in terminals, logs or CI systems where clearing the screen is unwanted.

### Markdown report

```bash
tlsanalyzer --host example.com --markdown example.com.md
```

Markdown reports include:

- Generation timestamp and scanner version
- Supported and unsupported TLS versions
- Cipher suites grouped by TLS version
- Cipher classification labels
- Unique certificate details grouped by TLS version
- Certificate validation status and DNS names

See [example-report.md](example-report.md) for a sample report.

### JSON output

```bash
tlsanalyzer --host example.com --json
```

JSON output is intended for scripts and automation. It includes:

- Host and port
- Scanner version and generation timestamp
- Per-version support status
- Scan status and error messages
- Cipher suites
- Certificate details
- Certificate validation status

### Certificate chain

Print the certificate chain:

```bash
tlsanalyzer --host example.com --cert
```

Save the PEM chain to a file:

```bash
tlsanalyzer --host example.com --cert --output example.pem
```

The saved file is prefixed by TLS version, for example `TLS1.2_example.pem`.

When using JSON output, `--cert` requires `--output` so PEM data does not mix with JSON on stdout:

```bash
tlsanalyzer --host example.com --json --cert --output example.pem
```

### Certificate expiration

```bash
tlsanalyzer --host example.com --checkcert
```

This prints days until certificate expiration in the human-readable output and includes expiration data in Markdown and JSON reports.

### Certificate validation behavior

By default, certificate validation is enabled and reported separately from TLS protocol support.

This means a server can be reported as supporting TLS 1.2 while its certificate is reported as invalid.

Use `--skip-verify` only when you intentionally want to inspect the TLS handshake without validating certificate trust:

```bash
tlsanalyzer --host expired.example.com --skip-verify
```

### Cipher probing

```bash
tlsanalyzer --host example.com --force-ciphers
```

For TLS 1.0, 1.1 and 1.2, `tlsanalyzer` can force individual cipher suites to probe support.

Go does not allow forcing individual TLS 1.3 cipher suites through `tls.Config.CipherSuites`. For TLS 1.3, `tlsanalyzer` reports cipher suites observed across repeated handshakes.

## Interpreting Scan Status

Each TLS version has a scan status:

- `supported`: the TLS handshake succeeded.
- `unsupported`: the remote endpoint rejected or does not support that protocol version.
- `timeout`: the connection or handshake timed out.
- `handshake_error`: the endpoint was reachable, but the TLS handshake failed for a reason other than a clear unsupported protocol version.
- `network_error`: the endpoint could not be reached or another network error occurred.

Certificate validation is reported separately:

- `valid`: the certificate chain validates for the scanned host.
- `invalid`: the TLS handshake succeeded, but certificate validation failed.
- `skipped`: validation was intentionally skipped with `--skip-verify`.
- `unavailable`: no peer certificate was available.

## Exit Behavior

Invalid CLI input, report write failures and certificate output failures exit with a non-zero status.

Unsupported TLS versions are scan results, not CLI failures.

## Operational Notes

- `--host` must not contain whitespace.
- `--port` must be numeric and in the `1..65535` range.
- `--timeout` must be at least one second.
- Some legacy TLS versions and cipher suites may be disabled by the remote server or by the Go runtime.
- The scanner uses only the Go standard library at runtime.
