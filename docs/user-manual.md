# User Manual

This manual covers day-to-day usage of `tlsanalyzer`.

## Installation

The easiest path is to download a binary from the [GitHub releases page](https://github.com/olelbis/tlsanalyzer/releases).

Linux users can also install the `.deb` or `.rpm` packages from the same release page. These packages install the binary and the `tlsanalyzer(1)` man page:

```bash
sudo dpkg -i tlsanalyzer_*.deb
sudo rpm -i tlsanalyzer-*.rpm
man tlsanalyzer
```

You can also build from source:

```bash
CGO_ENABLED=0 go build -v -ldflags="-X 'github.com/olelbis/tlsanalyzer/build.Version=$(cat VERSION)' -X 'github.com/olelbis/tlsanalyzer/build.BuildUser=Team tlsanalyzer' -X 'github.com/olelbis/tlsanalyzer/build.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)'" -o tlsanalyzer .
```

Or use the build script:

```bash
./scripts/build.sh
./scripts/build.sh --all
```

## Release Verification

Each release includes `checksums.txt`, an SPDX SBOM and GitHub artifact attestations.

Verify downloaded files with SHA256:

```bash
sha256sum --ignore-missing -c checksums.txt
```

Verify provenance attestations with the GitHub CLI:

```bash
gh attestation verify tlsanalyzer-linux-amd64 --repo olelbis/tlsanalyzer
```

## Basic Usage

```bash
tlsanalyzer --host example.com
```

Scan a different port:

```bash
tlsanalyzer --host example.com --port 8443
```

Scan an IP address or load balancer while sending a specific SNI name:

```bash
tlsanalyzer --host 203.0.113.10 --sni example.com
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
  --sni string
        TLS Server Name Indication and certificate validation name
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
  --policy string
        Policy to evaluate: modern
  --fail-on string
        Comma-separated checks that fail the run: legacy-tls, weak-cipher, invalid-cert, expired-cert
  --markdown string
        Write scan result to a Markdown file
```

## Common Workflows

### Human-readable scan

```bash
tlsanalyzer --host example.com --no-clear
```

Use `--no-clear` when running in terminals, logs or CI systems where clearing the screen is unwanted.

The console output ends with a compact summary covering supported TLS versions, protocol findings, certificate validation status and cipher findings. Cipher findings include the evidence mode, such as `negotiated`, `probed`, `raw-probed`, `observed` or mixed evidence. When TLS 1.3 raw probe evidence is available, the summary also reports the supported raw-probed cipher count. Cipher severity is version-aware, so CBC cipher suites negotiated on TLS 1.0 or TLS 1.1 are reported as legacy CBC findings.

`tlsanalyzer` offers `h2` and `http/1.1` through ALPN to observe the negotiated TLS application protocol. It does not send HTTP requests or evaluate non-TLS HTTP behavior.

### Markdown report

```bash
tlsanalyzer --host example.com --markdown example.com.md
```

Markdown reports include:

- Generation timestamp and scanner version
- Supported and unsupported TLS versions
- Negotiated key exchange group and ALPN protocol when available
- Cipher suites grouped by TLS version
- Cipher classification labels
- Unique certificate details grouped by TLS version
- Certificate public key, signature algorithm, validation status and DNS names

See [example-report.md](example-report.md) for a sample report.

### JSON output

```bash
tlsanalyzer --host example.com --json
```

JSON output is intended for scripts and automation. It includes:

- Schema version
- Host and port
- Server name, when `--sni` is used
- Scanner version and generation timestamp
- Per-version support status
- Scan status and error messages
- Negotiated key exchange group and ALPN protocol when available
- Negotiated cipher suite
- Cipher suite discovery mode: `negotiated`, `probed`, `raw-probed` or `observed`
- Cipher suites found by probing or observation
- Raw probe status details when available
- Handshake attempts, scan duration and warnings
- Certificate details, including public key and signature algorithm metadata when available
- Certificate validation status
- Policy result, when `--policy` or `--fail-on` is used

The current JSON schema version is `1.1`. See [json-schema-v1.md](json-schema-v1.md) for the field contract. Additive fields may be introduced in later minor releases. Removing or renaming existing fields should be treated as a breaking schema change.

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

When certificate policy checks are enabled with `--policy modern` or `--fail-on invalid-cert`, skipped or unavailable certificate validation fails the policy.

### Cipher probing

```bash
tlsanalyzer --host example.com --force-ciphers
```

For TLS 1.0, 1.1 and 1.2, `tlsanalyzer` can force individual cipher suites to probe support.

By default, `tlsanalyzer` reports the cipher suite negotiated by the normal TLS handshake. Full cipher probing runs when `--force-ciphers` is used, or when a policy check needs cipher evidence, such as `--policy modern` or `--fail-on weak-cipher`.

Go does not allow forcing individual TLS 1.3 cipher suites through `tls.Config.CipherSuites`. When cipher probing is enabled for TLS 1.3, `tlsanalyzer` uses its internal raw probe to send minimal ClientHello messages with one TLS 1.3 cipher suite at a time. The probe reads the ServerHello, alert or another probe outcome and records per-cipher status without completing the full TLS handshake.

If the raw probe cannot confirm support, `tlsanalyzer` falls back to observed handshakes so the report still includes the negotiated TLS 1.3 evidence.

JSON and Markdown output distinguish:

- `negotiated`: the cipher selected by the first successful handshake.
- `probed`: cipher suites accepted when forcing individual TLS 1.0, 1.1 or 1.2 suites.
- `raw-probed`: TLS 1.3 cipher suites accepted by the internal raw ClientHello probe.
- `observed`: TLS 1.3 cipher suites seen across repeated handshakes when raw probing is inconclusive.

### Policy mode

Evaluate a built-in policy:

```bash
tlsanalyzer --host example.com --policy modern
```

The `modern` policy fails the run when it detects:

- TLS 1.0 or TLS 1.1 support
- Weak or insecure cipher suites
- Unclassified cipher suites
- Invalid certificates
- Expired certificates

Because the `modern` policy includes weak cipher checks, it automatically enables cipher probing.

Because the `modern` policy includes certificate checks, certificate validation must succeed. Invalid, skipped or unavailable validation fails the policy.

Use targeted checks without a named policy:

```bash
tlsanalyzer --host example.com --fail-on legacy-tls,weak-cipher
```

The `weak-cipher` check also enables cipher probing.

Available checks are:

- `legacy-tls`
- `weak-cipher`
- `invalid-cert`
- `expired-cert`

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

Policy failures exit with status `3`.

Unsupported TLS versions are scan results, not CLI failures.

## Operational Notes

- `--host` must not contain whitespace.
- `--port` must be numeric and in the `1..65535` range.
- `--sni`, when set, must not contain whitespace.
- `--timeout` must be at least one second.
- Some legacy TLS versions and cipher suites may be disabled by the remote server or by the Go runtime.
- The scanner uses only the Go standard library at runtime.
