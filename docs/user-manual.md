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

Release tags also publish a minimal multi-arch container image to GitHub Container Registry:

```bash
docker run --rm ghcr.io/olelbis/tlsanalyzer:v0.24.2 --host example.com --no-clear
docker run --rm ghcr.io/olelbis/tlsanalyzer:latest --host example.com --policy modern --no-clear
```

The image supports `linux/amd64` and `linux/arm64`, includes CA certificates for normal certificate validation and is published with registry SBOM and provenance attestations.

Homebrew and Windows package-manager support are not published yet. For now, macOS users should use the release binaries or the container image, and Windows users should use the release `.exe` assets. A dedicated Homebrew tap and Scoop or WinGet manifests are the next installation-channel candidates.

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

Container provenance is attached to the GHCR image by the release workflow.

## Go Package Usage

The CLI is backed by the reusable `analyzer` package:

```go
opts := analyzer.DefaultOptions("example.com")
opts.MinVersion = tls.VersionTLS12
opts.PolicyConfig = policy.Config{Name: policy.NameModern}

result, err := analyzer.Run(opts, analyzer.Hooks{})
```

Use `analyzer.DefaultOptions` for CLI-like defaults, then override host, SNI, timeout, minimum TLS version and policy settings as needed. Operational target failures are represented in `result.Results` with scan statuses such as `network_error`, `timeout` and `handshake_error`; `Run` returns an error only for caller hook failures, wrapped as `*analyzer.HookError`.

The preview `tlsprobe` package exposes the raw TLS 1.3 cipher probe:

```go
results, err := tlsprobe.ProbeTLS13CipherSuites(context.Background(), tlsprobe.Options{
	Address:    net.JoinHostPort("example.com", "443"),
	ServerName: "example.com",
	Timeout:    5 * time.Second,
}, tlsprobe.SupportedTLS13CipherSuites())
```

`tlsprobe` sends ClientHello-only probes and classifies the first useful server response. It does not complete full TLS handshakes. See [TLS probe Go package](tlsprobe-package.md) for status values and current limits.

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

Use a JSON config file:

```bash
tlsanalyzer --config tlsanalyzer.json --target production --profile modern-ci
```

## Flags

```text
  --config string
        JSON config file
  --target string
        Named target from --config
  --profile string
        Named policy profile from --config
  --host string
        Hostname or server IP to scan (required unless provided by --config)
  --port string
        TLS server port (default "443")
  --sni string
        TLS Server Name Indication and certificate validation name
  --targets-file string
        JSON file with targets to scan in batch mode
  --concurrency int
        Maximum concurrent targets in batch mode, capped at 64 (default 4)
  --retries int
        Retry count for transient network failures
  --retry-backoff int
        Base retry backoff in seconds (default 1)
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
  --compact
        Use compact human-readable console output
  --version
        Print version information and exit
  --policy string
        Policy to evaluate: modern
  --fail-on string
        Comma-separated checks that fail the run: legacy-tls, weak-cipher, invalid-cert, expired-cert
  --require-tls string
        Comma-separated TLS versions that must be supported, such as 1.3
  --forbid-tls string
        Comma-separated TLS versions that must not be supported, such as 1.0,1.1
  --require-alpn string
        Comma-separated ALPN protocols that supported handshakes must negotiate
  --forbid-alpn string
        Comma-separated ALPN protocols that must not be negotiated
  --min-cert-key-bits int
        Minimum certificate public key size in bits
  --min-cert-days int
        Minimum number of days before certificate expiry
  --markdown string
        Write scan result to a Markdown file
  --sarif string
        Write policy findings to a SARIF file
  --junit string
        Write scan and policy results to a JUnit XML file
```

## Common Workflows

### Human-readable scan

```bash
tlsanalyzer --host example.com --no-clear
```

Use `--no-clear` when running in terminals, logs or CI systems where clearing the screen is unwanted.

The console output ends with a compact summary covering supported TLS versions, protocol findings, certificate validation status and cipher findings. Cipher findings include the evidence mode, such as `negotiated`, `probed`, `raw-probed`, `observed` or mixed evidence. When TLS 1.3 raw probe evidence is available, the summary also reports the supported raw-probed cipher count. Cipher severity is version-aware, so CBC cipher suites negotiated on TLS 1.0 or TLS 1.1 are reported as legacy CBC findings.

Use `--compact` for shorter human-readable output while preserving the final summary:

```bash
tlsanalyzer --host example.com --compact
```

`tlsanalyzer` offers `h2` and `http/1.1` through ALPN to observe the negotiated TLS application protocol. It does not send HTTP requests or evaluate non-TLS HTTP behavior.

### JSON config file

`tlsanalyzer` can read repeatable scan settings from a JSON file without adding runtime dependencies:

```json
{
  "target": "production",
  "profile": "modern-ci",
  "timeout": 5,
  "min_version": "1.2",
  "json": true,
  "sarif": "tlsanalyzer.sarif",
  "junit": "tlsanalyzer.xml",
  "no_clear": true,
  "targets_file": "targets.json",
  "concurrency": 4,
  "retries": 2,
  "retry_backoff": 1,
  "targets": {
    "production": {
      "host": "example.com",
      "port": "443",
      "sni": "example.com"
    }
  },
  "profiles": {
    "modern-ci": {
      "policy": "modern",
      "require_tls": "1.3",
      "forbid_tls": "1.0,1.1",
      "min_cert_days": 30
    }
  }
}
```

Run it with:

```bash
tlsanalyzer --config tlsanalyzer.json
```

Use `--target` or `--profile` to select a different named entry from the same file:

```bash
tlsanalyzer --config tlsanalyzer.json --target staging --profile baseline
```

CLI flags override values loaded from the config file:

```bash
tlsanalyzer --config tlsanalyzer.json --target production --host override.example.com
```

Unknown JSON fields are rejected so configuration typos fail early.

### Batch scans

Use `--targets-file` to scan multiple endpoints in one run. The file can be a JSON array:

```json
[
  {"host": "example.com"},
  {"host": "203.0.113.10", "port": "443", "sni": "example.com"}
]
```

It can also be wrapped in a `targets` object:

```json
{
  "targets": [
    {"host": "example.com", "port": "443"}
  ]
}
```

Run a batch scan with bounded concurrency and retry controls:

```bash
tlsanalyzer --targets-file targets.json --concurrency 4 --retries 2 --retry-backoff 1 --json
```

Batch mode supports human summaries, aggregate JSON output, SARIF and JUnit XML:

```bash
tlsanalyzer --targets-file targets.json --policy modern --sarif tls.sarif --junit tls.xml
```

Retries are only applied when a target produces transient `network_error` or `timeout` scan statuses. Backoff is linear, so `--retry-backoff 2` waits 2 seconds before the first retry, 4 seconds before the second retry and so on.

If a target omits `port`, the global `--port` value is used. If a target omits `sni`, the global `--sni` value is used when present.

Unknown fields in target files are rejected so typos fail early. Batch concurrency is capped at 64 workers to keep local resource usage predictable.

`--cert` and `--markdown` are currently single-target features and are rejected together with `--targets-file`.

### CI report formats

Write SARIF output for security dashboards:

```bash
tlsanalyzer --host example.com --policy modern --sarif tlsanalyzer.sarif
```

SARIF output uses version 2.1.0 and reports enabled policy failures and scan execution errors as SARIF results. A passing policy with no scan execution errors still produces a valid SARIF file with no results.

Write JUnit XML output for CI test report views:

```bash
tlsanalyzer --host example.com --policy modern --junit tlsanalyzer.xml
```

JUnit output includes one testcase per scanned TLS version. Network, timeout and handshake execution errors are reported as JUnit errors, while policy failures are reported as JUnit failures.

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

Go does not allow forcing individual TLS 1.3 cipher suites through `tls.Config.CipherSuites`. When cipher probing is enabled for TLS 1.3, `tlsanalyzer` uses its preview `tlsprobe` raw probe to send minimal ClientHello messages with one TLS 1.3 cipher suite at a time. The probe reads the ServerHello, alert or another probe outcome and records per-cipher status without completing the full TLS handshake.

If the raw probe cannot confirm support, `tlsanalyzer` falls back to observed handshakes so the report still includes the negotiated TLS 1.3 evidence.

JSON and Markdown output distinguish:

- `negotiated`: the cipher selected by the first successful handshake.
- `probed`: cipher suites accepted when forcing individual TLS 1.0, 1.1 or 1.2 suites.
- `raw-probed`: TLS 1.3 cipher suites accepted by the raw ClientHello probe.
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

Use configurable policy gates for stricter environments:

```bash
tlsanalyzer --host example.com --require-tls 1.3 --forbid-tls 1.0,1.1 --require-alpn h2 --min-cert-key-bits 2048 --min-cert-days 30
```

Configurable policy flags are evaluated together with `--policy` and `--fail-on` when they are present:

- `--require-tls`: fails when any listed TLS version is not supported.
- `--forbid-tls`: fails when any listed TLS version is supported.
- `--require-alpn`: fails when a supported handshake does not negotiate one of the listed ALPN protocols.
- `--forbid-alpn`: fails when a supported handshake negotiates a listed ALPN protocol.
- `--min-cert-key-bits`: fails when the certificate public key is unavailable or smaller than the configured size.
- `--min-cert-days`: fails when certificate expiry is unavailable or closer than the configured threshold.

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

| Code | Meaning |
| ---: | --- |
| 0 | Scan completed successfully and enabled policy checks passed. |
| 1 | Invalid input, scan setup failure, report write failure, certificate output failure or target-level scan execution failure. |
| 2 | CLI flag parsing failed. |
| 3 | Scan completed but enabled policy checks failed. |

Unsupported TLS versions are scan results, not CLI failures.

A target-level scan execution failure means every attempted TLS version ended with `network_error`, `timeout` or `handshake_error`. Mixed results are still reported as scan evidence; use policy gates when a specific TLS posture must fail the run.

## Operational Notes

- `--host` must not contain whitespace.
- `--port` must be numeric and in the `1..65535` range.
- `--sni`, when set, must not contain whitespace.
- `--timeout` must be at least one second.
- Some legacy TLS versions and cipher suites may be disabled by the remote server or by the Go runtime.
- The scanner uses only the Go standard library at runtime.
