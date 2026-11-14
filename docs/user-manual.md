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
docker run --rm ghcr.io/olelbis/tlsanalyzer:v0.34.0 --host example.com --no-clear
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

`tlsprobe` sends ClientHello-only probes and classifies the first useful server response. It does not complete full TLS handshakes. The package also exposes selected key share group, HelloRetryRequest retry and TLS alert-code metadata when available. See [TLS probe Go package](tlsprobe-package.md) for status values and current limits.

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
        Minimum TLS version to test: 1.0, 1.1, 1.2 or 1.3 (default "1.0").
        Explicit --forbid-tls, --require-tls and --fail-on legacy-tls gates
        that refer to older versions lower the scan range for that run
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
        Policy to evaluate: modern, mozilla-modern or mozilla-intermediate
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
  --enum-groups
        Enumerate the TLS 1.3 key exchange groups the server accepts, including post-quantum hybrids
  --require-pq
        Fail when TLS 1.3 accepts no post-quantum key exchange group (implies --enum-groups)
  --baseline string
        Compare with a JSON report recorded earlier with --json; regressions fail the run (exit 3)
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

The verbose per-version output prints the negotiated cipher suite once and labels it as the cipher selected in that handshake. Additional cipher lists are shown only when the scanner has probed, raw-probed or observed extra cipher evidence. The console output ends with a compact summary covering supported TLS versions, protocol findings, certificate validation status and cipher findings. Cipher findings include the evidence mode, such as `negotiated`, `probed`, `raw-probed`, `observed` or mixed evidence. When TLS 1.3 raw probe evidence is available, the summary also reports the supported raw-probed cipher count and makes clear that the evidence is ClientHello-only ServerHello evidence, not a full TLS handshake. Cipher severity is version-aware, so CBC cipher suites negotiated on TLS 1.0 or TLS 1.1 are reported as legacy CBC findings.

Use `--compact` for shorter human-readable output while preserving the final summary:

```bash
tlsanalyzer --host example.com --compact
```

`tlsanalyzer` offers `h2` and `http/1.1` through ALPN to observe the negotiated TLS application protocol. It does not send HTTP requests or evaluate non-TLS HTTP behavior.

See [output-examples.md](output-examples.md) for small examples that explain negotiated, probed, raw-probed and observed evidence.

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
- Policy result, when any policy gate is enabled

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

For TLS 1.0, 1.1 and 1.2, `tlsanalyzer` finds the supported cipher suites in two steps:

- A raw enumeration over the `tlsprobe` legacy catalog (124 suites on TLS 1.2, 54 on TLS 1.0 and 1.1). The scanner sends a minimal ClientHello that offers a group of suites, reads which one the ServerHello selects, removes it and asks again until the server refuses the rest. It never needs an implementation of the suite, so it also reaches RC4, DES, 3DES, EXPORT, NULL, anonymous DH/ECDH, DHE with RSA or DSS certificates, CAMELLIA, ARIA, SEED, IDEA, AES-CCM and the CBC-SHA256/SHA384 suites. An endpoint with k suites costs about k connections plus a few refusals, not one connection per catalog suite.
- A full TLS handshake for every enumerated suite that Go's `crypto/tls` implements, so those keep full-handshake evidence.

A suite found only by the raw enumeration is reported as supported because the ServerHello selected it on the probed protocol version. In the console list such suites are marked `(raw probe, ClientHello-only)`; in JSON and Markdown they have a `cipher_probe_results` row with `clienthello-serverhello` evidence while `cipher_discovery` stays `probed`.

Unanswered probes are repeated once. If the enumeration still cannot finish, or full-handshake probes time out twice, the result is flagged `cipher_evidence_incomplete`: the console and the reports carry a warning, and the `weak-cipher` check fails with `cipher evidence is incomplete`, because a suite missing from the list is then not proof that the endpoint refuses it. This usually means the endpoint or a firewall is rate limiting or dropping connections; scanning again later, or with a longer `--timeout`, normally clears it.

Raw-probed suites without an explicit classification are rated from their name: NULL, anonymous, EXPORT, RC4, DES, 3DES, IDEA and MD5 suites are insecure; static RSA or DSS with CBC, and `CCM_8`, are weak; forward-secret CBC and all DHE suites are acceptable (the Diffie-Hellman group size is not inspected); other AEAD suites are secure.

Not covered: PSK, SRP, Kerberos, GOST and static DH/ECDH suites, SSLv2/SSLv3, and the strength of DHE parameters.

### Endpoints Go cannot negotiate with

TLS version detection uses a full Go TLS handshake. Some endpoints refuse every such handshake on TLS 1.0 to 1.2 because they only accept suites Go does not implement (RC4, NULL, anonymous, DHE), or because they demand a client certificate. When the handshake is refused or dropped, `tlsanalyzer` sends one raw ClientHello offering the whole legacy catalog. If the ServerHello selects a suite on that version, the version is reported as supported with reduced evidence:

```text
✅ TLS 1.2: supported (raw probe, ClientHello-only)
   Cipher suite selected in ServerHello: TLS_RSA_WITH_RC4_128_SHA
   Full handshake: not completed (remote error: tls: handshake failure)
   Certificate: not retrieved
```

In JSON the result has `version_evidence: "clienthello-serverhello"`, no `certificate`, and `certificate_validation_status: "unavailable"`. Cipher probing and policy gates then work as for any other version. Since the certificate cannot be validated, `--policy modern` and `--fail-on invalid-cert` fail on a version detected this way; `legacy-tls`, `weak-cipher`, `--forbid-tls` and `--require-tls` are evaluated normally. A version the server rejects explicitly, a timeout or a failed TCP connection is not probed again.

By default, `tlsanalyzer` reports the cipher suite negotiated by the normal TLS handshake. Full cipher probing runs when `--force-ciphers` is used, or when a policy check needs cipher evidence, such as `--policy modern` or `--fail-on weak-cipher`.

Go does not allow forcing individual TLS 1.3 cipher suites through `tls.Config.CipherSuites`. When cipher probing is enabled for TLS 1.3, `tlsanalyzer` uses its preview `tlsprobe` raw probe to send minimal ClientHello messages with one TLS 1.3 cipher suite at a time. The probe reads ServerHello, HelloRetryRequest, alert, close, timeout or inconclusive outcomes and records per-cipher status without completing the full TLS handshake.

If the raw probe cannot confirm support, `tlsanalyzer` falls back to observed handshakes so the report still includes the negotiated TLS 1.3 evidence.

JSON and Markdown output distinguish:

- `negotiated`: the cipher selected by the first successful handshake.
- `probed`: cipher suites accepted when forcing individual TLS 1.0, 1.1 or 1.2 suites.
- `raw-probed`: TLS 1.3 cipher suites accepted by the raw ClientHello probe.
- `observed`: the cipher suite negotiated by the version handshake, reported when raw probing is inconclusive.

Raw probe status rows may include:

- `evidence`: classification level such as `clienthello-serverhello`, `clienthello-hrr-serverhello`, `clienthello-alert`, `clienthello-timeout`, `clienthello-closed` or `clienthello-inconclusive`.
- `selected_group`: the key share group selected by ServerHello or HelloRetryRequest when available.
- `hello_retry_request` and `hello_retry_request_retried`: whether the server requested a different key share and whether the probe retried it.
- `alert_level` and `alert_description`: raw TLS alert codes when the server returned an alert.

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

#### Mozilla presets

`mozilla-modern` and `mozilla-intermediate` follow the Modern and Intermediate configurations of the [Mozilla Server Side TLS guidelines](https://wiki.mozilla.org/Security/Server_Side_TLS), version 6.0:

```bash
tlsanalyzer --host example.com --policy mozilla-intermediate
tlsanalyzer --host example.com --policy mozilla-modern --require-pq
```

They are separate from `modern`, which keeps its meaning as tlsanalyzer's own TLS 1.2 baseline. Mozilla removed its Old configuration in version 6.0, so there is no preset for it.

| Check | `mozilla-modern` | `mozilla-intermediate` |
| --- | --- | --- |
| TLS versions | TLS 1.3 required, TLS 1.0 to 1.2 forbidden (`required-tls`, `forbidden-tls`) | TLS 1.0 and 1.1 forbidden (`legacy-tls`) |
| TLS 1.2 cipher suites | not applicable | only the six ECDHE AES-GCM and ChaCha20 suites of the guideline (`cipher-allowlist`, one failure per version listing the suites outside it), plus `weak-cipher` |
| Certificate key | ECDSA, P-256 or larger (`cert-key`) | ECDSA, P-256 or larger, or RSA of at least 2048 bits (`cert-key`) |
| Certificate lifespan | at most 90 days, `NotAfter` minus `NotBefore` (`cert-lifespan`) | at most 366 days (`cert-lifespan`) |
| Certificate trust | valid and not expired (`invalid-cert`, `expired-cert`) | valid and not expired |

`mozilla-modern` scans down to TLS 1.0 whatever `--min-version` says, because the versions it forbids have to be looked at. `mozilla-intermediate` enables cipher probing, since it judges the TLS 1.2 suite list. Lifespans are compared in whole days, rounded down. A version detected only by the raw probe has no certificate, so the key and lifespan checks fail on it.

Only what a client-side scan can observe is checked. The server's cipher preference order, HSTS, OCSP stapling and the key exchange groups are not. Add `--require-pq` to also require a post-quantum group; the presets do not, so their result does not change when a server adds or drops one. An explicit gate that contradicts a preset, such as `--policy mozilla-modern --require-tls 1.2`, is an input error (exit 1).

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

### Key exchange groups and post-quantum support

By default the scan reports the key exchange group the TLS handshake negotiated. `--enum-groups` finds every TLS 1.3 group the endpoint accepts, which answers the question "does this server offer post-quantum key exchange?":

```bash
tlsanalyzer --host example.com --min-version 1.3 --enum-groups
```

```
   Accepted Key Exchange Groups: X25519MLKEM768 (post-quantum), X25519, P-256
```

The 17 groups of the catalog are classical (P-256, P-384, P-521, X25519, X448, ffdhe2048 to ffdhe8192), hybrid (`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`), pure ML-KEM (`MLKEM512`, `MLKEM768`, `MLKEM1024`) and the pre-standard `X25519Kyber768Draft00`. Groups marked `post_quantum` in the JSON report are the ones that include a post-quantum KEM.

How it works matters for reading the result. Each probe is a ClientHello that offers the remaining groups with an empty key share; the server answers with a HelloRetryRequest naming the group it wants. The group is recorded and removed, and the probe repeats until the server refuses, so an endpoint with three groups costs four connections. No handshake is completed with any group: "supported" means the server selected the group, not that a full key exchange was verified. The list is in the order the server selected the groups; it is the server's preference only if the server applies its own preference order rather than the client's.

The enumeration is checked against the handshake: the group the version handshake negotiated has to be in the list. When it is not, or when probes went unanswered, `key_exchange_groups_incomplete` is set and the console warns that the list may be missing groups.

Only TLS 1.3 is enumerated. TLS 1.2 ECDHE curves are not.

`--require-pq` turns it into a gate: the run fails (exit 3, check `require-pq`) when TLS 1.3 accepts no post-quantum group, when TLS 1.3 is not supported, or when the enumeration is incomplete and no post-quantum group was found. It implies `--enum-groups`, and `require_pq` can be set in a config file or a policy profile. With a [baseline](#baseline-comparison) that lists groups, losing a post-quantum group is a regression.

### Baseline comparison

A baseline turns a scan into a regression check: instead of asking whether an endpoint meets a fixed policy, it asks whether the endpoint got worse since a known-good scan.

Record the baseline once with `--json`, adding `--force-ciphers` so that the cipher suites are part of it:

```bash
tlsanalyzer --host example.com --force-ciphers --json --no-clear > baseline.json
```

Then compare later scans with it:

```bash
tlsanalyzer --host example.com --baseline baseline.json
```

The baseline is an ordinary report, single-target or batch, so it can be committed next to the infrastructure it describes and replaced by recording a new one. `baseline` can also be set in a [config file](#json-config-file).

A scan fails (exit 3, check `baseline`) when security got worse:

- a legacy version (TLS 1.0 or 1.1) is supported that was not;
- TLS 1.3 is no longer supported;
- a cipher suite that is insecure, weak or unclassified is offered that was not;
- cipher evidence became incomplete (probes went unanswered), so changes cannot be ruled out;
- a post-quantum key exchange group (see above) is no longer accepted, or the group evidence became incomplete;
- the certificate is no longer valid, expires earlier than the one in the baseline, or has a shorter key.

Everything else that changed is reported as a `baseline:` note and does not change the exit code: a suite that disappeared, TLS 1.3 that appeared, a legacy version that is gone, a certificate that was renewed. A version that timed out or failed on either side, a version the baseline did not scan and a certificate that the current scan could not retrieve are notes as well, never regressions, so a flaky probe cannot fail the run by itself.

Baseline failures are combined with `--policy` and the other gates; the policy fails when any of them fails. When the baseline lists cipher suites, the run probes them even without `--force-ciphers`.

In batch mode pass a batch report recorded with `--targets-file ... --json`. Each target is compared with its own entry, matched by host, port and SNI. A target that is not in the baseline is scanned and noted. In single-target mode, a baseline without a report for the scanned host and port is an input error (exit 1), because comparing with another endpoint would pass silently.

A baseline recorded with another JSON schema major version is refused. Scan the same range it was recorded with: versions the baseline has and the run did not scan (`--min-version`) are listed in a note and not compared.

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

For single-target scans, input validation reports all detected input problems in
one response when possible, while preserving the documented exit codes. The
special `--host is required` case still prints usage help.

A target-level scan execution failure means every attempted TLS version ended with `network_error`, `timeout` or `handshake_error`. Mixed results are still reported as scan evidence; use policy gates when a specific TLS posture must fail the run.

See [compatibility-policy.md](compatibility-policy.md) for the preview stability
promises around exit codes, JSON schema v1, policy behavior and TLS 1.3
evidence labels.

## Operational Notes

- `--host` must not contain whitespace.
- `--port` must be numeric and in the `1..65535` range.
- `--sni`, when set, must not contain whitespace.
- `--timeout` must be at least one second.
- Some legacy TLS versions and cipher suites may be disabled by the remote server or by the Go runtime.
- The scanner uses only the Go standard library at runtime.
