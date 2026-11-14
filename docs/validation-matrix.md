# Real-world validation matrix

This matrix is for manual release confidence checks. It intentionally uses
public endpoints, so exact negotiated ciphers, certificates, ALPN and key
exchange groups may change over time or differ by network location.

Do not make these checks part of normal CI. Treat them as smoke tests before a
preview or beta release.

## Command

Run the scripted validation:

```bash
scripts/validate-real-world.sh
```

The script uses `go run .` and avoids external JSON tools such as `jq`. It
creates a temporary output directory and removes it when it exits.

## Matrix

| Scenario | Target | Command shape | Expected evidence |
| --- | --- | --- | --- |
| Version metadata | local binary | `go run . --version` | Prints the current scanner version. |
| TLS 1.3 normal handshake | `www.example.com` with SNI `example.com` | `--min-version 1.3 --no-clear` | TLS 1.3 supported, certificate valid, one negotiated cipher line. |
| TLS 1.3 raw probing | `www.example.com` with SNI `example.com` | `--min-version 1.3 --force-ciphers --no-clear` | Raw-probed cipher list and ClientHello-only summary. |
| JSON shape | `www.example.com` with SNI `example.com` | `--min-version 1.3 --force-ciphers --json` | `schema_version`, `scanner_version`, `cipher_discovery` and raw probe evidence are present. |
| Key exchange groups | `www.example.com` with SNI `example.com` | `--min-version 1.3 --enum-groups --json` | `key_exchange_groups` contains at least the negotiated group and `key_exchange_groups_incomplete` is absent. |
| Baseline self-check | `www.example.com` with SNI `example.com` | `--force-ciphers --json > base.json`, then `--baseline base.json` | The second run exits `0` with no `baseline` policy failure. |
| Markdown report | `www.example.com` with SNI `example.com` | `--markdown <tempfile>` | Markdown report contains summary, TLS table and cipher section. |
| Policy pass smoke | `www.example.com` with SNI `example.com` | `--min-version 1.3 --policy modern --json` | Command exits successfully and emits JSON policy evidence. |
| Certificate validation failure | `expired.badssl.com` | `--min-version 1.2 --json` | JSON reports invalid certificate evidence separately from TLS support. |

## badssl Exit-Code Matrix

A second, larger matrix lives in `scripts/badssl-cases.tsv` and is run by
`scripts/validate-badssl.sh`. It asserts documented exit codes rather than
output text: `0` for a clean scan, `3` for a failed policy check, `1` for a
handshake that cannot complete.

```bash
./scripts/validate-badssl.sh          # gating cases only
./scripts/validate-badssl.sh --all    # include observational cases
./scripts/validate-badssl.sh --only expired,ecc256 --keep-logs
```

Both validation scripts build the binary with `go build` instead of using
`go run .`. This is deliberate: `go run` replaces the program's exit code with
`1`, which makes a failed policy check indistinguishable from a runtime error
and silently defeats any assertion on exit codes.

Cases marked `gate: no` in the TSV are observational. They are reported but do
not fail the run, either because the outcome depends on server-side
configuration (certificate size) or because the case is slow (`rsa8192`).

Two results are worth knowing before reading the output:

- badssl endpoints with an RSA certificate fail `--policy modern` even though
  the certificate itself validates. They deliberately offer 3DES and
  static-RSA suites, which the modern policy rejects for lack of forward
  secrecy. `ecc256.badssl.com` and `ecc384.badssl.com` offer only ECDHE_ECDSA
  suites but fail as well: they accept `TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA`,
  which the Go standard library does not implement and only the raw
  TLS 1.0-1.2 probe detects. The matrix therefore has no badssl case that
  passes `--policy modern`; the positive case is covered by the Go test
  `TestWeakCipherGateStillPassesOnCleanEndpoint`.
- `revoked.badssl.com` is platform dependent. Go's own verifier (Linux) performs no
  OCSP or CRL check, so the certificate validates (exit 0). On macOS the system
  verifier reports it as revoked (exit 3). The case is observational.

Weak-cipher endpoints (`rc4`, `null`, `dh480`, `dh512`, `dh1024`) are
not negotiable by the Go standard library. Their TLS versions are detected
with a ClientHello-only raw probe and their suites with the raw enumeration,
so `--policy modern` fails on them (exit 3): no certificate is retrieved, and
RC4 and NULL suites are insecure. The size of the DHE parameters is not
inspected, so the `dh*` cases fail for the missing certificate and for legacy
TLS versions, not for the weak Diffie-Hellman group.

All badssl endpoints are TLS 1.2 only; TLS 1.3 reports `handshake_error`
there.

Do not run either script in normal CI. badssl.com runs on donated
infrastructure.

## Interpreting Drift

Expected drift:

- certificate issuer and validity windows can change;
- negotiated cipher suites can change with CDN/server policy;
- ALPN can vary if a server or CDN changes HTTP/2 support;
- key exchange group can vary by Go runtime and server preference;
- public targets can be temporarily unavailable.

Unexpected drift worth investigating:

- JSON is not parseable or required fields disappear;
- certificate validation is merged with protocol support;
- TLS 1.3 raw probe output claims a full handshake;
- negotiated ciphers are printed as an exhaustive supported list;
- policy mode exits with the wrong code for clear pass/fail cases.

## Manual Notes Template

```text
Date:
Network/location:
Go version:
tlsanalyzer version:

version:
tls13-handshake:
tls13-raw-probe:
json-shape:
markdown-report:
policy-pass:
expired-cert:

Notes:
```
