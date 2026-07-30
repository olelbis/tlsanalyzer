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
  secrecy. The positive baseline is `ecc256.badssl.com`, which offers only
  ECDHE_ECDSA suites.
- `revoked.badssl.com` passes. The scanner performs no OCSP or CRL check, so
  the certificate validates. This is expected behaviour, not a regression.

Weak-cipher endpoints (`rc4`, `3des`, `null`, `dh480`, `dh512`, `dh1024`) are
not negotiable by the Go standard library, so they exercise error handling
rather than cipher classification.

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
