# TLS Scan Report for host example.com:443

- **Generated At**: 2026-05-17T15:20:00Z
- **Scanner Version**: v0.30.0
- **JSON Schema Version**: 1.1

## Summary

- **Supported TLS Versions**: 4 of 4 tested
- **Protocol Findings**: legacy TLS versions supported: TLS 1.0, TLS 1.1
- **Certificate Validation**: valid
- **Cipher Findings**: weak cipher suites detected in probed evidence
- **Policy**: modern (failed)

## Policy Failures

| Check | TLS Version | Message |
| --- | --- | --- |
| legacy-tls | TLS 1.0 | TLS 1.0 is supported; modern policy requires TLS 1.2 or newer |
| legacy-tls | TLS 1.1 | TLS 1.1 is supported; modern policy requires TLS 1.2 or newer |
| weak-cipher | TLS 1.0 | TLS 1.0 allows weak cipher TLS_RSA_WITH_AES_128_CBC_SHA |

## TLS Versions

| Version | Supported | Status | Certificate | Key Exchange | ALPN | Duration | Attempts |
| --- | --- | --- | --- | --- | --- | ---: | ---: |
| TLS 1.0 | yes | supported | valid | X25519 | - | 82 ms | 21 |
| TLS 1.1 | yes | supported | valid | X25519 | - | 75 ms | 21 |
| TLS 1.2 | yes | supported | valid | X25519 | h2 | 95 ms | 21 |
| TLS 1.3 | yes | supported | valid | X25519 | h2 | 44 ms | 4 |

## Cipher Suites

### TLS 1.0

- **Negotiated**: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
- **Discovery**: probed
- **Cipher Probe Duration**: 412 ms

| Cipher Suite | Classification |
| --- | --- |
| TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA | 🟠 WEAK (legacy CBC) |
| TLS_RSA_WITH_AES_128_CBC_SHA | 🟠 WEAK |

### TLS 1.2

- **Negotiated**: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- **Discovery**: probed
- **Cipher Probe Duration**: 521 ms

| Cipher Suite | Classification |
| --- | --- |
| TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 | 🟢 SECURE |
| TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | 🟢 SECURE |
| TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 | 🟢 MODERN |

### TLS 1.3

- **Negotiated**: TLS_AES_128_GCM_SHA256
- **Discovery**: raw-probed
- **Cipher Probe Duration**: 168 ms
- **Warning**: TLS 1.3 cipher suites were raw-probed with ClientHello-only handshakes; full TLS handshakes are not completed by the raw probe.

| Cipher Suite | Classification |
| --- | --- |
| TLS_AES_128_GCM_SHA256 | 🟢 MODERN |
| TLS_AES_256_GCM_SHA384 | 🟢 MODERN |
| TLS_CHACHA20_POLY1305_SHA256 | 🟢 MODERN |

#### Cipher Probe Results

Raw probe evidence is ClientHello-only. `clienthello-serverhello` and `clienthello-hrr-serverhello` evidence means the server selected a cipher in ServerHello, but the probe still does not complete a full TLS handshake.

| Cipher Suite | Status | Evidence | Group | HRR | Alert | Error |
| --- | --- | --- | --- | --- | --- | --- |
| TLS_AES_128_GCM_SHA256 | supported | clienthello-serverhello | X25519 | - | - | - |
| TLS_AES_256_GCM_SHA384 | supported | clienthello-serverhello | X25519 | - | - | - |
| TLS_CHACHA20_POLY1305_SHA256 | supported | clienthello-serverhello | X25519 | - | - | - |

## Certificate Details

### TLS 1.0, TLS 1.1
- **Subject CN**: example.com
- **Issuer**: Example RSA CA
- **Public Key**: RSA 2048-bit
- **Signature Algorithm**: SHA256-RSA
- **Valid From**: 2026-04-02
- **Valid To**: 2026-07-01
- **Days Until Expiry**: 45
- **Certificate Validation**: valid
- **Certificate Validation Details**: certificate validation passed
- **DNS Names**: example.com, *.example.com

### TLS 1.2, TLS 1.3
- **Subject CN**: example.com
- **Issuer**: Example ECC CA
- **Public Key**: ECDSA P-256 (256-bit)
- **Signature Algorithm**: ECDSA-SHA256
- **Valid From**: 2026-04-02
- **Valid To**: 2026-07-01
- **Days Until Expiry**: 45
- **Certificate Validation**: valid
- **Certificate Validation Details**: certificate validation passed
- **DNS Names**: example.com, *.example.com
