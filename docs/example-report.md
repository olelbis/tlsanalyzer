# TLS Scan Report for host example.com:443

- **Generated At**: 2026-05-17T15:20:00Z
- **Scanner Version**: v0.9.3
- **JSON Schema Version**: 1.0

## Summary

- **Supported TLS Versions**: 4
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

| Version | Supported | Status | Certificate | Duration | Attempts |
| --- | --- | --- | --- | ---: | ---: |
| TLS 1.0 | yes | supported | valid | 82 ms | 21 |
| TLS 1.1 | yes | supported | valid | 75 ms | 21 |
| TLS 1.2 | yes | supported | valid | 95 ms | 21 |
| TLS 1.3 | yes | supported | valid | 44 ms | 11 |

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
- **Discovery**: observed
- **Cipher Probe Duration**: 168 ms
- **Warning**: TLS 1.3 cipher suites are observed from repeated handshakes; Go does not allow forcing individual TLS 1.3 cipher suites.

| Cipher Suite | Classification |
| --- | --- |
| TLS_AES_128_GCM_SHA256 | 🟢 MODERN |

## Certificate Details

### TLS 1.0, TLS 1.1
- **Subject CN**: example.com
- **Issuer**: Example RSA CA
- **Valid From**: 2026-04-02
- **Valid To**: 2026-07-01
- **Days Until Expiry**: 45
- **Certificate Validation**: valid
- **Certificate Validation Details**: certificate validation passed
- **DNS Names**: example.com, *.example.com

### TLS 1.2, TLS 1.3
- **Subject CN**: example.com
- **Issuer**: Example ECC CA
- **Valid From**: 2026-04-02
- **Valid To**: 2026-07-01
- **Days Until Expiry**: 45
- **Certificate Validation**: valid
- **Certificate Validation Details**: certificate validation passed
- **DNS Names**: example.com, *.example.com
