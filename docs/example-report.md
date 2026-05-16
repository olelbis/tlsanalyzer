# TLS Scan Report for host example.com:443

- **Generated At**: 2026-05-16T20:30:00Z
- **Scanner Version**: v0.8.4

## TLS Versions Supported
- ❌ TLS 1.0 (unsupported - remote error: tls: protocol version not supported)
- ❌ TLS 1.1 (unsupported - remote error: tls: protocol version not supported)
- ✅ TLS 1.2 (certificate: valid - certificate validation passed)
- ✅ TLS 1.3 (certificate: valid - certificate validation passed)

## Cipher Suites

### TLS 1.2 Supported Cipher Suites
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 🟢 SECURE
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 🟢 SECURE
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 🟢 MODERN

### TLS 1.3 Observed Cipher Suites
- TLS_AES_128_GCM_SHA256 🟢 MODERN
- TLS_AES_256_GCM_SHA384 🟢 MODERN
- TLS_CHACHA20_POLY1305_SHA256 🟢 MODERN

## Certificate Details

### TLS 1.2, TLS 1.3
- **Subject CN**: *.example.com
- **Issuer**: Example TLS CA
- **Valid From**: 2026-01-01
- **Valid To**: 2026-12-31
- **Days Until Expiry**: 229
- **Certificate Validation**: valid
- **Certificate Validation Details**: certificate validation passed
- **DNS Names**: *.example.com, example.com
