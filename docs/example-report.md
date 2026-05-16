# TLS Scan Report for host example.com:443

- **Generated At**: 2026-05-16T21:12:22Z
- **Scanner Version**: v0.8.7

## TLS Versions Supported
- ✅ TLS 1.0 (certificate: valid - certificate validation passed)
- ✅ TLS 1.1 (certificate: valid - certificate validation passed)
- ✅ TLS 1.2 (certificate: valid - certificate validation passed)
- ✅ TLS 1.3 (certificate: valid - certificate validation passed)

## Cipher Suites

### TLS 1.0 Supported Cipher Suites
- TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA 🟡 ACCEPTABLE
- TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA 🟡 ACCEPTABLE
- TLS_RSA_WITH_3DES_EDE_CBC_SHA 🔴 INSECURE
- TLS_RSA_WITH_AES_128_CBC_SHA 🟠 WEAK
- TLS_RSA_WITH_AES_256_CBC_SHA 🟠 WEAK

### TLS 1.1 Supported Cipher Suites
- TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA 🟡 ACCEPTABLE
- TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA 🟡 ACCEPTABLE
- TLS_RSA_WITH_AES_128_CBC_SHA 🟠 WEAK
- TLS_RSA_WITH_AES_256_CBC_SHA 🟠 WEAK

### TLS 1.2 Supported Cipher Suites
- TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA 🟡 ACCEPTABLE
- TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 🟢 SECURE
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 🟢 SECURE
- TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA 🟡 ACCEPTABLE
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 🟢 SECURE
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 🟢 MODERN
- TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA 🟡 ACCEPTABLE
- TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 🟢 SECURE
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 🟢 SECURE
- TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA 🟡 ACCEPTABLE
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 🟢 SECURE
- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 🟢 MODERN
- TLS_RSA_WITH_AES_128_CBC_SHA 🟠 WEAK
- TLS_RSA_WITH_AES_128_CBC_SHA256 🟠 WEAK
- TLS_RSA_WITH_AES_128_GCM_SHA256 🟢 SECURE
- TLS_RSA_WITH_AES_256_CBC_SHA 🟠 WEAK
- TLS_RSA_WITH_AES_256_GCM_SHA384 🟢 SECURE

### TLS 1.3 Observed Cipher Suites
- TLS_AES_128_GCM_SHA256 🟢 MODERN

## Certificate Details

### TLS 1.0, TLS 1.1
- **Subject CN**: example.com
- **Issuer**: Cloudflare TLS Issuing RSA CA 1
- **Valid From**: 2026-04-02
- **Valid To**: 2026-07-01
- **Days Until Expiry**: 46
- **Certificate Validation**: valid
- **Certificate Validation Details**: certificate validation passed
- **DNS Names**: example.com, *.example.com

### TLS 1.2, TLS 1.3
- **Subject CN**: example.com
- **Issuer**: Cloudflare TLS Issuing ECC CA 1
- **Valid From**: 2026-04-02
- **Valid To**: 2026-07-01
- **Days Until Expiry**: 46
- **Certificate Validation**: valid
- **Certificate Validation Details**: certificate validation passed
- **DNS Names**: example.com, *.example.com
