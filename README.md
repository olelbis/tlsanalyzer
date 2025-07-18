# tlsanalyzer

 [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
 [![OS - Linux](https://img.shields.io/badge/OS-Linux-blue?logo=linux&logoColor=white)](https://www.linux.org/ "Go to Linux homepage")
 [![OS - MacOS](https://img.shields.io/badge/OS-macOS-blue?logo=Apple&logoColor=white)](https://apple.com/ "Go to Apple homepage")
 

`tlsanalyzer` It is a utility that takes inspiration from the original `sslscan`, with fewer features, but with the aim of being used in those work contexts where it is not permitted to install anything on your machines, or where you are not allowed access to the internet network.

This is early development version.
## Roadmap:

- [x] Timeout flag
- [x] Print certificate chain
- [x] Certificate Expiration check
- [x] Save certificate chain on file
- [x] Fix ordered test (go range behaviour)
- [x] Check supported cipher
- [x] Add the minimum version to start the scan from
- [x] Improved performance (goroutines)
- [x] Export report in markdown
- [x] Project name change
- [x] Github action for multiarch release
- [x] force-cipher flag added to check all supported cipher
- [ ] Full build (shell)script

 ## Building from source

If you want to build `tlsanalyzer` from source, please verify to have already installed **go1.23.4** or higher.

Then run this command:

```bash
go build -v -ldflags="-X 'github.com/olelbis/tlsanalyzer/build.Version=$(cat VERSION)' -X 'github.com/olelbis/tlsanalyzer/build.BuildUser=Team tlsanalyzer' -X 'github.com/olelbis/tlsanalyzer/build.BuildTime=$(date)'" -o tlsanalyzer
```
 
 ## How it works

Usage:
```bash
Mandatory flags:
  --host string Hostname or server IP to scan

Optional flags:
  -cert
        Print cerificate chain
  -checkcert
        Check if the certificate is about to expire
  -force-ciphers
        Force all cipher suites during version scan
  -host string
        Hostname or server IP (mandatory)
  -markdown string
        Write scan result to markdown file
  -min-version string
        Minimum TLS version to test (1.0, 1.1, 1.2, 1.3) (default "1.0")
  -output string
        File to save the PEM output to (optional), only used with --cert
  -port string
        TLS server port (default "443")
  -timeout int
        Connection Timeout (default 5)
```

Basic execution:

```bash
olelbis@mymachost tlsanalyzer % tlsanalyzer --host example.com                        

TLS Analisys for: [example.com:443]

👉 Trying TLS version TLS 1.0
❌ Handshake failed: remote error: tls: protocol version not supported

🚫 TLS 1.0: unsupported

👉 Trying TLS version TLS 1.1
❌ Handshake failed: remote error: tls: protocol version not supported

🚫 TLS 1.1: unsupported

👉 Trying TLS version TLS 1.2

✅ TLS 1.2: supported
   Negotiated Cipher suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
   CN: *.example.com
   Issuer: DigiCert Global G3 TLS ECC SHA384 2020 CA1
   Valid: 2025-01-15T00:00:00Z - 2026-01-15T23:59:59Z
   DNS: [*.example.com example.com]
   Supported cipher suites:
     • TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
     • TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
     • TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305

👉 Trying TLS version TLS 1.3

✅ TLS 1.3: supported
   Negotiated Cipher suite: TLS_AES_256_GCM_SHA384
   CN: *.example.com
   Issuer: DigiCert Global G3 TLS ECC SHA384 2020 CA1
   Valid: 2025-01-15T00:00:00Z - 2026-01-15T23:59:59Z
   DNS: [*.example.com example.com]
   Supported cipher suites:
     • TLS_AES_128_GCM_SHA256
     • TLS_AES_256_GCM_SHA384
     • TLS_CHACHA20_POLY1305_SHA256
   ```