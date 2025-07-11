# sslscango

 [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
 [![OS - Linux](https://img.shields.io/badge/OS-Linux-blue?logo=linux&logoColor=white)](https://www.linux.org/ "Go to Linux homepage")
 [![OS - MacOS](https://img.shields.io/badge/OS-macOS-blue?logo=Apple&logoColor=white)](https://apple.com/ "Go to Apple homepage")
 

`sslscango` It is a utility that takes inspiration from the original `sslscan`, with fewer features, but with the aim of being used in those work contexts where it is not permitted to install anything on your machines, or where you are not allowed access to the internet network.

This is early development version.
## Roadmap:

- [x] Timeout flag
- [x] Print certificate chain
- [x] Certificate Expiration check
- [x] Save certificate chain on file
- [x] Fix ordered test (go range behaviour)
- [x] Check supported cipher
- [x] Add the minimum version to start the scan from
- [ ] Full build (shell)script

 ## Building from source

If you want to build `sslscango` from source, please verify to have already installed **go1.23.4** or higher.

Then run this command:

```bash
go build -v -ldflags="-X 'github.com/olelbis/sslscango/build.Version=$(cat VERSION)' -X 'github.com/olelbis/sslscango/build.BuildUser=Team sslscango' -X 'github.com/olelbis/sslscango/build.BuildTime=$(date)'" -o sslscango
```
 
 ## How it works

Usage:
```bash
Usage: sslscango [--cert] [--checkcert] --host <host> [--port <portnumber>] [--timeout <sec>] [--output <file>] [--min-version 1.0|1.1|1.2|1.3]
```

Basic execution:

```bash
olelbis@mymachost sslscango % sslscango --host example.com                        

TLS Analisys for: [example.com:443]

🚫 TLS 1.0: unsupported

🚫 TLS 1.1: unsupported

✅ TLS 1.2: supported
   Cipher suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
   CN: *.example.com
   Issuer: DigiCert Global G3 TLS ECC SHA384 2020 CA1
   Valid: 2025-01-15T00:00:00Z - 2026-01-15T23:59:59Z
   DNS: [*.example.com example.com]
   Supported cipher suites:
     • TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
     • TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
     • TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305

✅ TLS 1.3: supported
   Cipher suite: TLS_AES_256_GCM_SHA384
   CN: *.example.com
   Issuer: DigiCert Global G3 TLS ECC SHA384 2020 CA1
   Valid: 2025-01-15T00:00:00Z - 2026-01-15T23:59:59Z
   DNS: [*.example.com example.com]
   Supported cipher suites:
     • TLS_RSA_WITH_AES_128_CBC_SHA
     • TLS_RSA_WITH_AES_256_CBC_SHA
     • TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
     • TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
     • TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
     • TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
     • TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
     • TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
     • TLS_AES_256_GCM_SHA384
   ```