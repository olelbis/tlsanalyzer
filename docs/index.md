# tlsanalyzer documentation

<div class="doc-hero">
  <img src="assets/tlsanalyzer-logo.png" alt="tlsanalyzer pixel art logo" width="168">
  <p class="doc-kicker">Dependency-free TLS inspection CLI</p>
  <p class="doc-lead">
    Inspect TLS protocol support, negotiated and probed cipher evidence,
    certificate trust, CI policy gates and machine-readable reports from a
    small Go binary with no runtime dependencies.
  </p>
  <p class="doc-badges">
    <a href="https://github.com/olelbis/tlsanalyzer/releases/latest">Latest release</a>
    <a href="https://github.com/olelbis/tlsanalyzer">GitHub</a>
    <a href="https://pkg.go.dev/github.com/olelbis/tlsanalyzer/tlsprobe">Go package docs</a>
  </p>
</div>

<div class="notice">
  <strong>Project status:</strong> preview maintenance on the <code>v0.25.x</code>
  line. Feature growth is paused; patch releases are limited to bug fixes,
  documentation updates and compatibility-preserving hardening while the project
  gathers real-world usage before a future beta/v1 decision.
</div>

## Quick Start

```bash
tlsanalyzer --host example.com
tlsanalyzer --host example.com --policy modern
tlsanalyzer --host example.com --json
tlsanalyzer --host example.com --markdown example.com.md
```

Container image:

```bash
docker run --rm ghcr.io/olelbis/tlsanalyzer:v0.25.1 --host example.com --no-clear
```

## Documentation Map

<div class="doc-grid">
  <a class="doc-card" href="user-manual.html">
    <span>User manual</span>
    Installation, CLI flags, config files, batch scans, reports and policy checks.
  </a>
  <a class="doc-card" href="json-schema-v1.html">
    <span>JSON schema v1</span>
    Stable machine-readable output for single-target and batch scans.
  </a>
  <a class="doc-card" href="tlsprobe-package.html">
    <span>TLS probe package</span>
    Preview Go API for ClientHello-only TLS 1.3 cipher evidence.
  </a>
  <a class="doc-card" href="example-report.html">
    <span>Sample report</span>
    Human-readable Markdown report with TLS 1.3 raw-probe evidence.
  </a>
  <a class="doc-card" href="p24-readiness-audit.html">
    <span>Readiness audit</span>
    Current beta/v1 posture, known limits and remaining decisions.
  </a>
</div>

## What It Reports

| Area | Evidence |
| --- | --- |
| TLS protocol support | TLS 1.0 through TLS 1.3 support, status and attempt duration. |
| Cipher suites | Negotiated, probed, raw-probed or observed cipher evidence depending on TLS version and scan mode. |
| TLS 1.3 raw probes | ClientHello-only ServerHello evidence with selected key share group, HelloRetryRequest and alert metadata. |
| Certificates | Trust status, issuer, subject, SANs, expiry, public key and signature details. |
| CI policy | Exit codes, modern policy checks, SARIF output and JUnit XML output. |

## Release Artifacts

Each release publishes:

- Linux, macOS and Windows binaries for amd64 and arm64.
- Debian and RPM packages for Linux amd64 and arm64.
- Multi-arch container images on GitHub Container Registry.
- Checksums, SBOM and GitHub artifact attestations.

## TLS 1.3 Note

Go's standard TLS API does not allow a caller to force individual TLS 1.3 cipher
suites in a full handshake. `tlsanalyzer` therefore uses a minimal raw
ClientHello probe when cipher probing is enabled. Reports label this evidence
explicitly as ClientHello-only and do not claim full-handshake completion for
raw TLS 1.3 probes.
