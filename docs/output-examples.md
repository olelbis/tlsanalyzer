# Output examples

These examples show how to read `tlsanalyzer` evidence. They are intentionally
small and focus on semantics rather than copying every field from a full scan.

## Console

Normal verbose output reports the cipher suite selected in the handshake:

```text
✅ TLS 1.3: supported
   Negotiated cipher suite (selected in this handshake): TLS_AES_128_GCM_SHA256
   Certificate validation: valid
   Key Exchange Group: X25519MLKEM768
   ALPN: h2
```

That line means the server and client selected that cipher for this specific
handshake. It does not mean the server supports only that cipher suite.

When cipher probing is enabled, additional evidence is shown separately:

```text
Raw-probed cipher suites (ClientHello-only support evidence):
  • TLS_AES_128_GCM_SHA256
  • TLS_AES_256_GCM_SHA384
  • TLS_CHACHA20_POLY1305_SHA256
```

For TLS 1.3 this is ClientHello-only ServerHello evidence. It confirms that the
server selected the offered cipher suite, but the raw probe does not complete a
full TLS handshake.

## JSON

JSON output is the best format for automation:

```json
{
  "schema_version": "1.1",
  "scanner_version": "v0.28.0",
  "host": "example.com",
  "port": "443",
  "results": [
    {
      "version": "TLS 1.3",
      "supported": true,
      "status": "supported",
      "negotiated_cipher_suite": "TLS_AES_128_GCM_SHA256",
      "cipher_discovery": "raw-probed",
      "cipher_suites": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256"
      ],
      "cipher_probe_results": [
        {
          "cipher_suite": "TLS_AES_128_GCM_SHA256",
          "status": "supported",
          "evidence": "clienthello-serverhello",
          "selected_group": "X25519"
        }
      ],
      "certificate_validation_status": "valid"
    }
  ]
}
```

Important fields:

| Field | Meaning |
| --- | --- |
| `negotiated_cipher_suite` | Cipher selected by the normal TLS handshake. |
| `cipher_discovery` | Evidence mode: `negotiated`, `probed`, `raw-probed` or `observed`. |
| `cipher_suites` | Cipher suites found under the evidence mode. |
| `cipher_probe_results[].evidence` | Raw TLS 1.3 ClientHello evidence level. |
| `certificate_validation_status` | Certificate trust status, separate from protocol support. |

## Markdown

Markdown reports are intended for review and tickets. Use them when a human
needs a persistent scan artifact:

```bash
tlsanalyzer --host example.com --policy modern --markdown example.com.md
```

The report contains:

- a summary with protocol, certificate and cipher findings;
- a TLS version table;
- cipher evidence grouped by TLS version;
- policy failures when policy mode is enabled;
- certificate details grouped by identical certificate.

## CI Reports

Use SARIF for security dashboards and JUnit XML for CI test result views:

```bash
tlsanalyzer --host example.com --policy modern --sarif tls.sarif --junit tls.xml
```

SARIF contains policy findings and scan execution errors. JUnit contains one
testcase per scanned TLS version, with scan errors reported as errors and policy
failures reported as failures.
