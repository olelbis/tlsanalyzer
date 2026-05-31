---
name: Endpoint compatibility report
about: Share real-world endpoint behavior, false positives or false negatives
title: "Endpoint compatibility: "
labels: compatibility, feedback
assignees: ""
---

## Endpoint

- Host:
- Port:
- SNI, if different from host:
- Public endpoint: yes / no

## Command

```bash
tlsanalyzer --host example.com --sni example.com --json
```

## Result

Paste the relevant output or attach the generated report. Redact private hostnames,
IP addresses or certificate details if needed.

## What looked wrong or surprising?

Examples:

- TLS version support did not match another scanner.
- TLS 1.3 raw-probe evidence looked inconclusive or inconsistent.
- Certificate validation looked wrong.
- Policy checks failed or passed unexpectedly.
- JSON fields were hard to consume.

## Comparison, if available

Mention any other scanner, browser, OpenSSL command or monitoring tool used for
comparison.

## Environment

- tlsanalyzer version:
- OS and architecture:
- Installation method:
