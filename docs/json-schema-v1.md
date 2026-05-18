# JSON Schema v1

This document describes the `schema_version: "1.1"` JSON output contract.

`tlsanalyzer --json` writes one JSON object to stdout. PEM certificate chains are never mixed into JSON stdout; `--json --cert` requires `--output`.

Single-target scans and batch scans share the same schema version but use different top-level shapes. Batch target entries embed the single-target object in their `report` field.

## Single-Target Top-Level Object

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `host` | string | yes | TCP host or IP address scanned. |
| `port` | string | yes | TCP port scanned. |
| `server_name` | string | no | TLS SNI and certificate validation name when `--sni` is used. |
| `schema_version` | string | yes | JSON schema version. Current value is `1.1`. |
| `scanner_version` | string | yes | Scanner version embedded at build time. |
| `generated_at` | string | yes | UTC RFC3339 timestamp for report generation. |
| `policy` | object | no | Policy result when `--policy` or `--fail-on` is used. |
| `results` | array | yes | Per-TLS-version scan results. |

## Batch Top-Level Object

`tlsanalyzer --targets-file targets.json --json` writes a batch object:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `schema_version` | string | yes | JSON schema version. Current value is `1.1`. |
| `scanner_version` | string | yes | Scanner version embedded at build time. |
| `generated_at` | string | yes | UTC RFC3339 timestamp for report generation. |
| `batch` | object | yes | Batch run metadata. |
| `targets` | array | yes | Per-target batch results. |

## Batch Metadata Object

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `target_count` | number | yes | Number of targets loaded from the target file. |
| `concurrency` | number | yes | Maximum concurrent target workers used by the run. |
| `retries` | number | yes | Retry count configured for transient network failures. |
| `retry_backoff` | string | yes | Linear retry backoff duration, for example `1s`. |

## Batch Target Object

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `host` | string | yes | TCP host or IP address scanned. |
| `port` | string | yes | TCP port scanned. |
| `server_name` | string | no | TLS SNI and certificate validation name when set. |
| `attempts` | number | yes | Full target scan attempts, including retries. |
| `exit_code` | number | yes | Per-target exit evidence: `0`, `1` or `3`. |
| `error` | string | no | Target-level setup or execution error when available. |
| `report` | object | yes | Embedded single-target JSON report for this target. |

## Result Object

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `version` | string | yes | TLS version label, for example `TLS 1.2`. |
| `version_id` | number | yes | Go TLS version ID. |
| `supported` | boolean | yes | Whether the TLS handshake succeeded. |
| `status` | string | yes | `supported`, `unsupported`, `timeout`, `handshake_error` or `network_error`. |
| `error_message` | string | no | Original scan error when the handshake did not succeed. |
| `duration_millis` | number | yes | Scan duration for the TLS version. |
| `handshake_attempts` | number | yes | Handshake attempts used for this result. |
| `key_exchange_group` | string | no | Negotiated key exchange group, for example `X25519`; omitted when unavailable or when legacy RSA key exchange does not expose a group. |
| `alpn_protocol` | string | no | Negotiated ALPN application protocol, for example `h2` or `http/1.1`. |
| `cipher_discovery` | string | yes | `negotiated`, `probed`, `raw-probed` or `observed`. |
| `negotiated_cipher_suite` | string | no | Cipher suite selected by the first successful handshake. |
| `cipher_suites` | array | no | Cipher suites discovered by the selected discovery mode. |
| `cipher_suites_observed` | boolean | yes | `true` when TLS 1.3 suites are observed rather than forced. |
| `cipher_probe_duration_millis` | number | no | Extra duration used for cipher probing or observation. |
| `cipher_probe_results` | array | no | Per-cipher raw probe statuses when available. |
| `raw_probe_completed_full_handshake` | boolean | no | `false` when `cipher_discovery` is `raw-probed`; raw probes stop after ServerHello, alert or another probe outcome. |
| `warnings` | array | no | Semantics warnings, such as TLS 1.3 observation limitations. |
| `certificate` | object | no | Leaf certificate details when available. |
| `certificate_validation_status` | string | no | `valid`, `invalid`, `skipped` or `unavailable`. |
| `certificate_validation_message` | string | no | Human-readable certificate validation detail. |

## Cipher Probe Result Object

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `cipher_suite` | string | yes | Cipher suite attempted by the raw probe. |
| `status` | string | yes | `supported`, `rejected`, `hello-retry-request`, `alert`, `timeout`, `closed` or `inconclusive`. |
| `evidence` | string | no | ClientHello-only evidence level, such as `clienthello-serverhello`, `clienthello-hrr-serverhello`, `clienthello-alert`, `clienthello-timeout`, `clienthello-closed` or `clienthello-inconclusive`. |
| `alert` | string | no | TLS alert level and description when the server returned an alert. |
| `alert_level` | number | no | Raw TLS alert level code when an alert is available. |
| `alert_description` | number | no | Raw TLS alert description code when an alert is available. |
| `selected_group` | string | no | Key share group selected by ServerHello or HelloRetryRequest when available. |
| `hello_retry_request` | boolean | no | Whether the server sent HelloRetryRequest. |
| `hello_retry_request_retried` | boolean | no | Whether the probe retried after HelloRetryRequest. |
| `error` | string | no | Probe error detail when the status is not supported. |

## Certificate Object

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `subject_common_name` | string | yes | Leaf certificate subject common name. |
| `issuer_common_name` | string | yes | Leaf certificate issuer common name. |
| `valid_from` | string | yes | RFC3339 certificate start time. |
| `valid_to` | string | yes | RFC3339 certificate expiration time. |
| `days_until_expiry` | number | yes | Days from `generated_at` to `valid_to`. |
| `public_key_algorithm` | string | no | Leaf certificate public key algorithm, for example `RSA`, `ECDSA` or `Ed25519`. |
| `public_key_bits` | number | no | Leaf certificate public key size in bits when available. |
| `public_key_curve` | string | no | Leaf certificate public key curve for elliptic-curve keys, for example `P-256`. |
| `signature_algorithm` | string | no | Leaf certificate signature algorithm, for example `SHA256-RSA` or `ECDSA-SHA256`. |
| `dns_names` | array | no | DNS SAN names from the certificate. |

## Policy Object

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `enabled` | boolean | yes | Whether policy evaluation was enabled. |
| `name` | string | no | Built-in policy name, such as `modern`. Empty custom policies omit this field. |
| `passed` | boolean | yes | Whether all enabled checks passed. |
| `failures` | array | no | Policy failure details. |

## Compatibility

Minor releases may add optional fields. Removing or renaming existing fields, changing field types or changing enum values requires a new schema version.
