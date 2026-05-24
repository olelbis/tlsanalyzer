# Compatibility Policy

`tlsanalyzer` is still preview software, but it now treats the main automation
surfaces as compatibility contracts.

This page describes what users can rely on during the `v0.x` line and what must
change before a future `v1.0.0`.

## Stable Preview Contracts

The following contracts are intended to stay compatible across minor preview
releases unless a changelog entry explicitly calls out a breaking change.

| Surface | Compatibility promise |
| --- | --- |
| CLI exit codes | `0`, `1`, `2` and `3` keep their documented meanings. |
| JSON schema v1 | Existing documented fields, types and enum meanings are preserved. |
| Policy checks | Built-in check names and policy failure exit behavior are preserved. |
| Report separation | TLS protocol support remains separate from certificate validation status. |
| TLS 1.3 evidence labels | Raw-probed, observed and negotiated evidence remain explicitly labeled. |
| Runtime dependency model | The released CLI remains dependency-free at runtime. |

## Allowed Preview Changes

Minor `v0.x` releases may:

- add optional JSON fields;
- add CLI flags with default-off behavior;
- add new policy checks when they do not change existing defaults;
- improve wording in human-readable output;
- improve raw TLS 1.3 evidence without claiming full-handshake support;
- add release artifacts, documentation or validation checks.

Patch releases should be limited to bug fixes, documentation corrections and
compatibility-preserving hardening.

## Breaking Changes

The following changes require either a new JSON schema version, a clearly marked
breaking preview release or a future `v1.0.0` compatibility decision:

- removing or renaming documented JSON fields;
- changing documented JSON field types;
- changing documented enum values without keeping the old meaning;
- changing the meaning of CLI exit codes;
- changing `--policy modern` defaults in a way that makes previous passes fail
  for reasons unrelated to better evidence;
- mixing certificate PEM output into JSON stdout;
- presenting TLS 1.3 raw probe evidence as a completed full TLS handshake.

## Exit Codes

| Code | Meaning |
| ---: | --- |
| 0 | Scan completed successfully and enabled policy checks passed. |
| 1 | Invalid input, scan setup failure, report write failure, certificate output failure or target-level scan execution failure. |
| 2 | CLI flag parsing failed. |
| 3 | Scan completed but enabled policy checks failed. |

## v1 Readiness Gate

Before a future `v1.0.0`, run one final compatibility audit covering:

- CLI flag names, defaults and exit behavior;
- JSON schema fields, enum values and batch shape;
- policy check names, defaults and failure messages;
- public Go package names and exported types;
- release asset names and package metadata.
