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
| Policy checks | Built-in check names, including `baseline` and `require-pq`, and policy failure exit behavior are preserved. |
| Report separation | TLS protocol support remains separate from certificate validation status. |
| Evidence labels | Raw-probed, observed and negotiated evidence, and the `clienthello-serverhello` version and cipher evidence, remain explicitly labeled. |
| Baseline input | `--baseline` reads an ordinary `--json` report. A report with a different JSON schema major version is an input error (exit 1), never a silent pass. |
| Runtime dependency model | The released CLI remains dependency-free at runtime. |

Single-target input validation may report multiple input errors in one
invocation, but the exit code contract remains unchanged.

TLS capability handshakes intentionally disable Go's built-in certificate
verification so protocol and cipher evidence is not confused with certificate
trust. Certificate validation is performed and reported separately unless
`--skip-verify` is explicitly requested.

## Allowed Preview Changes

Minor `v0.x` releases may:

- add optional JSON fields;
- add CLI flags with default-off behavior;
- add new policy checks when they do not change existing defaults;
- improve wording in human-readable output;
- improve raw probe evidence without claiming full-handshake support;
- extend what `--baseline` treats as a regression only when security gets worse;
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
- presenting raw probe evidence (TLS 1.0 to 1.3 versions and cipher suites, or key exchange groups) as a completed full TLS handshake.

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
