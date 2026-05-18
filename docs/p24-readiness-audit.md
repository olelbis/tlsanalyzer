# P24 Readiness Audit

Date: 2026-05-19

This audit checks whether `tlsanalyzer` is ready to move from preview feature growth
to a more stable beta/v1 track, with special attention to the future public TLS
1.3 raw probe library.

## Verdict

`tlsanalyzer` is ready for a beta-hardening phase, but the raw probe should remain
internal until its public contract is deliberately frozen.

The CLI, reporting, policy, batch scanning and release pipeline are mature enough
for controlled operational use. The remaining risk is API stability: once the raw
probe is exported, names, statuses, errors and documented limitations become part
of the compatibility promise.

## Current Strengths

- Runtime code remains dependency-free and standard-library based.
- CLI behavior has stable exit codes, policy failure semantics and documented
  machine-readable output.
- JSON output has a documented schema version and conservative compatibility rules.
- Release assets include binaries, Linux packages, checksums, SBOM and artifact
  attestations.
- TLS support, certificate validation and cipher evidence are reported separately.
- TLS 1.3 cipher probing uses structured raw-probe evidence instead of pretending
  Go can force TLS 1.3 cipher suites through `crypto/tls`.
- The raw probe already has a small surface: `Options`, `Result`, `Status`,
  `ProbeTLS13CipherSuite`, `ProbeTLS13CipherSuites`, `SupportedTLS13CipherSuites`
  and `ValidateOptions`.

## P22 Blockers

These items should be resolved before publishing the raw probe as a public package
or separate module:

- Decide module shape: public package inside this module versus standalone module.
- Freeze status names and error semantics for long-term compatibility.
- Decide whether configuration errors should be typed errors instead of plain
  formatted errors.
- Document context and timeout behavior for connect, write and read operations.
- Document intentional parser limits, especially that the probe is ClientHello-only
  and does not aim to parse every possible fragmented TLS handshake.
- Add more malformed-record fixtures for record truncation, unsupported record
  types, rejected ServerHello and invalid HelloRetryRequest extension data.
- Decide whether public results should expose fields such as selected group,
  retry count, raw alert level/description and whether a HelloRetryRequest retry
  was attempted.
- Decide whether supported key share groups should be configurable or stay fixed
  to the current narrow probe set.

## P22 Recommendation

Keep the first public release conservative:

- Package scope: TLS 1.3 cipher probing only.
- Handshake scope: ClientHello-only evidence, no full TLS implementation.
- Dependency policy: Go standard library only.
- API style: small structs, string status constants, no callback-heavy design.
- Compatibility promise: additive fields only during `v0.x`; no `v1.0` until
  fixtures and edge-case semantics are stable.

## Acceptance Criteria For P22

- Public package or module location is chosen and documented.
- Go package documentation includes examples that do not require live internet.
- Status values and configuration errors are covered by tests.
- Parser fixture coverage includes supported, rejected, alert, timeout, closed,
  malformed and HelloRetryRequest paths.
- The CLI continues to consume the package without leaking CLI/reporting concepts
  into the probe API.
- Release notes explicitly mark the API as preview if it is still under `v0.x`.

## Follow-Up Backlog

- P22: extract or expose the raw TLS 1.3 probe API once the above blockers are
  resolved.
- v1 readiness: run one final compatibility audit for CLI flags, JSON schema,
  policy defaults and release artifact naming before declaring a stable `v1.0`.
