# P24 Readiness Audit

Date: 2026-05-19

This audit checks whether `tlsanalyzer` is ready to move from preview feature growth
to a more stable beta/v1 track, with special attention to the future public TLS
1.3 raw probe library.

## Verdict

`tlsanalyzer` is ready for a beta-hardening phase. The raw probe can be exposed
as a conservative preview package in this module, while a standalone module
should wait until the API has user feedback.

The CLI, reporting, policy, batch scanning and release pipeline are mature enough
for controlled operational use. The remaining risk is long-term API stability:
names, statuses, errors and documented limitations are now part of the preview
compatibility promise.

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
- The raw probe has a small public surface: `Options`, `Result`, `Status`,
  `ConfigError`,
  `ProbeTLS13CipherSuite`, `ProbeTLS13CipherSuites`, `SupportedTLS13CipherSuites`
  and `ValidateOptions`.

## P22 Decisions

P22 resolved the first public shape as follows:

- Package shape: public package inside this module at `github.com/olelbis/tlsanalyzer/tlsprobe`.
- Module shape: no standalone module yet.
- Configuration errors: typed `*tlsprobe.ConfigError`.
- Status values: public string constants are the automation contract.
- Result errors: human-readable diagnostics, not a stable parsing contract.
- Probe limits: TLS 1.3 only, ClientHello-only, no full TLS handshake completion.
- Key share groups: fixed to the narrow current set for the first preview.

## Remaining Library Work

Keep future raw-probe-library work conservative:

- Add fixtures for more legal TLS fragmentation shapes.
- Decide whether public results should expose selected group, retry count, raw
  alert level/description and HelloRetryRequest retry metadata.
- Decide whether supported key share groups should become configurable.
- Consider a standalone module after at least one or two preview releases.

## Acceptance Criteria For P22

- Public package location is chosen and documented.
- Go package documentation includes examples that do not require live internet.
- Status values and configuration errors are covered by tests.
- Parser fixture coverage includes supported, rejected, alert, timeout, closed,
  malformed and HelloRetryRequest paths.
- The CLI consumes the package without leaking CLI/reporting concepts into the
  probe API.
- Release notes explicitly mark the API as preview while it remains under `v0.x`.

## Follow-Up Backlog

- v1 readiness: run one final compatibility audit for CLI flags, JSON schema,
  policy defaults and release artifact naming before declaring a stable `v1.0`.
