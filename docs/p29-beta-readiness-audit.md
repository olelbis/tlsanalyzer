# P29 Beta-Readiness Audit

Date: 2026-05-31

This audit checks whether `tlsanalyzer` is ready to move from preview
stabilization toward a beta decision without adding new product features.

## Verdict

`tlsanalyzer` is beta-candidate quality for controlled operational use and CI
policy gates.

No blocking beta-readiness issues were found. The fixes from this audit are
documentation and contract hardening only.

## Audit Scope

| Area | Result |
| --- | --- |
| CLI flags | User manual matches the implemented flag set. The man page was missing `--timeout` and was corrected. |
| Exit codes | The `0`, `1`, `2` and `3` contract is documented and covered by focused tests. |
| JSON schema v1 | Current single-target and batch fields are documented. Policy failure fields were clarified. |
| Policy behavior | Built-in and configurable policy gates remain conservative and documented. |
| TLS 1.3 evidence | Raw-probed, observed and negotiated evidence remain explicitly separated. |
| Public Go packages | `analyzer`, `tlsprobe`, `output`, `policy` and `scan` now have package-level documentation. |
| Release assets | Binary, package, SBOM, checksum, attestation and container naming remains stable. |
| Real-world validation | The validation script now asserts the exact expected scanner version. |

## Fixes Applied

- Added package documentation for `output`, `policy` and `scan`.
- Documented JSON policy failure objects.
- Clarified that JSON `policy` output is emitted for any enabled policy gate.
- Added `--timeout` to the man page.
- Tightened real-world validation to check the exact scanner version from
  `VERSION`.

## Remaining Non-Blocking Work

- Decide when to tag the first explicit beta release.
- Run at least one more real-world validation pass after external usage
  feedback.
- Decide whether the future public library API should live in this module or in
  a separate module.
- Before `v1.0.0`, run a final breaking-change audit for CLI flags, JSON schema
  fields, policy check names, public Go packages and release asset names.
