// Package output renders tlsanalyzer scan evidence into human-readable and
// machine-readable reports.
//
// The package contains helpers for console summaries, Markdown reports, JSON
// schema v1 reports, SARIF and JUnit XML. It is used by the CLI and batch
// runner, and can be reused by callers that already have scan.TLSScanResult
// values and optional policy results.
//
// JSON output follows the documented schema_version contract. Human-readable
// wording may evolve during preview releases, while JSON field removals,
// renames or type changes require a schema version change.
package output
