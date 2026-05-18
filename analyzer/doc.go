// Package analyzer coordinates TLS version scans and policy evaluation for one
// target.
//
// It is the reusable core behind the command-line interface. The package keeps
// progress reporting optional through hooks so callers can build CLI, batch or
// library workflows on top of the same scan orchestration.
package analyzer
