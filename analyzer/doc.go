// Package analyzer coordinates TLS version scans and policy evaluation for one
// target.
//
// It is the reusable core behind the command-line interface. The package keeps
// progress reporting optional through hooks so callers can build CLI, batch or
// library workflows on top of the same scan orchestration.
//
// Callers can start with DefaultOptions and then override the fields they need:
//
//	opts := analyzer.DefaultOptions("example.com")
//	opts.MinVersion = tls.VersionTLS12
//	result, err := analyzer.Run(opts, analyzer.Hooks{})
//
// Run returns scan evidence even when a target does not support a requested TLS
// version. It only returns an error for caller hook failures; operational scan
// failures are represented in Result.Results with scan statuses such as
// network_error, timeout and handshake_error.
package analyzer
