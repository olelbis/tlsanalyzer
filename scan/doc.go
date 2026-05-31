// Package scan performs TLS handshakes for individual protocol versions and
// returns structured evidence.
//
// The package reports protocol support, scan status, negotiated cipher suite,
// optional cipher probe evidence, certificate validation status, ALPN and key
// exchange metadata. Operational failures such as network errors, timeouts and
// handshake errors are represented as statuses instead of process exits.
package scan
