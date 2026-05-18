// Package tlsprobe provides a small raw TLS 1.3 ClientHello probe.
//
// The package is intentionally narrow: it can offer one TLS 1.3 cipher suite at
// a time, parse enough server response data to classify support, and return
// structured probe evidence. It is not a general TLS stack and it does not
// complete full TLS handshakes.
//
// This package is internal while the API matures, but its exported surface is
// kept small enough to make future extraction into a standalone module
// practical.
package tlsprobe
