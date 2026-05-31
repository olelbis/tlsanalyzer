// Package tlsprobe provides a small raw TLS 1.3 ClientHello probe.
//
// The package is intentionally narrow: it can offer one TLS 1.3 cipher suite at
// a time, parse enough server response data to classify support, and return
// structured probe evidence. It can advertise a configurable supported key
// share group set and report selected group, HelloRetryRequest and TLS alert
// metadata when the server exposes them. It is not a general TLS stack and it
// does not complete full TLS handshakes.
//
// The API is public but still preview-level while edge-case fixtures and user
// feedback settle. Callers should treat status values, evidence level,
// CompletedHandshake and ErrorCode as the stable integration points and avoid
// depending on unstructured Result.Error text.
package tlsprobe
