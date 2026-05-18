// Package tlsprobe provides a small raw TLS 1.3 ClientHello probe.
//
// The package is intentionally narrow: it can offer one TLS 1.3 cipher suite at
// a time, parse enough server response data to classify support, and return
// structured probe evidence. It is not a general TLS stack and it does not
// complete full TLS handshakes.
//
// The API is public but still preview-level while edge-case fixtures and user
// feedback settle. Callers should treat status values as the stable integration
// point and avoid depending on unstructured Result.Error text.
package tlsprobe
