// Package policy evaluates TLS scan evidence against built-in and configurable
// policy gates.
//
// The modern policy is intentionally conservative: legacy protocol support,
// weak or unclassified cipher evidence, invalid certificates and expired
// certificates fail the policy. Callers can also require or forbid TLS versions
// and ALPN protocols, and can enforce minimum certificate key size or validity
// windows.
//
// Policy results are structured so CLI, JSON, SARIF and JUnit output can share
// the same failure evidence.
package policy
