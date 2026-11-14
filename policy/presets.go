package policy

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/olelbis/tlsanalyzer/scan"
)

// Mozilla Server Side TLS presets.
//
// NameMozillaModern and NameMozillaIntermediate follow the Modern and
// Intermediate configurations of the Mozilla Server Side TLS guidelines,
// version 6.0 (https://wiki.mozilla.org/Security/Server_Side_TLS). The Old
// configuration was removed from the guidelines in 6.0 and has no preset.
//
// They are separate from NameModern: that preset is tlsanalyzer's own baseline
// (TLS 1.2 or newer, no weak ciphers, a valid certificate) and keeps its
// meaning. Only the parts of a guideline that a client-side scan can observe
// are checked: protocol versions, TLS 1.2 cipher suites, the certificate key
// type and size, and the certificate lifespan. Server cipher preference order,
// HSTS, OCSP stapling and the key exchange groups are not checked; use
// --require-pq for the post-quantum group.
const (
	NameMozillaModern       = "mozilla-modern"
	NameMozillaIntermediate = "mozilla-intermediate"

	// CheckCertKey fails when the certificate key type or size is not one the
	// preset allows. It is only enabled by the Mozilla presets.
	CheckCertKey = "cert-key"
	// CheckCertLifespan fails when the certificate was issued for longer than
	// the preset allows (NotAfter minus NotBefore).
	CheckCertLifespan = "cert-lifespan"
	// CheckCipherAllowlist fails when TLS 1.2 accepts a cipher suite that the
	// preset does not list.
	CheckCipherAllowlist = "cipher-allowlist"
)

// Names returns the built-in policy names.
func Names() []string {
	return []string{NameModern, NameMozillaModern, NameMozillaIntermediate}
}

// IsKnownName reports whether name is a built-in policy.
func IsKnownName(name string) bool {
	for _, known := range Names() {
		if name == known {
			return true
		}
	}
	return false
}

func isMozillaPreset(name string) bool {
	return name == NameMozillaModern || name == NameMozillaIntermediate
}

// presetTLSVersions returns the TLS versions a preset requires and forbids.
func presetTLSVersions(name string) (required, forbidden []uint16) {
	if name == NameMozillaModern {
		return []uint16{tls.VersionTLS13}, []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12}
	}
	return nil, nil
}

// expand returns config with the explicit gates a preset stands for filled in,
// so the rest of the package only has to deal with explicit fields. The
// caller's slices are not modified.
func expand(config Config) Config {
	required, forbidden := presetTLSVersions(config.Name)
	if len(required) == 0 && len(forbidden) == 0 {
		return config
	}
	config.RequiredTLSVersions = mergeVersions(config.RequiredTLSVersions, required)
	config.ForbiddenTLSVersions = mergeVersions(config.ForbiddenTLSVersions, forbidden)
	return config
}

func mergeVersions(existing, extra []uint16) []uint16 {
	merged := append([]uint16(nil), existing...)
	for _, version := range extra {
		if !containsTLSVersion(merged, version) {
			merged = append(merged, version)
		}
	}
	return merged
}

// validatePresetConflicts rejects explicit gates that contradict the preset,
// with a message that names the preset instead of a bare overlap.
func validatePresetConflicts(config Config) error {
	required, forbidden := presetTLSVersions(config.Name)
	for _, version := range config.RequiredTLSVersions {
		if containsTLSVersion(forbidden, version) {
			return fmt.Errorf("policy %s forbids %s, so it cannot also be required", config.Name, tlsVersionName(version))
		}
	}
	for _, version := range config.ForbiddenTLSVersions {
		if containsTLSVersion(required, version) {
			return fmt.Errorf("policy %s requires %s, so it cannot also be forbidden", config.Name, tlsVersionName(version))
		}
	}
	return nil
}

// mozillaIntermediateTLS12 is the TLS 1.2 cipher suite list of the Mozilla
// Intermediate configuration, 6.0. The ChaCha20 suites appear under both names
// because Go and the IANA registry spell them differently.
var mozillaIntermediateTLS12 = map[string]bool{
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       true,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         true,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       true,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         true,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": true,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   true,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":        true,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":          true,
}

// maxCertLifespanDays is the longest certificate lifespan a preset allows:
// 90 days for Modern, and the 366-day ceiling for Intermediate.
func maxCertLifespanDays(name string) int {
	switch name {
	case NameMozillaModern:
		return 90
	case NameMozillaIntermediate:
		return 366
	}
	return 0
}

func cipherAllowlistFailure(r scan.TLSScanResult, cipher string) (Failure, bool) {
	if r.VersionID != tls.VersionTLS12 || mozillaIntermediateTLS12[cipher] {
		return Failure{}, false
	}
	return Failure{
		Check:   CheckCipherAllowlist,
		Version: r.Version,
		Message: fmt.Sprintf("%s allows cipher %s, which the %s preset does not list", r.Version, cipher, NameMozillaIntermediate),
	}, true
}

// certKeyFailure judges the certificate public key. Modern asks for ECDSA
// (P-256 or larger); Intermediate accepts ECDSA (P-256 or larger) or RSA of at
// least 2048 bits. Other key types are not in the guideline and fail.
func certKeyFailure(r scan.TLSScanResult, name string) (Failure, bool) {
	algorithm, bits := certificatePublicKeyMetadata(r.Certificate)
	want := "an ECDSA key (P-256 or larger)"
	if name == NameMozillaIntermediate {
		want = "an ECDSA key (P-256 or larger) or an RSA key of at least 2048 bits"
	}
	if bits == 0 {
		return Failure{
			Check:   CheckCertKey,
			Version: r.Version,
			Message: fmt.Sprintf("%s certificate public key is unavailable; the %s preset requires %s", r.Version, name, want),
		}, true
	}
	switch {
	case algorithm == "ECDSA" && bits >= 256:
		return Failure{}, false
	case algorithm == "RSA" && bits >= 2048 && name == NameMozillaIntermediate:
		return Failure{}, false
	}
	return Failure{
		Check:   CheckCertKey,
		Version: r.Version,
		Message: fmt.Sprintf("%s certificate public key is %s %d-bit; the %s preset requires %s", r.Version, algorithm, bits, name, want),
	}, true
}

// certLifespanFailure compares the issued lifespan (NotAfter minus NotBefore)
// with the preset ceiling. Whole days are compared, rounded down, so the one
// hour some CAs backdate NotBefore does not turn a 90-day certificate into a
// failure.
func certLifespanFailure(r scan.TLSScanResult, name string) (Failure, bool) {
	maxDays := maxCertLifespanDays(name)
	if maxDays == 0 {
		return Failure{}, false
	}
	if r.Certificate == nil {
		return Failure{
			Check:   CheckCertLifespan,
			Version: r.Version,
			Message: fmt.Sprintf("%s certificate lifespan is unavailable; the %s preset allows at most %d days", r.Version, name, maxDays),
		}, true
	}
	days := int(r.Certificate.NotAfter.Sub(r.Certificate.NotBefore) / (24 * time.Hour))
	if days > maxDays {
		return Failure{
			Check:   CheckCertLifespan,
			Version: r.Version,
			Message: fmt.Sprintf("%s certificate lifespan is %d days; the %s preset allows at most %d days", r.Version, days, name, maxDays),
		}, true
	}
	return Failure{}, false
}

func legacyTLSMessage(name, version string) string {
	if name == NameMozillaIntermediate {
		return fmt.Sprintf("%s is supported; %s requires TLS 1.2 or newer", version, name)
	}
	return fmt.Sprintf("%s is supported; modern policy requires TLS 1.2 or newer", version)
}
