package utils

import (
	"crypto/tls"
	"sort"
	"strings"
)

type CipherSuite struct {
	ID   uint16
	Name string
}

type CipherSeverity string

const (
	CipherSeverityInsecure   CipherSeverity = "insecure"
	CipherSeverityWeak       CipherSeverity = "weak"
	CipherSeverityAcceptable CipherSeverity = "acceptable"
	CipherSeveritySecure     CipherSeverity = "secure"
	CipherSeverityModern     CipherSeverity = "modern"
	CipherSeverityUnknown    CipherSeverity = "unknown"
)

// AllCipherSuites contains the cipher suites actively offered by TLS 1.0-1.2
// probing. Some legacy suites remain classified below for negotiated evidence
// and policy output, but are not actively offered because Go and CodeQL treat
// them as insecure client configurations.
var AllCipherSuites = []CipherSuite{
	{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
	{tls.TLS_RSA_WITH_AES_128_CBC_SHA, "TLS_RSA_WITH_AES_128_CBC_SHA"},
	{tls.TLS_RSA_WITH_AES_256_CBC_SHA, "TLS_RSA_WITH_AES_256_CBC_SHA"},
	{tls.TLS_RSA_WITH_AES_128_GCM_SHA256, "TLS_RSA_WITH_AES_128_GCM_SHA256"},
	{tls.TLS_RSA_WITH_AES_256_GCM_SHA384, "TLS_RSA_WITH_AES_256_GCM_SHA384"},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"},
	{tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"},
	{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
	{tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
	{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
	{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
	{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
	{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
	{tls.TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256"},
	{tls.TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384"},
	{tls.TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256"},
}

var CipherClassification = map[string]string{
	"TLS_RSA_WITH_RC4_128_SHA":                "🔴 INSECURE",
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           "🔴 INSECURE",
	"TLS_RSA_WITH_AES_128_CBC_SHA":            "🟠 WEAK",
	"TLS_RSA_WITH_AES_256_CBC_SHA":            "🟠 WEAK",
	"TLS_RSA_WITH_AES_128_CBC_SHA256":         "🟠 WEAK",
	"TLS_RSA_WITH_AES_128_GCM_SHA256":         "🟢 SECURE",
	"TLS_RSA_WITH_AES_256_GCM_SHA384":         "🟢 SECURE",
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":        "🔴 INSECURE",
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    "🟡 ACCEPTABLE",
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    "🟡 ACCEPTABLE",
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":          "🔴 INSECURE",
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     "🔴 INSECURE",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      "🟡 ACCEPTABLE",
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      "🟡 ACCEPTABLE",
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": "🟢 SECURE",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":   "🟢 SECURE",
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": "🟢 SECURE",
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": "🟢 SECURE",
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   "🟢 SECURE",
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   "🟢 SECURE",
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  "🟢 MODERN",
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    "🟢 MODERN",
	// IANA and crypto/tls spelling; the two entries above are the names
	// earlier releases printed and are kept so older names still classify.
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": "🟢 MODERN",
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   "🟢 MODERN",
	"TLS_AES_128_GCM_SHA256":                        "🟢 MODERN",
	"TLS_AES_256_GCM_SHA384":                        "🟢 MODERN",
	"TLS_CHACHA20_POLY1305_SHA256":                  "🟢 MODERN",
}

// CipherSeverityByName drives policy decisions; CipherClassification is only
// the human-facing display label used in reports.
var CipherSeverityByName = map[string]CipherSeverity{
	"TLS_RSA_WITH_RC4_128_SHA":                CipherSeverityInsecure,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           CipherSeverityInsecure,
	"TLS_RSA_WITH_AES_128_CBC_SHA":            CipherSeverityWeak,
	"TLS_RSA_WITH_AES_256_CBC_SHA":            CipherSeverityWeak,
	"TLS_RSA_WITH_AES_128_CBC_SHA256":         CipherSeverityWeak,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":         CipherSeveritySecure,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":         CipherSeveritySecure,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":        CipherSeverityInsecure,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    CipherSeverityAcceptable,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    CipherSeverityAcceptable,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":          CipherSeverityInsecure,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     CipherSeverityInsecure,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      CipherSeverityAcceptable,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      CipherSeverityAcceptable,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": CipherSeveritySecure,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":   CipherSeveritySecure,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": CipherSeveritySecure,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": CipherSeveritySecure,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   CipherSeveritySecure,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   CipherSeveritySecure,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  CipherSeverityModern,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    CipherSeverityModern,
	// IANA and crypto/tls spelling; the two entries above are the names
	// earlier releases printed and are kept so older names still classify.
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": CipherSeverityModern,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   CipherSeverityModern,
	"TLS_AES_128_GCM_SHA256":                        CipherSeverityModern,
	"TLS_AES_256_GCM_SHA384":                        CipherSeverityModern,
	"TLS_CHACHA20_POLY1305_SHA256":                  CipherSeverityModern,
}

func CipherSuiteSeverity(name string) CipherSeverity {
	severity, ok := CipherSeverityByName[name]
	if !ok {
		return cipherSeverityFromName(name)
	}
	return severity
}

// cipherKeyExchangePrefixes lists the TLS 1.0-1.2 key exchange and
// authentication families the name-based classifier understands. The trailing
// bool reports whether the key exchange is forward secret.
var cipherKeyExchangePrefixes = []struct {
	prefix        string
	forwardSecret bool
}{
	{"TLS_ECDHE_ECDSA_", true},
	{"TLS_ECDHE_RSA_", true},
	{"TLS_DHE_RSA_", true},
	{"TLS_DHE_DSS_", true},
	{"TLS_DH_anon_", true},
	{"TLS_ECDH_anon_", true},
	{"TLS_RSA_", false},
}

// cipherSeverityFromName classifies cipher suites that are not listed in
// CipherSeverityByName from the construction spelled out in their IANA name.
// It exists for suites found by the raw TLS 1.0-1.2 probe, which can detect
// far more suites than crypto/tls implements.
//
// The rules are conservative and return CipherSeverityUnknown as soon as the
// key exchange or the bulk cipher is not recognised:
//
//   - insecure: no encryption (NULL), no authentication (anon), EXPORT-grade
//     keys, RC4, RC2, DES, 3DES and IDEA (64-bit blocks), MD5 MACs;
//   - weak: static RSA key exchange or DSS certificates combined with CBC,
//     and truncated-tag CCM_8;
//   - acceptable: forward-secret CBC, and every DHE suite, because the probe
//     does not see the Diffie-Hellman group the server would use;
//   - secure / modern: static RSA or ECDHE with an AEAD cipher, following the
//     labels already used in CipherSeverityByName.
func cipherSeverityFromName(name string) CipherSeverity {
	forwardSecret, known := false, false
	for _, kx := range cipherKeyExchangePrefixes {
		if strings.HasPrefix(name, kx.prefix) {
			forwardSecret, known = kx.forwardSecret, true
			break
		}
	}
	if !known {
		return CipherSeverityUnknown
	}

	for _, marker := range []string{"_anon_", "_EXPORT_", "_WITH_NULL_", "_RC4_", "_RC2_", "_DES_", "_DES40_", "_3DES_", "_IDEA_"} {
		if strings.Contains(name, marker) {
			return CipherSeverityInsecure
		}
	}
	if strings.HasSuffix(name, "_MD5") {
		return CipherSeverityInsecure
	}

	aead := strings.Contains(name, "_GCM_") || strings.Contains(name, "_CCM") || strings.Contains(name, "CHACHA20_POLY1305")
	if !aead && !isCBCCipherSuite(name) {
		return CipherSeverityUnknown
	}
	blockCipherKnown := false
	for _, marker := range []string{"_AES_128_", "_AES_256_", "_CAMELLIA_128_", "_CAMELLIA_256_", "_ARIA_128_", "_ARIA_256_", "_SEED_", "CHACHA20_POLY1305"} {
		if strings.Contains(name, marker) {
			blockCipherKnown = true
			break
		}
	}
	if !blockCipherKnown {
		return CipherSeverityUnknown
	}

	dss := strings.HasPrefix(name, "TLS_DHE_DSS_")
	dhe := strings.HasPrefix(name, "TLS_DHE_")
	switch {
	case strings.HasSuffix(name, "_CCM_8"), dss:
		return CipherSeverityWeak
	case !aead && !forwardSecret:
		return CipherSeverityWeak
	case !aead || dhe:
		return CipherSeverityAcceptable
	case strings.Contains(name, "CHACHA20_POLY1305"):
		return CipherSeverityModern
	default:
		return CipherSeveritySecure
	}
}

// cipherSeverityLabels maps a severity to the display label used when a suite
// has no explicit entry in CipherClassification.
var cipherSeverityLabels = map[CipherSeverity]string{
	CipherSeverityInsecure:   "🔴 INSECURE",
	CipherSeverityWeak:       "🟠 WEAK",
	CipherSeverityAcceptable: "🟡 ACCEPTABLE",
	CipherSeveritySecure:     "🟢 SECURE",
	CipherSeverityModern:     "🟢 MODERN",
}

func CipherSuiteSeverityForVersion(version uint16, name string) CipherSeverity {
	severity := CipherSuiteSeverity(name)
	if severity == CipherSeverityUnknown ||
		severity == CipherSeverityInsecure ||
		severity == CipherSeverityWeak {
		return severity
	}

	if version != 0 && version < tls.VersionTLS12 && isCBCCipherSuite(name) {
		return CipherSeverityWeak
	}

	return severity
}

func CipherClassificationForVersion(version uint16, name string) (string, bool) {
	if IsLegacyCBCForVersion(version, name) {
		return "🟠 WEAK (legacy CBC)", true
	}
	if label, ok := CipherClassification[name]; ok {
		return label, true
	}
	label, ok := cipherSeverityLabels[cipherSeverityFromName(name)]
	return label, ok
}

func IsLegacyCBCForVersion(version uint16, name string) bool {
	baseSeverity := CipherSuiteSeverity(name)
	return version != 0 &&
		version < tls.VersionTLS12 &&
		isCBCCipherSuite(name) &&
		baseSeverity != CipherSeverityUnknown &&
		baseSeverity != CipherSeverityInsecure &&
		baseSeverity != CipherSeverityWeak
}

func isCBCCipherSuite(name string) bool {
	return strings.Contains(name, "_CBC_")
}

// CipherSuiteIDsForVersion returns the IDs of the actively probed cipher suites
// (AllCipherSuites) that can be negotiated with the given TLS version.
//
// The list is ordered from most to least preferable (forward-secret AEAD
// first, static RSA and 3DES last), so a server that honours the client's
// preference still reports a sensible negotiated suite.
func CipherSuiteIDsForVersion(version uint16) []uint16 {
	suites := make([]CipherSuite, 0, len(AllCipherSuites))
	for _, cs := range AllCipherSuites {
		if IsCipherSuiteCompatibleWith(version, cs.ID) {
			suites = append(suites, cs)
		}
	}
	sort.SliceStable(suites, func(i, j int) bool {
		return cipherPreferenceRank(suites[i].Name) < cipherPreferenceRank(suites[j].Name)
	})
	ids := make([]uint16, len(suites))
	for i, cs := range suites {
		ids[i] = cs.ID
	}
	return ids
}

func cipherPreferenceRank(name string) int {
	switch {
	case strings.Contains(name, "3DES"):
		return 4
	case strings.HasPrefix(name, "TLS_RSA_") && isCBCCipherSuite(name):
		return 3
	case strings.HasPrefix(name, "TLS_RSA_"):
		return 2
	case isCBCCipherSuite(name):
		return 1
	default:
		return 0
	}
}

func IsCipherSuiteCompatibleWith(version uint16, id uint16) bool {
	if version == tls.VersionTLS13 {
		return id == tls.TLS_AES_128_GCM_SHA256 ||
			id == tls.TLS_AES_256_GCM_SHA384 ||
			id == tls.TLS_CHACHA20_POLY1305_SHA256
	}
	return id != tls.TLS_AES_128_GCM_SHA256 &&
		id != tls.TLS_AES_256_GCM_SHA384 &&
		id != tls.TLS_CHACHA20_POLY1305_SHA256
}
