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
	{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"},
	{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"},
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
	"TLS_AES_128_GCM_SHA256":                  "🟢 MODERN",
	"TLS_AES_256_GCM_SHA384":                  "🟢 MODERN",
	"TLS_CHACHA20_POLY1305_SHA256":            "🟢 MODERN",
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
	"TLS_AES_128_GCM_SHA256":                  CipherSeverityModern,
	"TLS_AES_256_GCM_SHA384":                  CipherSeverityModern,
	"TLS_CHACHA20_POLY1305_SHA256":            CipherSeverityModern,
}

func CipherSuiteSeverity(name string) CipherSeverity {
	severity, ok := CipherSeverityByName[name]
	if !ok {
		return CipherSeverityUnknown
	}
	return severity
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
	label, ok := CipherClassification[name]
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
