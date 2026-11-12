package utils

import (
	"crypto/tls"
	"reflect"
	"testing"
)

func TestTLSVersionToUint16(t *testing.T) {
	tests := map[string]uint16{
		"1.0": tls.VersionTLS10,
		"1.1": tls.VersionTLS11,
		"1.2": tls.VersionTLS12,
		"1.3": tls.VersionTLS13,
		"2.0": 0,
		"":    0,
	}

	for input, expected := range tests {
		got := TLSVersionToUint16(input)
		if got != expected {
			t.Fatalf("TLSVersionToUint16(%q) = %d, want %d", input, got, expected)
		}
	}
}

func TestFilterTLSVersionsReturnsSortedVersionsAtOrAboveMinimum(t *testing.T) {
	got := FilterTLSVersions(tls.VersionTLS12)
	want := []uint16{tls.VersionTLS12, tls.VersionTLS13}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FilterTLSVersions(TLS 1.2) = %v, want %v", got, want)
	}
}

func TestIsCipherSuiteCompatibleWith(t *testing.T) {
	if !IsCipherSuiteCompatibleWith(tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256) {
		t.Fatal("TLS_AES_128_GCM_SHA256 should be compatible with TLS 1.3")
	}

	if IsCipherSuiteCompatibleWith(tls.VersionTLS13, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) {
		t.Fatal("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 should not be compatible with TLS 1.3")
	}

	if !IsCipherSuiteCompatibleWith(tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) {
		t.Fatal("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 should be compatible with TLS 1.2")
	}

	if IsCipherSuiteCompatibleWith(tls.VersionTLS12, tls.TLS_AES_128_GCM_SHA256) {
		t.Fatal("TLS_AES_128_GCM_SHA256 should not be compatible with TLS 1.2")
	}
}

func TestCipherSuiteSeverity(t *testing.T) {
	tests := map[string]CipherSeverity{
		"TLS_RSA_WITH_RC4_128_SHA":                CipherSeverityInsecure,
		"TLS_RSA_WITH_AES_128_CBC_SHA":            CipherSeverityWeak,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      CipherSeverityAcceptable,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   CipherSeveritySecure,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    CipherSeverityModern,
		"TLS_NOT_A_REAL_CIPHER_SUITE_FOR_TESTING": CipherSeverityUnknown,
	}

	for cipher, want := range tests {
		if got := CipherSuiteSeverity(cipher); got != want {
			t.Fatalf("CipherSuiteSeverity(%q) = %q, want %q", cipher, got, want)
		}
	}
}

func TestAllCipherSuitesExcludeUnsafeClientConfigurations(t *testing.T) {
	for _, cipherSuite := range AllCipherSuites {
		switch cipherSuite.ID {
		case tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
			t.Fatalf("AllCipherSuites includes unsafe client probe cipher %s", cipherSuite.Name)
		}
	}
}

func TestCipherSuiteSeverityForVersionTreatsLegacyCBCAsWeak(t *testing.T) {
	cipher := "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	if got := CipherSuiteSeverityForVersion(tls.VersionTLS10, cipher); got != CipherSeverityWeak {
		t.Fatalf("CipherSuiteSeverityForVersion(TLS 1.0, %q) = %q, want %q", cipher, got, CipherSeverityWeak)
	}
	if got := CipherSuiteSeverityForVersion(tls.VersionTLS12, cipher); got != CipherSeverityAcceptable {
		t.Fatalf("CipherSuiteSeverityForVersion(TLS 1.2, %q) = %q, want %q", cipher, got, CipherSeverityAcceptable)
	}
}

func TestIsLegacyCBCForVersion(t *testing.T) {
	if !IsLegacyCBCForVersion(tls.VersionTLS11, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA") {
		t.Fatal("TLS 1.1 ECDHE CBC should be reported as legacy CBC")
	}
	if IsLegacyCBCForVersion(tls.VersionTLS12, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA") {
		t.Fatal("TLS 1.2 CBC should not be reported as legacy CBC")
	}
	if IsLegacyCBCForVersion(tls.VersionTLS10, "TLS_RSA_WITH_AES_128_CBC_SHA") {
		t.Fatal("already weak CBC should not be reported as upgraded legacy CBC")
	}
}

func TestCipherClassificationForVersion(t *testing.T) {
	label, ok := CipherClassificationForVersion(tls.VersionTLS10, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")
	if !ok {
		t.Fatal("CipherClassificationForVersion() ok = false, want true")
	}
	if label != "🟠 WEAK (legacy CBC)" {
		t.Fatalf("CipherClassificationForVersion() = %q, want legacy CBC label", label)
	}

	label, ok = CipherClassificationForVersion(tls.VersionTLS12, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")
	if !ok {
		t.Fatal("CipherClassificationForVersion() ok = false, want true")
	}
	if label != "🟡 ACCEPTABLE" {
		t.Fatalf("CipherClassificationForVersion() = %q, want acceptable label", label)
	}
}

func TestUniqueStringsPreservesFirstOccurrenceOrder(t *testing.T) {
	got := UniqueStrings([]string{"b", "a", "b", "c", "a"})
	want := []string{"b", "a", "c"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UniqueStrings() = %v, want %v", got, want)
	}
}

func TestCipherSuiteSeverityClassifiesRawProbedSuitesByName(t *testing.T) {
	tests := map[string]CipherSeverity{
		// No encryption, no authentication, export-grade or broken primitives.
		"TLS_RSA_WITH_NULL_SHA256":              CipherSeverityInsecure,
		"TLS_ECDHE_RSA_WITH_NULL_SHA":           CipherSeverityInsecure,
		"TLS_DH_anon_WITH_AES_256_GCM_SHA384":   CipherSeverityInsecure,
		"TLS_ECDH_anon_WITH_AES_128_CBC_SHA":    CipherSeverityInsecure,
		"TLS_RSA_EXPORT_WITH_RC4_40_MD5":        CipherSeverityInsecure,
		"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA":     CipherSeverityInsecure,
		"TLS_RSA_WITH_RC4_128_MD5":              CipherSeverityInsecure,
		"TLS_RSA_WITH_DES_CBC_SHA":              CipherSeverityInsecure,
		"TLS_RSA_WITH_IDEA_CBC_SHA":             CipherSeverityInsecure,
		"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA":     CipherSeverityInsecure,
		"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA": CipherSeverityInsecure,

		// Static RSA key exchange or DSS certificates.
		"TLS_RSA_WITH_AES_256_CBC_SHA256":      CipherSeverityWeak,
		"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA":    CipherSeverityWeak,
		"TLS_RSA_WITH_SEED_CBC_SHA":            CipherSeverityWeak,
		"TLS_RSA_WITH_AES_128_CCM_8":           CipherSeverityWeak,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8":   CipherSeverityWeak,
		"TLS_DHE_DSS_WITH_AES_128_CBC_SHA":     CipherSeverityWeak,
		"TLS_DHE_DSS_WITH_AES_256_GCM_SHA384":  CipherSeverityWeak,
		"TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256": CipherSeverityWeak,

		// Forward-secret CBC, and DHE (group strength is not observed).
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384":        CipherSeverityAcceptable,
		"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256": CipherSeverityAcceptable,
		"TLS_DHE_RSA_WITH_AES_128_CBC_SHA":             CipherSeverityAcceptable,
		"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256":          CipherSeverityAcceptable,
		"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256":    CipherSeverityAcceptable,

		// AEAD without DHE.
		"TLS_RSA_WITH_AES_256_CCM":                      CipherSeveritySecure,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CCM":              CipherSeveritySecure,
		"TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384":        CipherSeveritySecure,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   CipherSeverityModern,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": CipherSeverityModern,

		// Anything the rules do not fully recognise stays unknown.
		"TLS_ECDHE_RSA_WITH_FUTURE_128_GCM_SHA256": CipherSeverityUnknown,
		"TLS_ECDHE_RSA_WITH_AES_128_OCB_SHA256":    CipherSeverityUnknown,
		"TLS_PSK_WITH_AES_128_GCM_SHA256":          CipherSeverityUnknown,
		"TLS_PRIVATE_UNKNOWN_CIPHER":               CipherSeverityUnknown,
		"0x1234":                                   CipherSeverityUnknown,
	}

	for cipher, want := range tests {
		if got := CipherSuiteSeverity(cipher); got != want {
			t.Errorf("CipherSuiteSeverity(%q) = %q, want %q", cipher, got, want)
		}
	}
}

func TestCipherSuiteSeverityKeepsExplicitEntries(t *testing.T) {
	// The name-based rules are only a fallback: explicit entries always win.
	for name, want := range CipherSeverityByName {
		if got := CipherSuiteSeverity(name); got != want {
			t.Errorf("CipherSuiteSeverity(%q) = %q, want explicit %q", name, got, want)
		}
	}
}

func TestCipherClassificationForVersionLabelsRawProbedSuites(t *testing.T) {
	tests := map[string]string{
		"TLS_RSA_WITH_RC4_128_MD5":            "🔴 INSECURE",
		"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA":   "🟠 WEAK",
		"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": "🟡 ACCEPTABLE",
	}
	for cipher, want := range tests {
		label, ok := CipherClassificationForVersion(tls.VersionTLS12, cipher)
		if !ok || label != want {
			t.Errorf("CipherClassificationForVersion(%q) = %q, %t; want %q", cipher, label, ok, want)
		}
	}

	if label, ok := CipherClassificationForVersion(tls.VersionTLS12, "TLS_PRIVATE_UNKNOWN_CIPHER"); ok {
		t.Errorf("unknown cipher got label %q, want no classification", label)
	}
	// Forward-secret CBC found by the raw probe is still legacy CBC below TLS 1.2.
	if label, _ := CipherClassificationForVersion(tls.VersionTLS10, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"); label != "🟠 WEAK (legacy CBC)" {
		t.Errorf("TLS 1.0 DHE CBC label = %q, want legacy CBC", label)
	}
}
