package policy

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/olelbis/tlsanalyzer/scan"
)

func TestEvaluateModernPolicyFailsOnLegacyTLSWeakCipherInvalidAndExpiredCert(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	result := Evaluate([]scan.TLSScanResult{
		{
			Version:              "TLS 1.0",
			VersionID:            tls.VersionTLS10,
			Supported:            true,
			CipherSuites:         []string{"TLS_RSA_WITH_RC4_128_SHA"},
			CertValidationStatus: scan.CertValidationInvalid,
			Certificate:          &x509.Certificate{NotAfter: now.Add(-time.Hour)},
		},
	}, Config{Name: NameModern}, now)

	if !result.Enabled {
		t.Fatal("policy should be enabled")
	}
	if result.Passed {
		t.Fatal("modern policy should fail")
	}
	checks := make(map[string]bool)
	for _, failure := range result.Failures {
		checks[failure.Check] = true
	}
	for _, check := range []string{CheckLegacyTLS, CheckWeakCipher, CheckInvalidCert, CheckExpiredCert} {
		if !checks[check] {
			t.Fatalf("missing policy failure %q in %+v", check, result.Failures)
		}
	}
}

func TestEvaluateCustomFailOn(t *testing.T) {
	result := Evaluate([]scan.TLSScanResult{
		{
			Version:      "TLS 1.1",
			VersionID:    tls.VersionTLS11,
			Supported:    true,
			CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		},
	}, Config{FailOn: []string{CheckLegacyTLS}}, time.Now())

	if !result.Enabled || result.Passed {
		t.Fatalf("custom fail-on should be enabled and fail: %+v", result)
	}
	if result.Name != "" {
		t.Fatalf("custom policy name = %q, want empty", result.Name)
	}
}

func TestEvaluateInvalidCertCheckFailsWhenValidationSkippedOrUnavailable(t *testing.T) {
	result := Evaluate([]scan.TLSScanResult{
		{
			Version:              "TLS 1.2",
			VersionID:            tls.VersionTLS12,
			Supported:            true,
			CertValidationStatus: scan.CertValidationSkipped,
		},
		{
			Version:              "TLS 1.3",
			VersionID:            tls.VersionTLS13,
			Supported:            true,
			CertValidationStatus: scan.CertValidationUnavailable,
		},
	}, Config{FailOn: []string{CheckInvalidCert}}, time.Now())

	if result.Passed {
		t.Fatal("invalid-cert check should fail when validation is skipped or unavailable")
	}
	if len(result.Failures) != 2 {
		t.Fatalf("Failures = %d, want 2: %+v", len(result.Failures), result.Failures)
	}
}

func TestEvaluateWeakCipherCheckFailsOnUnknownCipher(t *testing.T) {
	result := Evaluate([]scan.TLSScanResult{
		{
			Version:      "TLS 1.2",
			VersionID:    tls.VersionTLS12,
			Supported:    true,
			CipherSuites: []string{"TLS_PRIVATE_UNKNOWN_CIPHER"},
		},
	}, Config{FailOn: []string{CheckWeakCipher}}, time.Now())

	if result.Passed {
		t.Fatal("weak-cipher check should fail on unclassified cipher suites")
	}
	if len(result.Failures) != 1 {
		t.Fatalf("Failures = %d, want 1: %+v", len(result.Failures), result.Failures)
	}
	if !strings.Contains(result.Failures[0].Message, "unclassified cipher") {
		t.Fatalf("failure message should mention unclassified cipher: %+v", result.Failures[0])
	}
}

func TestEvaluateWeakCipherCheckTreatsLegacyCBCAsWeak(t *testing.T) {
	result := Evaluate([]scan.TLSScanResult{
		{
			Version:      "TLS 1.0",
			VersionID:    tls.VersionTLS10,
			Supported:    true,
			CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
		},
	}, Config{FailOn: []string{CheckWeakCipher}}, time.Now())

	if result.Passed {
		t.Fatal("weak-cipher check should fail on legacy CBC negotiated over TLS 1.0")
	}
	if len(result.Failures) != 1 {
		t.Fatalf("Failures = %d, want 1: %+v", len(result.Failures), result.Failures)
	}
	if !strings.Contains(result.Failures[0].Message, "weak cipher") {
		t.Fatalf("failure message should mention weak cipher: %+v", result.Failures[0])
	}
}

func TestEvaluateParameterizedPolicyFailsOnConfiguredRequirements(t *testing.T) {
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	result := Evaluate([]scan.TLSScanResult{
		{
			Version:         "TLS 1.2",
			VersionID:       tls.VersionTLS12,
			Supported:       true,
			ALPNProtocol:    "http/1.1",
			Certificate:     testCertificate(1024, now.Add(10*24*time.Hour)),
			CipherDiscovery: scan.CipherDiscoveryNegotiated,
		},
	}, Config{
		RequiredTLSVersions:        []uint16{tls.VersionTLS13},
		ForbiddenTLSVersions:       []uint16{tls.VersionTLS12},
		RequiredALPNProtocols:      []string{"h2"},
		ForbiddenALPNProtocols:     []string{"http/1.1"},
		MinCertificateKeyBits:      2048,
		MinCertificateValidityDays: 30,
	}, now)

	if !result.Enabled {
		t.Fatal("parameterized policy should be enabled")
	}
	if result.Passed {
		t.Fatal("parameterized policy should fail")
	}
	for _, check := range []string{
		CheckForbiddenTLS,
		CheckRequiredTLS,
		CheckRequiredALPN,
		CheckForbiddenALPN,
		CheckMinCertKeyBits,
		CheckMinCertDays,
	} {
		if !hasFailure(result, check) {
			t.Fatalf("missing policy failure %q in %+v", check, result.Failures)
		}
	}
}

func TestEvaluateParameterizedPolicyPassesWhenRequirementsMatch(t *testing.T) {
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	result := Evaluate([]scan.TLSScanResult{
		{
			Version:      "TLS 1.3",
			VersionID:    tls.VersionTLS13,
			Supported:    true,
			ALPNProtocol: "h2",
			Certificate:  testCertificate(2048, now.Add(60*24*time.Hour)),
		},
	}, Config{
		RequiredTLSVersions:        []uint16{tls.VersionTLS13},
		ForbiddenTLSVersions:       []uint16{tls.VersionTLS10, tls.VersionTLS11},
		RequiredALPNProtocols:      []string{"h2"},
		ForbiddenALPNProtocols:     []string{"http/1.1"},
		MinCertificateKeyBits:      2048,
		MinCertificateValidityDays: 30,
	}, now)

	if !result.Enabled {
		t.Fatal("parameterized policy should be enabled")
	}
	if !result.Passed {
		t.Fatalf("parameterized policy should pass: %+v", result.Failures)
	}
}

func TestEvaluateParameterizedPolicyFailsWhenEvidenceIsUnavailable(t *testing.T) {
	result := Evaluate([]scan.TLSScanResult{
		{
			Version:   "TLS 1.2",
			VersionID: tls.VersionTLS12,
			Supported: true,
		},
	}, Config{
		RequiredALPNProtocols:      []string{"h2"},
		MinCertificateKeyBits:      2048,
		MinCertificateValidityDays: 30,
	}, time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC))

	if result.Passed {
		t.Fatal("policy should fail when required evidence is unavailable")
	}
	for _, check := range []string{CheckRequiredALPN, CheckMinCertKeyBits, CheckMinCertDays} {
		if !hasFailure(result, check) {
			t.Fatalf("missing policy failure %q in %+v", check, result.Failures)
		}
	}
}

func TestRequiresCipherProbe(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		want   bool
	}{
		{name: "disabled"},
		{name: "modern", config: Config{Name: NameModern}, want: true},
		{name: "weak cipher", config: Config{FailOn: []string{CheckWeakCipher}}, want: true},
		{name: "legacy tls only", config: Config{FailOn: []string{CheckLegacyTLS}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RequiresCipherProbe(tt.config); got != tt.want {
				t.Fatalf("RequiresCipherProbe() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateConfigRejectsUnknownPolicyAndCheck(t *testing.T) {
	if err := ValidateConfig(Config{Name: "strict"}); err == nil {
		t.Fatal("ValidateConfig() error = nil, want unknown policy error")
	}
	if err := ValidateConfig(Config{FailOn: []string{"surprise"}}); err == nil {
		t.Fatal("ValidateConfig() error = nil, want unknown fail-on error")
	}
}

func TestValidateConfigRejectsConflictingParameterizedPolicy(t *testing.T) {
	if err := ValidateConfig(Config{
		RequiredTLSVersions:  []uint16{tls.VersionTLS13},
		ForbiddenTLSVersions: []uint16{tls.VersionTLS13},
	}); err == nil {
		t.Fatal("ValidateConfig() error = nil, want conflicting TLS policy error")
	}
	if err := ValidateConfig(Config{
		RequiredALPNProtocols:  []string{"h2"},
		ForbiddenALPNProtocols: []string{"h2"},
	}); err == nil {
		t.Fatal("ValidateConfig() error = nil, want conflicting ALPN policy error")
	}
	if err := ValidateConfig(Config{MinCertificateKeyBits: -1}); err == nil {
		t.Fatal("ValidateConfig() error = nil, want negative key bits error")
	}
	if err := ValidateConfig(Config{MinCertificateValidityDays: -1}); err == nil {
		t.Fatal("ValidateConfig() error = nil, want negative validity days error")
	}
	if err := ValidateConfig(Config{RequiredALPNProtocols: []string{"bad protocol"}}); err == nil {
		t.Fatal("ValidateConfig() error = nil, want ALPN whitespace error")
	}
	if err := ValidateConfig(Config{RequiredALPNProtocols: []string{strings.Repeat("a", 256)}}); err == nil {
		t.Fatal("ValidateConfig() error = nil, want ALPN length error")
	}
}

func TestParseFailOn(t *testing.T) {
	got := ParseFailOn("legacy-tls, weak-cipher,,invalid-cert")
	want := []string{CheckLegacyTLS, CheckWeakCipher, CheckInvalidCert}
	if len(got) != len(want) {
		t.Fatalf("len(ParseFailOn()) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ParseFailOn()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseTLSVersions(t *testing.T) {
	got, err := ParseTLSVersions("1.2, 1.3")
	if err != nil {
		t.Fatalf("ParseTLSVersions() error = %v", err)
	}
	want := []uint16{tls.VersionTLS12, tls.VersionTLS13}
	if len(got) != len(want) {
		t.Fatalf("len(ParseTLSVersions()) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ParseTLSVersions()[%d] = %x, want %x", i, got[i], want[i])
		}
	}
	if _, err := ParseTLSVersions("1.4"); err == nil {
		t.Fatal("ParseTLSVersions() error = nil, want invalid version error")
	}
}

func TestParseALPNProtocols(t *testing.T) {
	got := ParseALPNProtocols("h2, http/1.1,,")
	want := []string{"h2", "http/1.1"}
	if len(got) != len(want) {
		t.Fatalf("len(ParseALPNProtocols()) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ParseALPNProtocols()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCertificatePublicKeyMetadata(t *testing.T) {
	tests := []struct {
		name      string
		cert      *x509.Certificate
		wantAlg   string
		wantBits  int
		wantEmpty bool
	}{
		{name: "nil", wantEmpty: true},
		{name: "rsa", cert: testCertificate(2048, time.Now()), wantAlg: "RSA", wantBits: 2048},
		{name: "ecdsa", cert: &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: elliptic.P256()}}, wantAlg: "ECDSA", wantBits: 256},
		{name: "ed25519", cert: &x509.Certificate{PublicKey: ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))}, wantAlg: "Ed25519", wantBits: 256},
		{name: "dsa", cert: &x509.Certificate{PublicKey: &dsa.PublicKey{Parameters: dsa.Parameters{P: new(big.Int).Lsh(big.NewInt(1), 2047)}}}, wantAlg: "DSA", wantBits: 2048},
		{name: "known algorithm without size", cert: &x509.Certificate{PublicKeyAlgorithm: x509.ECDSA}, wantAlg: "ECDSA"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAlg, gotBits := certificatePublicKeyMetadata(tt.cert)
			if tt.wantEmpty {
				if gotAlg != "" || gotBits != 0 {
					t.Fatalf("certificatePublicKeyMetadata() = %q %d, want empty", gotAlg, gotBits)
				}
				return
			}
			if gotAlg != tt.wantAlg || gotBits != tt.wantBits {
				t.Fatalf("certificatePublicKeyMetadata() = %q %d, want %q %d", gotAlg, gotBits, tt.wantAlg, tt.wantBits)
			}
		})
	}
}

func hasFailure(result Result, check string) bool {
	for _, failure := range result.Failures {
		if failure.Check == check {
			return true
		}
	}
	return false
}

func testCertificate(bits int, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		NotAfter: notAfter,
		PublicKey: &rsa.PublicKey{
			N: new(big.Int).Lsh(big.NewInt(1), uint(bits-1)),
			E: 65537,
		},
	}
}
