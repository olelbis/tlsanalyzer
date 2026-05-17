package policy

import (
	"crypto/tls"
	"crypto/x509"
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
