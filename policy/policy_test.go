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

func TestEvaluateFailsWeakCipherOnIncompleteCipherEvidence(t *testing.T) {
	results := []scan.TLSScanResult{{
		Version:                  "TLS 1.2",
		VersionID:                tls.VersionTLS12,
		Supported:                true,
		CipherSuites:             []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		CipherEvidenceIncomplete: true,
	}}

	result := Evaluate(results, Config{FailOn: []string{CheckWeakCipher}}, time.Now())

	// Every suite that was found is fine, but probes went unanswered: the
	// gate must not report a verified absence of weak suites.
	if result.Passed {
		t.Fatal("weak-cipher passed on incomplete cipher evidence")
	}
	if len(result.Failures) != 1 || result.Failures[0].Check != CheckWeakCipher ||
		!strings.Contains(result.Failures[0].Message, "TLS 1.2 cipher evidence is incomplete") {
		t.Fatalf("Failures = %+v, want one weak-cipher failure about incomplete evidence", result.Failures)
	}

	// Without the weak-cipher check nobody relies on the cipher list.
	result = Evaluate(results, Config{FailOn: []string{CheckLegacyTLS}}, time.Now())
	if !result.Passed || len(result.Failures) != 0 {
		t.Fatalf("Failures = %+v, want none when weak-cipher is not evaluated", result.Failures)
	}

	// Complete evidence with the same suites passes.
	results[0].CipherEvidenceIncomplete = false
	if result = Evaluate(results, Config{FailOn: []string{CheckWeakCipher}}, time.Now()); !result.Passed {
		t.Fatalf("Failures = %+v, want a pass on complete evidence", result.Failures)
	}
}

func tls13WithGroups(incomplete bool, groups ...scan.KeyExchangeGroupResult) scan.TLSScanResult {
	return scan.TLSScanResult{
		Version:                     "TLS 1.3",
		VersionID:                   tls.VersionTLS13,
		Supported:                   true,
		KeyExchangeGroups:           groups,
		KeyExchangeGroupsIncomplete: incomplete,
	}
}

var (
	groupHybrid = scan.KeyExchangeGroupResult{ID: 0x11ec, Name: "X25519MLKEM768", PostQuantum: true}
	groupX25519 = scan.KeyExchangeGroupResult{ID: 0x001d, Name: "X25519"}
	groupP256   = scan.KeyExchangeGroupResult{ID: 0x0017, Name: "P-256"}
)

func TestEvaluateRequirePostQuantum(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	config := Config{RequirePostQuantum: true}

	tests := []struct {
		name        string
		results     []scan.TLSScanResult
		wantPass    bool
		wantMessage string
	}{
		{
			name:     "hybrid group accepted",
			results:  []scan.TLSScanResult{tls13WithGroups(false, groupX25519, groupHybrid)},
			wantPass: true,
		},
		{
			name:        "classical groups only",
			results:     []scan.TLSScanResult{tls13WithGroups(false, groupX25519, groupP256)},
			wantMessage: "TLS 1.3 accepts no post-quantum key exchange group (groups found: X25519, P-256)",
		},
		{
			name:        "no group evidence at all",
			results:     []scan.TLSScanResult{tls13WithGroups(false)},
			wantMessage: "(groups found: none)",
		},
		{
			name:        "incomplete evidence cannot confirm support",
			results:     []scan.TLSScanResult{tls13WithGroups(true, groupX25519)},
			wantMessage: "key exchange group evidence is incomplete",
		},
		{
			name:     "a hybrid that was found is proof even when the rest is incomplete",
			results:  []scan.TLSScanResult{tls13WithGroups(true, groupHybrid)},
			wantPass: true,
		},
		{
			name: "TLS 1.3 not supported",
			results: []scan.TLSScanResult{
				{Version: "TLS 1.3", VersionID: tls.VersionTLS13, Status: scan.ScanStatusUnsupported},
				{Version: "TLS 1.2", VersionID: tls.VersionTLS12, Supported: true},
			},
			wantMessage: "post-quantum key exchange requires TLS 1.3, which is not supported",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Evaluate(tt.results, config, now)
			if !result.Enabled {
				t.Fatal("Enabled = false, want --require-pq to enable the policy")
			}
			if result.Passed != tt.wantPass {
				t.Fatalf("Passed = %t, want %t; failures %+v", result.Passed, tt.wantPass, result.Failures)
			}
			if tt.wantPass {
				return
			}
			if len(result.Failures) != 1 || result.Failures[0].Check != CheckRequirePQ || !strings.Contains(result.Failures[0].Message, tt.wantMessage) {
				t.Fatalf("Failures = %+v, want one %s failure containing %q", result.Failures, CheckRequirePQ, tt.wantMessage)
			}
		})
	}
}

func TestRequiresGroupProbe(t *testing.T) {
	if !RequiresGroupProbe(Config{RequirePostQuantum: true}) {
		t.Fatal("RequiresGroupProbe() = false for --require-pq")
	}
	if RequiresGroupProbe(Config{Name: NameModern}) {
		t.Fatal("RequiresGroupProbe() = true for the modern policy, which does not need groups")
	}
}

func TestEvaluateRequirePostQuantumRejectsUnconfirmedHybrid(t *testing.T) {
	failed := groupHybrid
	failed.Evidence = scan.GroupEvidenceHandshakeFailed
	result := Evaluate([]scan.TLSScanResult{tls13WithGroups(false, groupX25519, failed)}, Config{RequirePostQuantum: true}, time.Now())
	if result.Passed || len(result.Failures) != 1 || !strings.Contains(result.Failures[0].Message, "handshake offering only that group failed") {
		t.Fatalf("result = %+v, want a failure about the unconfirmed hybrid", result)
	}

	confirmed := groupHybrid
	confirmed.Evidence = scan.GroupEvidenceHandshake
	if result := Evaluate([]scan.TLSScanResult{tls13WithGroups(false, groupX25519, confirmed)}, Config{RequirePostQuantum: true}, time.Now()); !result.Passed {
		t.Fatalf("Failures = %+v, want a confirmed hybrid to pass", result.Failures)
	}
}

func TestEvaluateRequirePostQuantumPreferred(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	config := Config{RequirePostQuantumPreferred: true}

	withPreference := func(preference string, incomplete bool, groups ...scan.KeyExchangeGroupResult) scan.TLSScanResult {
		r := tls13WithGroups(incomplete, groups...)
		r.KeyExchangeGroupPreference = preference
		return r
	}
	tests := []struct {
		name        string
		results     []scan.TLSScanResult
		wantMessage string
	}{
		{"server prefers post-quantum", []scan.TLSScanResult{withPreference(scan.PreferencePostQuantum, false, groupHybrid, groupX25519)}, ""},
		{"server prefers classical", []scan.TLSScanResult{withPreference(scan.PreferenceClassical, false, groupHybrid, groupX25519)}, "prefers a classical key exchange group"},
		{"server follows the client", []scan.TLSScanResult{withPreference(scan.PreferenceClient, false, groupHybrid, groupX25519)}, "follows the client's group order"},
		{"inconclusive probes", []scan.TLSScanResult{withPreference(scan.PreferenceInconclusive, false, groupHybrid, groupX25519)}, "could not be determined"},
		{"no post-quantum group", []scan.TLSScanResult{withPreference("", false, groupX25519)}, "accepts no post-quantum key exchange group"},
		{"incomplete evidence", []scan.TLSScanResult{withPreference("", true, groupX25519)}, "preference cannot be confirmed"},
		{"TLS 1.3 not supported", []scan.TLSScanResult{{Version: "TLS 1.3", VersionID: tls.VersionTLS13, Status: scan.ScanStatusUnsupported}, {Version: "TLS 1.2", VersionID: tls.VersionTLS12, Supported: true}}, "requires TLS 1.3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Evaluate(tt.results, config, now)
			if !result.Enabled {
				t.Fatal("Enabled = false, want --require-pq-preferred to enable the policy")
			}
			if tt.wantMessage == "" {
				if !result.Passed {
					t.Fatalf("Failures = %+v, want a pass", result.Failures)
				}
				return
			}
			if result.Passed || len(result.Failures) != 1 || result.Failures[0].Check != CheckRequirePQPreferred || !strings.Contains(result.Failures[0].Message, tt.wantMessage) {
				t.Fatalf("Failures = %+v, want one %s failure containing %q", result.Failures, CheckRequirePQPreferred, tt.wantMessage)
			}
		})
	}
	if !RequiresGroupProbe(config) {
		t.Fatal("RequiresGroupProbe() = false for --require-pq-preferred")
	}
}
