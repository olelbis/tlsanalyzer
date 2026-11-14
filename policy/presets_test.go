package policy

import (
	"crypto/ecdsa"
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

var presetNow = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

func ecdsaCert(lifespan time.Duration) *x509.Certificate {
	notBefore := presetNow.Add(-24 * time.Hour)
	return &x509.Certificate{
		PublicKey: &ecdsa.PublicKey{Curve: elliptic.P256()},
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(lifespan),
	}
}

func rsaCert(bits int, lifespan time.Duration) *x509.Certificate {
	notBefore := presetNow.Add(-24 * time.Hour)
	return &x509.Certificate{
		PublicKey: &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), E: 65537},
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(lifespan),
	}
}

func days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

func supportedResult(name string, id uint16, cert *x509.Certificate, suites ...string) scan.TLSScanResult {
	return scan.TLSScanResult{
		Version:              name,
		VersionID:            id,
		Supported:            true,
		Status:               "supported",
		CipherSuites:         suites,
		CertValidationStatus: scan.CertValidationValid,
		Certificate:          cert,
	}
}

func unsupportedResult(name string, id uint16) scan.TLSScanResult {
	return scan.TLSScanResult{Version: name, VersionID: id, Status: "unsupported"}
}

func tls13Only(cert *x509.Certificate) []scan.TLSScanResult {
	return []scan.TLSScanResult{
		unsupportedResult("TLS 1.0", tls.VersionTLS10),
		unsupportedResult("TLS 1.1", tls.VersionTLS11),
		unsupportedResult("TLS 1.2", tls.VersionTLS12),
		supportedResult("TLS 1.3", tls.VersionTLS13, cert, "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"),
	}
}

func failureChecks(result Result) map[string]int {
	checks := make(map[string]int)
	for _, failure := range result.Failures {
		checks[failure.Check]++
	}
	return checks
}

func TestMozillaModernPassesTLS13OnlyECDSAShortLived(t *testing.T) {
	result := Evaluate(tls13Only(ecdsaCert(days(90))), Config{Name: NameMozillaModern}, presetNow)
	if !result.Enabled || !result.Passed {
		t.Fatalf("mozilla-modern should pass: %+v", result)
	}
	if result.Name != NameMozillaModern {
		t.Fatalf("Name = %q, want %q", result.Name, NameMozillaModern)
	}
}

func TestMozillaModernFailsTLS12RSAAndLongLifespan(t *testing.T) {
	cert := rsaCert(2048, days(200))
	results := []scan.TLSScanResult{
		unsupportedResult("TLS 1.0", tls.VersionTLS10),
		unsupportedResult("TLS 1.1", tls.VersionTLS11),
		supportedResult("TLS 1.2", tls.VersionTLS12, cert, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
		unsupportedResult("TLS 1.3", tls.VersionTLS13),
	}
	result := Evaluate(results, Config{Name: NameMozillaModern}, presetNow)
	if result.Passed {
		t.Fatalf("mozilla-modern should fail: %+v", result)
	}
	checks := failureChecks(result)
	for _, check := range []string{CheckForbiddenTLS, CheckRequiredTLS, CheckCertKey, CheckCertLifespan} {
		if checks[check] == 0 {
			t.Fatalf("missing %q failure in %+v", check, result.Failures)
		}
	}
	if checks[CheckLegacyTLS] != 0 || checks[CheckWeakCipher] != 0 {
		t.Fatalf("mozilla-modern should not repeat legacy-tls or weak-cipher: %+v", result.Failures)
	}
}

func TestMozillaModernFailsLegacyVersionOnce(t *testing.T) {
	results := tls13Only(ecdsaCert(days(90)))
	results[0] = supportedResult("TLS 1.0", tls.VersionTLS10, ecdsaCert(days(90)), "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA")
	result := Evaluate(results, Config{Name: NameMozillaModern}, presetNow)
	if got := failureChecks(result)[CheckForbiddenTLS]; got != 1 {
		t.Fatalf("forbidden-tls failures = %d, want 1: %+v", got, result.Failures)
	}
}

func TestMozillaCertLifespanRoundsDownToWholeDays(t *testing.T) {
	// One hour of backdating on a 90-day certificate stays within 90 days.
	result := Evaluate(tls13Only(ecdsaCert(days(90)+time.Hour)), Config{Name: NameMozillaModern}, presetNow)
	if !result.Passed {
		t.Fatalf("90 days and one hour should pass: %+v", result.Failures)
	}
	result = Evaluate(tls13Only(ecdsaCert(days(91))), Config{Name: NameMozillaModern}, presetNow)
	if failureChecks(result)[CheckCertLifespan] == 0 {
		t.Fatalf("91 days should fail cert-lifespan: %+v", result.Failures)
	}
	if !strings.Contains(result.Failures[0].Message, "91 days") {
		t.Fatalf("message should name the lifespan: %q", result.Failures[0].Message)
	}
}

func TestMozillaIntermediatePassesAllowedSuites(t *testing.T) {
	cert := rsaCert(2048, days(90))
	results := []scan.TLSScanResult{
		unsupportedResult("TLS 1.0", tls.VersionTLS10),
		unsupportedResult("TLS 1.1", tls.VersionTLS11),
		supportedResult("TLS 1.2", tls.VersionTLS12, cert,
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"),
		supportedResult("TLS 1.3", tls.VersionTLS13, cert, "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"),
	}
	result := Evaluate(results, Config{Name: NameMozillaIntermediate}, presetNow)
	if !result.Passed {
		t.Fatalf("mozilla-intermediate should pass: %+v", result.Failures)
	}
}

func TestMozillaIntermediateFailsSuitesOutsideTheList(t *testing.T) {
	cert := rsaCert(2048, days(90))
	results := []scan.TLSScanResult{
		supportedResult("TLS 1.2", tls.VersionTLS12, cert,
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_RSA_WITH_AES_128_GCM_SHA256"),
	}
	result := Evaluate(results, Config{Name: NameMozillaIntermediate}, presetNow)
	if got := failureChecks(result)[CheckCipherAllowlist]; got != 1 {
		t.Fatalf("cipher-allowlist failures = %d, want one per version: %+v", got, result.Failures)
	}
	for _, failure := range result.Failures {
		if failure.Check != CheckCipherAllowlist {
			continue
		}
		for _, want := range []string{"TLS 1.2 allows 2 cipher suites", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_128_GCM_SHA256"} {
			if !strings.Contains(failure.Message, want) {
				t.Fatalf("message %q does not contain %q", failure.Message, want)
			}
		}
		if strings.Contains(failure.Message, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") {
			t.Fatalf("a listed suite must not be reported: %q", failure.Message)
		}
	}
}

func TestMozillaIntermediateAllowlistSkipsSuitesAlreadyFlaggedWeak(t *testing.T) {
	cert := rsaCert(2048, days(90))
	weakAndOutside := "TLS_RSA_WITH_AES_128_CBC_SHA"
	results := []scan.TLSScanResult{
		supportedResult("TLS 1.2", tls.VersionTLS12, cert, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", weakAndOutside),
	}
	result := Evaluate(results, Config{Name: NameMozillaIntermediate}, presetNow)
	checks := failureChecks(result)
	if checks[CheckWeakCipher] != 1 {
		t.Fatalf("weak-cipher failures = %d, want 1: %+v", checks[CheckWeakCipher], result.Failures)
	}
	if checks[CheckCipherAllowlist] != 0 {
		t.Fatalf("a suite weak-cipher already reports must not appear again: %+v", result.Failures)
	}

	results[0].CipherSuites = append(results[0].CipherSuites, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256")
	result = Evaluate(results, Config{Name: NameMozillaIntermediate}, presetNow)
	for _, failure := range result.Failures {
		if failure.Check == CheckCipherAllowlist && (strings.Contains(failure.Message, weakAndOutside) || !strings.Contains(failure.Message, "allows 1 cipher suite outside")) {
			t.Fatalf("allowlist message should name only the suite weak-cipher does not report: %q", failure.Message)
		}
	}
}

func TestMozillaIntermediateDoesNotJudgeTLS13SuitesOrOlderVersionsByAllowlist(t *testing.T) {
	cert := rsaCert(2048, days(90))
	results := []scan.TLSScanResult{
		supportedResult("TLS 1.1", tls.VersionTLS11, cert, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
	}
	result := Evaluate(results, Config{Name: NameMozillaIntermediate}, presetNow)
	checks := failureChecks(result)
	if checks[CheckCipherAllowlist] != 0 {
		t.Fatalf("the allowlist applies to TLS 1.2 only: %+v", result.Failures)
	}
	if checks[CheckLegacyTLS] == 0 {
		t.Fatalf("TLS 1.1 must fail legacy-tls: %+v", result.Failures)
	}
	for _, failure := range result.Failures {
		if failure.Check == CheckLegacyTLS && !strings.Contains(failure.Message, NameMozillaIntermediate) {
			t.Fatalf("legacy-tls message should name the preset: %q", failure.Message)
		}
	}
}

func TestMozillaCertKeyRules(t *testing.T) {
	tests := []struct {
		name     string
		preset   string
		cert     *x509.Certificate
		wantFail bool
	}{
		{"modern accepts ECDSA", NameMozillaModern, ecdsaCert(days(90)), false},
		{"modern rejects RSA 4096", NameMozillaModern, rsaCert(4096, days(90)), true},
		{"intermediate accepts RSA 2048", NameMozillaIntermediate, rsaCert(2048, days(90)), false},
		{"intermediate accepts ECDSA", NameMozillaIntermediate, ecdsaCert(days(90)), false},
		{"intermediate rejects RSA 1024", NameMozillaIntermediate, rsaCert(1024, days(90)), true},
		{"intermediate rejects a missing certificate", NameMozillaIntermediate, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failure, failed := certKeyFailure(supportedResult("TLS 1.3", tls.VersionTLS13, tt.cert), tt.preset)
			if failed != tt.wantFail {
				t.Fatalf("certKeyFailure() failed = %v, want %v (%+v)", failed, tt.wantFail, failure)
			}
			if failed && failure.Check != CheckCertKey {
				t.Fatalf("Check = %q, want %q", failure.Check, CheckCertKey)
			}
		})
	}
}

func TestMozillaIntermediateLifespanCeilingIs366Days(t *testing.T) {
	cert := rsaCert(2048, days(366))
	if _, failed := certLifespanFailure(supportedResult("TLS 1.2", tls.VersionTLS12, cert), NameMozillaIntermediate); failed {
		t.Fatal("366 days should be allowed")
	}
	cert = rsaCert(2048, days(398))
	if _, failed := certLifespanFailure(supportedResult("TLS 1.2", tls.VersionTLS12, cert), NameMozillaIntermediate); !failed {
		t.Fatal("398 days should fail")
	}
}

func TestMozillaPresetsFailWithoutCertificate(t *testing.T) {
	// A version found only by the raw probe has no certificate: the key and
	// lifespan checks cannot be answered and must not pass.
	raw := scan.TLSScanResult{Version: "TLS 1.2", VersionID: tls.VersionTLS12, Supported: true, VersionEvidence: scan.VersionEvidenceRawProbe}
	result := Evaluate([]scan.TLSScanResult{raw}, Config{Name: NameMozillaIntermediate}, presetNow)
	checks := failureChecks(result)
	if checks[CheckCertKey] == 0 || checks[CheckCertLifespan] == 0 {
		t.Fatalf("missing cert-key or cert-lifespan failure: %+v", result.Failures)
	}
}

func TestMozillaPresetScanRequirements(t *testing.T) {
	if got := MinimumScanVersion(Config{Name: NameMozillaModern}, tls.VersionTLS13); got != tls.VersionTLS10 {
		t.Fatalf("MinimumScanVersion(mozilla-modern) = %#x, want TLS 1.0 so the forbidden versions are scanned", got)
	}
	if RequiresCipherProbe(Config{Name: NameMozillaModern}) {
		t.Fatal("mozilla-modern is decided by the versions; it needs no cipher probe")
	}
	if !RequiresCipherProbe(Config{Name: NameMozillaIntermediate}) {
		t.Fatal("mozilla-intermediate needs the TLS 1.2 cipher list")
	}
	if RequiresGroupProbe(Config{Name: NameMozillaModern}) || RequiresGroupProbe(Config{Name: NameMozillaIntermediate}) {
		t.Fatal("the presets must not require group enumeration; --require-pq stays optional")
	}
}

func TestMozillaPresetsCombineWithRequirePQ(t *testing.T) {
	config := Config{Name: NameMozillaModern, RequirePostQuantum: true}
	if !RequiresGroupProbe(config) {
		t.Fatal("--require-pq on top of a preset must still require the group probe")
	}
	result := Evaluate(tls13Only(ecdsaCert(days(90))), config, presetNow)
	if failureChecks(result)[CheckRequirePQ] == 0 {
		t.Fatalf("require-pq should fail without groups: %+v", result.Failures)
	}
}

func TestValidateConfigPresets(t *testing.T) {
	for _, name := range Names() {
		if err := ValidateConfig(Config{Name: name}); err != nil {
			t.Fatalf("ValidateConfig(%q) = %v", name, err)
		}
	}
	err := ValidateConfig(Config{Name: "mozilla-old"})
	if err == nil || !strings.Contains(err.Error(), `unknown policy "mozilla-old"`) || !strings.Contains(err.Error(), NameMozillaIntermediate) {
		t.Fatalf("unknown preset error = %v, want it to list the known names", err)
	}
	err = ValidateConfig(Config{Name: NameMozillaModern, RequiredTLSVersions: []uint16{tls.VersionTLS12}})
	if err == nil || !strings.Contains(err.Error(), "forbids TLS 1.2") {
		t.Fatalf("requiring TLS 1.2 under mozilla-modern = %v, want a conflict naming the preset", err)
	}
	err = ValidateConfig(Config{Name: NameMozillaModern, ForbiddenTLSVersions: []uint16{tls.VersionTLS13}})
	if err == nil || !strings.Contains(err.Error(), "requires TLS 1.3") {
		t.Fatalf("forbidding TLS 1.3 under mozilla-modern = %v, want a conflict naming the preset", err)
	}
	if err := ValidateConfig(Config{Name: NameMozillaIntermediate, RequiredTLSVersions: []uint16{tls.VersionTLS12}}); err != nil {
		t.Fatalf("requiring TLS 1.2 under mozilla-intermediate = %v", err)
	}
}

func TestExpandDoesNotModifyCallerSlices(t *testing.T) {
	forbidden := []uint16{tls.VersionTLS10}
	config := Config{Name: NameMozillaModern, ForbiddenTLSVersions: forbidden}
	expanded := expand(config)
	if len(forbidden) != 1 || len(config.ForbiddenTLSVersions) != 1 {
		t.Fatalf("expand modified the caller's config: %+v", config)
	}
	if len(expanded.ForbiddenTLSVersions) != 3 || len(expanded.RequiredTLSVersions) != 1 {
		t.Fatalf("expanded gates = %+v", expanded)
	}
}

func TestModernPresetKeepsItsMeaning(t *testing.T) {
	// The original preset stays a TLS 1.2 baseline: TLS 1.2 passes, and the
	// new certificate checks are not part of it.
	cert := rsaCert(2048, days(398))
	results := []scan.TLSScanResult{
		supportedResult("TLS 1.2", tls.VersionTLS12, cert, "TLS_RSA_WITH_AES_128_GCM_SHA256"),
	}
	result := Evaluate(results, Config{Name: NameModern}, presetNow)
	checks := failureChecks(result)
	for _, check := range []string{CheckCertKey, CheckCertLifespan, CheckCipherAllowlist, CheckForbiddenTLS, CheckRequiredTLS} {
		if checks[check] != 0 {
			t.Fatalf("modern must not report %q: %+v", check, result.Failures)
		}
	}
}
