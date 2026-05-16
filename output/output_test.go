package output

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"github.com/olelbis/tlsanalyzer/scan"
)

func TestBuildMarkdownReportFromResults(t *testing.T) {
	cert := &x509.Certificate{
		Subject:   pkixName("example.com"),
		Issuer:    pkixName("Example CA"),
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Now().Add(48 * time.Hour),
		DNSNames:  []string{"example.com", "www.example.com"},
	}

	report := BuildMarkdownReportFromResults("example.com", "443", []scan.TLSScanResult{
		{Version: "TLS 1.0", Supported: false},
		{
			Version:               "TLS 1.2",
			Supported:             true,
			CipherSuites:          []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			Certificate:           cert,
			CertValidationStatus:  "valid",
			CertValidationMessage: "certificate validation passed",
		},
		{
			Version:              "TLS 1.3",
			Supported:            true,
			CipherSuites:         []string{"TLS_AES_128_GCM_SHA256"},
			CipherSuitesObserved: true,
		},
	})

	expectedFragments := []string{
		"# TLS Scan Report for host example.com:443",
		"- ❌ TLS 1.0",
		"- ✅ TLS 1.2 (certificate: valid - certificate validation passed)",
		"### TLS 1.2 Supported Cipher Suites",
		"### TLS 1.3 Observed Cipher Suites",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 🟢 SECURE",
		"**Subject CN**: example.com",
		"**Issuer**: Example CA",
		"**Certificate Validation**: valid",
		"**Certificate Validation Details**: certificate validation passed",
		"**DNS Names**: example.com, www.example.com",
	}

	for _, fragment := range expectedFragments {
		if !strings.Contains(report, fragment) {
			t.Fatalf("report does not contain %q:\n%s", fragment, report)
		}
	}
}

func pkixName(commonName string) pkix.Name {
	return pkix.Name{CommonName: commonName}
}
