package output

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/olelbis/tlsanalyzer/scan"
)

func TestBuildMarkdownReportFromResults(t *testing.T) {
	generatedAt := time.Date(2026, 5, 16, 20, 30, 0, 0, time.UTC)
	cert := &x509.Certificate{
		Subject:   pkixName("example.com"),
		Issuer:    pkixName("Example CA"),
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Now().Add(48 * time.Hour),
		DNSNames:  []string{"example.com", "www.example.com"},
	}

	report := BuildMarkdownReportFromResults("example.com", "443", "vtest", generatedAt, []scan.TLSScanResult{
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
		"**Generated At**: 2026-05-16T20:30:00Z",
		"**Scanner Version**: vtest",
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

func TestBuildMarkdownReportGroupsDuplicateCertificates(t *testing.T) {
	generatedAt := time.Date(2026, 5, 16, 20, 30, 0, 0, time.UTC)
	cert := &x509.Certificate{
		Raw:       []byte("same-cert"),
		Subject:   pkixName("example.com"),
		Issuer:    pkixName("Example CA"),
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Now().Add(48 * time.Hour),
	}

	report := BuildMarkdownReportFromResults("example.com", "443", "vtest", generatedAt, []scan.TLSScanResult{
		{Version: "TLS 1.2", Supported: true, Certificate: cert, CertValidationStatus: "valid"},
		{Version: "TLS 1.3", Supported: true, Certificate: cert, CertValidationStatus: "valid"},
	})

	if !strings.Contains(report, "### TLS 1.2, TLS 1.3") {
		t.Fatalf("report should group duplicate certificates by version:\n%s", report)
	}
	if strings.Count(report, "**Subject CN**") != 1 {
		t.Fatalf("report should render duplicate certificate details once:\n%s", report)
	}
}

func TestBuildJSONReport(t *testing.T) {
	generatedAt := time.Date(2026, 5, 16, 20, 30, 0, 0, time.UTC)
	cert := &x509.Certificate{
		Subject:   pkixName("example.com"),
		Issuer:    pkixName("Example CA"),
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Now().Add(48 * time.Hour),
		DNSNames:  []string{"example.com"},
	}

	data, err := BuildJSONReport("example.com", "443", "vtest", generatedAt, []scan.TLSScanResult{
		{
			Version:               "TLS 1.2",
			Supported:             true,
			Status:                scan.ScanStatusSupported,
			CipherSuites:          []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			Certificate:           cert,
			CertValidationStatus:  "valid",
			CertValidationMessage: "certificate validation passed",
		},
		{
			Version:      "TLS 1.0",
			Supported:    false,
			Status:       scan.ScanStatusUnsupported,
			ErrorMessage: "protocol version not supported",
		},
	})
	if err != nil {
		t.Fatalf("BuildJSONReport() error = %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\n%s", err, string(data))
	}
	if report.Host != "example.com" || report.Port != "443" || report.ScannerVersion != "vtest" {
		t.Fatalf("unexpected report metadata: %+v", report)
	}
	if report.GeneratedAt != "2026-05-16T20:30:00Z" {
		t.Fatalf("GeneratedAt = %q", report.GeneratedAt)
	}
	if len(report.Results) != 2 {
		t.Fatalf("len(Results) = %d, want 2", len(report.Results))
	}
	if report.Results[0].Certificate == nil {
		t.Fatal("expected certificate in first JSON result")
	}
	if report.Results[1].Status != scan.ScanStatusUnsupported {
		t.Fatalf("unsupported status = %q", report.Results[1].Status)
	}
}

func pkixName(commonName string) pkix.Name {
	return pkix.Name{CommonName: commonName}
}
