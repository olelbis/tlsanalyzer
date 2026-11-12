package output

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/olelbis/tlsanalyzer/scan"
)

func extendedProbeResult() scan.TLSScanResult {
	return scan.TLSScanResult{
		Version:               "TLS 1.2",
		VersionID:             tls.VersionTLS12,
		Supported:             true,
		Status:                scan.ScanStatusSupported,
		CipherDiscovery:       scan.CipherDiscoveryProbed,
		NegotiatedCipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		CipherSuites:          []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_RC4_128_MD5"},
		CipherProbeResults: []scan.CipherProbeStatus{
			{CipherSuite: "TLS_RSA_WITH_RC4_128_MD5", Status: "supported", Evidence: "clienthello-serverhello"},
		},
	}
}

func TestPrintCipherSuitesForResultMarksRawProbedSuites(t *testing.T) {
	var buf bytes.Buffer
	PrintCipherSuitesForResult(&buf, extendedProbeResult())
	out := buf.String()

	if !strings.Contains(out, "• TLS_RSA_WITH_RC4_128_MD5 (raw probe, ClientHello-only)\n") {
		t.Fatalf("raw-only suite should be marked:\n%s", out)
	}
	if !strings.Contains(out, "• TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\n") {
		t.Fatalf("full-handshake suite should not be marked:\n%s", out)
	}
	if strings.Contains(out, "⚠️") {
		t.Fatalf("a complete result should not print warnings:\n%s", out)
	}
}

func TestPrintCipherSuitesForResultShowsIncompleteWarnings(t *testing.T) {
	result := extendedProbeResult()
	result.CipherEvidenceIncomplete = true
	result.Warnings = []string{
		"TLS 1.2: 1 cipher suite(s) were confirmed only by ClientHello-only raw probes (listed in the cipher probe results); full TLS handshakes are not completed for them.",
		"TLS 1.2: the raw cipher enumeration could not finish (timeout); 31 of 124 legacy cipher suites were not classified, so the cipher list is incomplete.",
	}

	var buf bytes.Buffer
	PrintCipherSuitesForResult(&buf, result)
	out := buf.String()

	if !strings.Contains(out, "⚠️  TLS 1.2: the raw cipher enumeration could not finish") {
		t.Fatalf("console output should warn that the cipher list is incomplete:\n%s", out)
	}
	if strings.Contains(out, "⚠️  TLS 1.2: 1 cipher suite(s)") {
		t.Fatalf("informational warnings should stay out of the console list:\n%s", out)
	}
}

func TestRawProbedCipherSuitesOnlyAppliesToProbedDiscovery(t *testing.T) {
	result := extendedProbeResult()
	if raw := RawProbedCipherSuites(result); len(raw) != 1 || !raw["TLS_RSA_WITH_RC4_128_MD5"] {
		t.Fatalf("RawProbedCipherSuites() = %v, want only TLS_RSA_WITH_RC4_128_MD5", raw)
	}

	result.CipherDiscovery = scan.CipherDiscoveryRawProbed
	if raw := RawProbedCipherSuites(result); raw != nil {
		t.Fatalf("RawProbedCipherSuites() = %v for TLS 1.3 raw-probed discovery, want nil", raw)
	}
}

func TestJSONReportFlagsRawAndIncompleteEvidence(t *testing.T) {
	generatedAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	rawOnly := extendedProbeResult()
	rawOnly.CipherEvidenceIncomplete = true
	fullHandshakeOnly := extendedProbeResult()
	fullHandshakeOnly.CipherSuites = fullHandshakeOnly.CipherSuites[:1]
	fullHandshakeOnly.CipherProbeResults = nil

	data, err := BuildJSONReport("example.com", "443", "", "test", generatedAt, []scan.TLSScanResult{rawOnly, fullHandshakeOnly})
	if err != nil {
		t.Fatalf("BuildJSONReport() error = %v", err)
	}
	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if report.Results[0].CipherDiscovery != scan.CipherDiscoveryProbed {
		t.Fatalf("CipherDiscovery = %q, want %q", report.Results[0].CipherDiscovery, scan.CipherDiscoveryProbed)
	}
	if report.Results[0].RawProbeFullHandshake == nil || *report.Results[0].RawProbeFullHandshake {
		t.Fatalf("RawProbeFullHandshake = %v, want false when a suite has raw-only evidence", report.Results[0].RawProbeFullHandshake)
	}
	if !report.Results[0].CipherEvidenceIncomplete {
		t.Fatal("CipherEvidenceIncomplete = false, want true")
	}
	if !strings.Contains(string(data), `"cipher_evidence_incomplete": true`) {
		t.Fatalf("JSON should carry cipher_evidence_incomplete:\n%s", data)
	}

	if report.Results[1].RawProbeFullHandshake != nil {
		t.Fatalf("RawProbeFullHandshake = %v, want it omitted without raw evidence", *report.Results[1].RawProbeFullHandshake)
	}
	if strings.Count(string(data), "cipher_evidence_incomplete") != 1 {
		t.Fatalf("cipher_evidence_incomplete should be omitted for complete results:\n%s", data)
	}
}

func TestMarkdownReportExplainsRawEvidenceInProbedResults(t *testing.T) {
	generatedAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	report := BuildMarkdownReportFromResults("example.com", "443", "", "test", generatedAt, []scan.TLSScanResult{extendedProbeResult()})

	for _, want := range []string{
		"| TLS_RSA_WITH_RC4_128_MD5 | 🔴 INSECURE |",
		"#### Cipher Probe Results",
		"These rows are cipher suites confirmed only by ClientHello-only raw probes.",
		"| TLS_RSA_WITH_RC4_128_MD5 | supported | clienthello-serverhello |",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("Markdown report is missing %q:\n%s", want, report)
		}
	}
}
