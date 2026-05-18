package output

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/xml"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/olelbis/tlsanalyzer/policy"
	"github.com/olelbis/tlsanalyzer/scan"
)

func TestBuildMarkdownReportFromResults(t *testing.T) {
	generatedAt := time.Date(2026, 5, 16, 20, 30, 0, 0, time.UTC)
	cert := &x509.Certificate{
		Subject:            pkixName("example.com"),
		Issuer:             pkixName("Example CA"),
		NotBefore:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           generatedAt.Add(48 * time.Hour),
		DNSNames:           []string{"example.com", "www.example.com"},
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          testRSAPublicKey(),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	report := BuildMarkdownReportFromResults("example.com", "443", "service.example.com", "vtest", generatedAt, []scan.TLSScanResult{
		{Version: "TLS 1.0", Supported: false},
		{
			Version:               "TLS 1.2",
			VersionID:             0x0303,
			Supported:             true,
			Status:                scan.ScanStatusSupported,
			DurationMillis:        12,
			HandshakeAttempts:     20,
			KeyExchangeGroup:      "X25519",
			ALPNProtocol:          "h2",
			CipherDiscovery:       scan.CipherDiscoveryProbed,
			NegotiatedCipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			CipherSuites:          []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			Certificate:           cert,
			CertValidationStatus:  "valid",
			CertValidationMessage: "certificate validation passed",
		},
		{
			Version:                   "TLS 1.3",
			VersionID:                 0x0304,
			Supported:                 true,
			Status:                    scan.ScanStatusSupported,
			HandshakeAttempts:         11,
			KeyExchangeGroup:          "X25519",
			ALPNProtocol:              "h2",
			CipherDiscovery:           scan.CipherDiscoveryRawProbed,
			CipherSuites:              []string{"TLS_AES_128_GCM_SHA256"},
			CipherProbeDurationMillis: 9,
			CipherProbeResults: []scan.CipherProbeStatus{{
				CipherSuite: "TLS_AES_128_GCM_SHA256",
				Status:      "supported",
				Evidence:    "clienthello-serverhello",
			}},
			Warnings: []string{"TLS 1.3 cipher suites were raw-probed with ClientHello-only handshakes; full TLS handshakes are not completed by the raw probe."},
		},
	})

	expectedFragments := []string{
		"# TLS Scan Report for host example.com:443",
		"**Server Name**: service.example.com",
		"**Generated At**: 2026-05-16T20:30:00Z",
		"**Scanner Version**: vtest",
		"**JSON Schema Version**: 1.1",
		"## Summary",
		"**Supported TLS Versions**: 2 of 3 tested",
		"| TLS 1.0 | no |",
		"| TLS 1.2 | yes | supported | valid | X25519 | h2 | 12 ms | 20 |",
		"**Negotiated**: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"**Discovery**: raw-probed",
		"#### Cipher Probe Results",
		"Raw probe evidence is ClientHello-only. `clienthello-serverhello` and `clienthello-hrr-serverhello` evidence means the server selected a cipher in ServerHello, but the probe still does not complete a full TLS handshake.",
		"| TLS_AES_128_GCM_SHA256 | supported | clienthello-serverhello | - | - | - | - |",
		"| TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | 🟢 SECURE |",
		"**Subject CN**: example.com",
		"**Issuer**: Example CA",
		"**Public Key**: RSA 2048-bit",
		"**Signature Algorithm**: SHA256-RSA",
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
		Raw:                []byte("same-cert"),
		Subject:            pkixName("example.com"),
		Issuer:             pkixName("Example CA"),
		NotBefore:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           generatedAt.Add(48 * time.Hour),
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          testRSAPublicKey(),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	report := BuildMarkdownReportFromResults("example.com", "443", "", "vtest", generatedAt, []scan.TLSScanResult{
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
		Subject:            pkixName("example.com"),
		Issuer:             pkixName("Example CA"),
		NotBefore:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           generatedAt.Add(48 * time.Hour),
		DNSNames:           []string{"example.com"},
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          testRSAPublicKey(),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	data, err := BuildJSONReport("example.com", "443", "service.example.com", "vtest", generatedAt, []scan.TLSScanResult{
		{
			Version:                   "TLS 1.3",
			VersionID:                 0x0304,
			Supported:                 true,
			Status:                    scan.ScanStatusSupported,
			DurationMillis:            12,
			HandshakeAttempts:         20,
			KeyExchangeGroup:          "X25519",
			ALPNProtocol:              "h2",
			CipherDiscovery:           scan.CipherDiscoveryRawProbed,
			NegotiatedCipherSuite:     "TLS_AES_128_GCM_SHA256",
			CipherSuites:              []string{"TLS_AES_128_GCM_SHA256"},
			CipherProbeDurationMillis: 4,
			CipherProbeResults: []scan.CipherProbeStatus{{
				CipherSuite: "TLS_AES_128_GCM_SHA256",
				Status:      "supported",
				Evidence:    "clienthello-serverhello",
			}},
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
	if report.ServerName != "service.example.com" {
		t.Fatalf("ServerName = %q, want service.example.com", report.ServerName)
	}
	if report.SchemaVersion != JSONSchemaVersion {
		t.Fatalf("SchemaVersion = %q, want %q", report.SchemaVersion, JSONSchemaVersion)
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
	if report.Results[0].Certificate.DaysUntilExpiry != 2 {
		t.Fatalf("DaysUntilExpiry = %d, want 2", report.Results[0].Certificate.DaysUntilExpiry)
	}
	if report.Results[0].KeyExchangeGroup != "X25519" {
		t.Fatalf("KeyExchangeGroup = %q, want X25519", report.Results[0].KeyExchangeGroup)
	}
	if report.Results[0].ALPNProtocol != "h2" {
		t.Fatalf("ALPNProtocol = %q, want h2", report.Results[0].ALPNProtocol)
	}
	if report.Results[0].Certificate.PublicKeyAlgorithm != "RSA" || report.Results[0].Certificate.PublicKeyBits != 2048 {
		t.Fatalf("unexpected public key metadata: %+v", report.Results[0].Certificate)
	}
	if report.Results[0].Certificate.SignatureAlgorithm != "SHA256-RSA" {
		t.Fatalf("SignatureAlgorithm = %q, want SHA256-RSA", report.Results[0].Certificate.SignatureAlgorithm)
	}
	if report.Results[0].CipherDiscovery != scan.CipherDiscoveryRawProbed {
		t.Fatalf("CipherDiscovery = %q, want %q", report.Results[0].CipherDiscovery, scan.CipherDiscoveryRawProbed)
	}
	if report.Results[0].NegotiatedCipherSuite == "" {
		t.Fatal("expected negotiated cipher in first JSON result")
	}
	if len(report.Results[0].CipherProbeResults) != 1 {
		t.Fatalf("CipherProbeResults = %d, want 1", len(report.Results[0].CipherProbeResults))
	}
	if report.Results[0].CipherProbeResults[0].Evidence != "clienthello-serverhello" {
		t.Fatalf("CipherProbeResults[0].Evidence = %q, want clienthello-serverhello", report.Results[0].CipherProbeResults[0].Evidence)
	}
	if report.Results[0].RawProbeFullHandshake == nil || *report.Results[0].RawProbeFullHandshake {
		t.Fatalf("RawProbeFullHandshake = %v, want false", report.Results[0].RawProbeFullHandshake)
	}
	if report.Results[1].Status != scan.ScanStatusUnsupported {
		t.Fatalf("unsupported status = %q", report.Results[1].Status)
	}
}

func TestBuildJSONReportIncludesPolicyWhenProvided(t *testing.T) {
	data, err := BuildJSONReport("example.com", "443", "", "vtest", time.Date(2026, 5, 16, 20, 30, 0, 0, time.UTC), nil, &policy.Result{
		Enabled: true,
		Name:    policy.NameModern,
		Passed:  false,
		Failures: []policy.Failure{{
			Check:   policy.CheckLegacyTLS,
			Version: "TLS 1.0",
			Message: "legacy TLS is supported",
		}},
	})
	if err != nil {
		t.Fatalf("BuildJSONReport() error = %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\n%s", err, string(data))
	}
	if report.Policy == nil {
		t.Fatal("expected policy result in JSON report")
	}
	if report.Policy.Passed {
		t.Fatal("policy should be failed")
	}
	if len(report.Policy.Failures) != 1 {
		t.Fatalf("policy failures = %d, want 1", len(report.Policy.Failures))
	}
}

func TestBuildSARIFReportIncludesPolicyFailures(t *testing.T) {
	data, err := BuildSARIFReport("example.com", "443", "service.example.com", "vtest", []scan.TLSScanResult{{
		Version:              "TLS 1.0",
		VersionID:            0x0301,
		Supported:            true,
		Status:               scan.ScanStatusSupported,
		CipherDiscovery:      scan.CipherDiscoveryNegotiated,
		CertValidationStatus: scan.CertValidationValid,
	}}, &policy.Result{
		Enabled: true,
		Name:    policy.NameModern,
		Passed:  false,
		Failures: []policy.Failure{{
			Check:   policy.CheckLegacyTLS,
			Version: "TLS 1.0",
			Message: "TLS 1.0 is supported; modern policy requires TLS 1.2 or newer",
		}},
	})
	if err != nil {
		t.Fatalf("BuildSARIFReport() error = %v", err)
	}

	var report sarifLog
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\n%s", err, string(data))
	}
	if report.Version != "2.1.0" {
		t.Fatalf("SARIF version = %q, want 2.1.0", report.Version)
	}
	if len(report.Runs) != 1 || len(report.Runs[0].Results) != 1 {
		t.Fatalf("unexpected SARIF runs/results: %+v", report)
	}
	result := report.Runs[0].Results[0]
	if result.RuleID != policy.CheckLegacyTLS || result.Level != "error" {
		t.Fatalf("unexpected SARIF result: %+v", result)
	}
	if result.Message.Text == "" || !strings.Contains(result.Message.Text, "TLS 1.0 is supported") {
		t.Fatalf("unexpected SARIF message: %+v", result.Message)
	}
	if got := result.Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "tlsanalyzer://example.com:443%20sni=service.example.com" {
		t.Fatalf("SARIF target URI = %q", got)
	}
}

func TestBuildSARIFReportWithoutPolicyHasNoResults(t *testing.T) {
	data, err := BuildSARIFReport("example.com", "443", "", "vtest", nil, nil)
	if err != nil {
		t.Fatalf("BuildSARIFReport() error = %v", err)
	}

	var report sarifLog
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\n%s", err, string(data))
	}
	if len(report.Runs) != 1 {
		t.Fatalf("SARIF runs = %d, want 1", len(report.Runs))
	}
	if len(report.Runs[0].Results) != 0 {
		t.Fatalf("SARIF results = %d, want 0", len(report.Runs[0].Results))
	}
}

func TestBuildSARIFReportIncludesScanErrors(t *testing.T) {
	data, err := BuildSARIFReport("example.com", "443", "", "vtest", []scan.TLSScanResult{{
		Version:      "TLS 1.3",
		Supported:    false,
		Status:       scan.ScanStatusNetworkError,
		ErrorMessage: "connection refused",
	}}, nil)
	if err != nil {
		t.Fatalf("BuildSARIFReport() error = %v", err)
	}

	var report sarifLog
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\n%s", err, string(data))
	}
	if len(report.Runs) != 1 || len(report.Runs[0].Results) != 1 {
		t.Fatalf("unexpected SARIF runs/results: %+v", report)
	}
	result := report.Runs[0].Results[0]
	if result.RuleID != "scan-network-error" {
		t.Fatalf("RuleID = %q, want scan-network-error", result.RuleID)
	}
	if !strings.Contains(result.Message.Text, "connection refused") {
		t.Fatalf("message = %q, want connection error", result.Message.Text)
	}
}

func TestBuildJUnitReportIncludesScanErrorsAndPolicyFailures(t *testing.T) {
	data, err := BuildJUnitReport("example.com", "443", "", "vtest", []scan.TLSScanResult{
		{
			Version:        "TLS 1.2",
			Supported:      true,
			Status:         scan.ScanStatusSupported,
			DurationMillis: 15,
		},
		{
			Version:        "TLS 1.3",
			Supported:      false,
			Status:         scan.ScanStatusTimeout,
			ErrorMessage:   "handshake timed out",
			DurationMillis: 1000,
		},
	}, &policy.Result{
		Enabled: true,
		Name:    policy.NameModern,
		Passed:  false,
		Failures: []policy.Failure{{
			Check:   policy.CheckRequiredTLS,
			Version: "TLS 1.3",
			Message: "TLS 1.3 is required by policy but was not supported",
		}},
	})
	if err != nil {
		t.Fatalf("BuildJUnitReport() error = %v", err)
	}

	var report junitTestSuites
	if err := xml.Unmarshal(data, &report); err != nil {
		t.Fatalf("xml.Unmarshal() error = %v\n%s", err, string(data))
	}
	if report.Tests != 3 || report.Failures != 1 || report.Errors != 1 {
		t.Fatalf("JUnit counts = tests %d failures %d errors %d", report.Tests, report.Failures, report.Errors)
	}
	if len(report.Suites) != 1 || len(report.Suites[0].TestCases) != 3 {
		t.Fatalf("unexpected JUnit suites/cases: %+v", report)
	}
	if report.Suites[0].TestCases[1].Error == nil {
		t.Fatalf("expected scan timeout as JUnit error:\n%s", string(data))
	}
	if report.Suites[0].TestCases[2].Failure == nil {
		t.Fatalf("expected policy failure as JUnit failure:\n%s", string(data))
	}
}

func TestBuildJSONReportGolden(t *testing.T) {
	generatedAt := time.Date(2026, 5, 16, 20, 30, 0, 0, time.UTC)
	data, err := BuildJSONReport("example.com", "443", "", "vtest", generatedAt, []scan.TLSScanResult{
		{
			Version:                   "TLS 1.2",
			VersionID:                 0x0303,
			Supported:                 true,
			Status:                    scan.ScanStatusSupported,
			DurationMillis:            12,
			HandshakeAttempts:         21,
			KeyExchangeGroup:          "X25519",
			ALPNProtocol:              "h2",
			CipherDiscovery:           scan.CipherDiscoveryProbed,
			NegotiatedCipherSuite:     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			CipherSuites:              []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			CipherProbeDurationMillis: 4,
			CertValidationStatus:      scan.CertValidationValid,
			CertValidationMessage:     "certificate validation passed",
		},
		{
			Version:           "TLS 1.0",
			VersionID:         0x0301,
			Supported:         false,
			Status:            scan.ScanStatusUnsupported,
			ErrorMessage:      "protocol version not supported",
			DurationMillis:    7,
			HandshakeAttempts: 1,
			CipherDiscovery:   scan.CipherDiscoveryNegotiated,
		},
	}, &policy.Result{
		Enabled: true,
		Name:    policy.NameModern,
		Passed:  false,
		Failures: []policy.Failure{{
			Check:   policy.CheckLegacyTLS,
			Version: "TLS 1.0",
			Message: "TLS 1.0 is supported",
		}},
	})
	if err != nil {
		t.Fatalf("BuildJSONReport() error = %v", err)
	}

	expected := `{
  "host": "example.com",
  "port": "443",
  "schema_version": "1.1",
  "scanner_version": "vtest",
  "generated_at": "2026-05-16T20:30:00Z",
  "policy": {
    "enabled": true,
    "name": "modern",
    "passed": false,
    "failures": [
      {
        "check": "legacy-tls",
        "version": "TLS 1.0",
        "message": "TLS 1.0 is supported"
      }
    ]
  },
  "results": [
    {
      "version": "TLS 1.2",
      "version_id": 771,
      "supported": true,
      "status": "supported",
      "duration_millis": 12,
      "handshake_attempts": 21,
      "key_exchange_group": "X25519",
      "alpn_protocol": "h2",
      "cipher_discovery": "probed",
      "negotiated_cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "cipher_suites": [
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
      ],
      "cipher_suites_observed": false,
      "cipher_probe_duration_millis": 4,
      "certificate_validation_status": "valid",
      "certificate_validation_message": "certificate validation passed"
    },
    {
      "version": "TLS 1.0",
      "version_id": 769,
      "supported": false,
      "status": "unsupported",
      "error_message": "protocol version not supported",
      "duration_millis": 7,
      "handshake_attempts": 1,
      "cipher_discovery": "negotiated",
      "cipher_suites_observed": false
    }
  ]
}`
	if string(data) != expected {
		t.Fatalf("JSON report changed.\nwant:\n%s\n\ngot:\n%s", expected, string(data))
	}
}

func TestPrintScanSummary(t *testing.T) {
	var buf bytes.Buffer
	PrintScanSummary(&buf, []scan.TLSScanResult{
		{
			Version:              "TLS 1.2",
			VersionID:            0x0303,
			Supported:            true,
			CipherDiscovery:      scan.CipherDiscoveryNegotiated,
			CipherSuites:         []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			CertValidationStatus: scan.CertValidationValid,
		},
		{
			Version:         "TLS 1.3",
			VersionID:       0x0304,
			Supported:       true,
			CipherDiscovery: scan.CipherDiscoveryRawProbed,
			CipherSuites:    []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"},
			CipherProbeResults: []scan.CipherProbeStatus{
				{CipherSuite: "TLS_AES_128_GCM_SHA256", Status: "supported", Evidence: "clienthello-serverhello"},
				{CipherSuite: "TLS_AES_256_GCM_SHA384", Status: "supported", Evidence: "clienthello-serverhello"},
				{CipherSuite: "TLS_CHACHA20_POLY1305_SHA256", Status: "supported", Evidence: "clienthello-serverhello"},
			},
		},
		{
			Version:   "TLS 1.0",
			Supported: false,
		},
	})

	expectedFragments := []string{
		"Summary:",
		"Supported TLS versions: 2 of 3 tested",
		"Protocol findings: no legacy TLS versions detected",
		"Certificate validation: valid",
		"Cipher findings: no weak cipher suites detected in mixed (negotiated, raw-probed) evidence",
		"Raw probe: 3/3 ciphers supported (ClientHello-only ServerHello evidence; no full handshakes)",
	}
	for _, fragment := range expectedFragments {
		if !strings.Contains(buf.String(), fragment) {
			t.Fatalf("summary does not contain %q:\n%s", fragment, buf.String())
		}
	}
}

func TestPrintScanSummaryReportsLegacyTLSAndLegacyCBC(t *testing.T) {
	var buf bytes.Buffer
	PrintScanSummary(&buf, []scan.TLSScanResult{
		{
			Version:         "TLS 1.0",
			VersionID:       0x0301,
			Supported:       true,
			CipherDiscovery: scan.CipherDiscoveryNegotiated,
			CipherSuites:    []string{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
		},
	})

	expectedFragments := []string{
		"Protocol findings: legacy TLS versions supported: TLS 1.0",
		"Cipher findings: legacy CBC cipher suites detected in negotiated evidence",
	}
	for _, fragment := range expectedFragments {
		if !strings.Contains(buf.String(), fragment) {
			t.Fatalf("summary does not contain %q:\n%s", fragment, buf.String())
		}
	}
}

func TestPrintScanSummaryReportsUnknownCipherEvidence(t *testing.T) {
	var buf bytes.Buffer
	PrintScanSummary(&buf, []scan.TLSScanResult{
		{
			Version:         "TLS 1.2",
			VersionID:       0x0303,
			Supported:       true,
			CipherDiscovery: scan.CipherDiscoveryProbed,
			CipherSuites:    []string{"TLS_PRIVATE_UNKNOWN_CIPHER"},
		},
	})

	if !strings.Contains(buf.String(), "Cipher findings: unknown cipher suites detected in probed evidence") {
		t.Fatalf("summary should report unknown cipher evidence:\n%s", buf.String())
	}
}

func TestPrintCompactScanResults(t *testing.T) {
	var buf bytes.Buffer
	PrintCompactScanResults(&buf, []scan.TLSScanResult{
		{
			Version:              "TLS 1.3",
			Supported:            true,
			Status:               scan.ScanStatusSupported,
			HandshakeAttempts:    4,
			KeyExchangeGroup:     "X25519",
			ALPNProtocol:         "h2",
			CipherDiscovery:      scan.CipherDiscoveryRawProbed,
			CertValidationStatus: scan.CertValidationValid,
		},
		{
			Version:           "TLS 1.0",
			Supported:         false,
			Status:            scan.ScanStatusUnsupported,
			ErrorMessage:      "protocol version not supported",
			HandshakeAttempts: 1,
		},
	})

	expectedFragments := []string{
		"TLS Results:",
		"TLS 1.3 supported cert=valid cipher=raw-probed kx=X25519 alpn=h2 attempts=4",
		"TLS 1.0 unsupported error=protocol version not supported attempts=1",
	}
	for _, fragment := range expectedFragments {
		if !strings.Contains(buf.String(), fragment) {
			t.Fatalf("compact results do not contain %q:\n%s", fragment, buf.String())
		}
	}
}

func pkixName(commonName string) pkix.Name {
	return pkix.Name{CommonName: commonName}
}

func testRSAPublicKey() *rsa.PublicKey {
	return &rsa.PublicKey{
		N: new(big.Int).Lsh(big.NewInt(1), 2047),
		E: 65537,
	}
}
