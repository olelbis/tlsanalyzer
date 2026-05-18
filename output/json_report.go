package output

import (
	"encoding/json"
	"time"

	"github.com/olelbis/tlsanalyzer/policy"
	"github.com/olelbis/tlsanalyzer/scan"
)

const JSONSchemaVersion = "1.1"

type JSONReport struct {
	Host           string           `json:"host"`
	Port           string           `json:"port"`
	ServerName     string           `json:"server_name,omitempty"`
	SchemaVersion  string           `json:"schema_version"`
	ScannerVersion string           `json:"scanner_version"`
	GeneratedAt    string           `json:"generated_at"`
	Policy         *policy.Result   `json:"policy,omitempty"`
	Results        []JSONScanResult `json:"results"`
}

type JSONScanResult struct {
	Version                   string            `json:"version"`
	VersionID                 uint16            `json:"version_id"`
	Supported                 bool              `json:"supported"`
	Status                    string            `json:"status"`
	ErrorMessage              string            `json:"error_message,omitempty"`
	DurationMillis            int64             `json:"duration_millis"`
	HandshakeAttempts         int               `json:"handshake_attempts"`
	KeyExchangeGroup          string            `json:"key_exchange_group,omitempty"`
	ALPNProtocol              string            `json:"alpn_protocol,omitempty"`
	CipherDiscovery           string            `json:"cipher_discovery"`
	NegotiatedCipherSuite     string            `json:"negotiated_cipher_suite,omitempty"`
	CipherSuites              []string          `json:"cipher_suites,omitempty"`
	CipherSuitesObserved      bool              `json:"cipher_suites_observed"`
	CipherProbeDurationMillis int64             `json:"cipher_probe_duration_millis,omitempty"`
	CipherProbeResults        []JSONProbeResult `json:"cipher_probe_results,omitempty"`
	RawProbeFullHandshake     *bool             `json:"raw_probe_completed_full_handshake,omitempty"`
	Warnings                  []string          `json:"warnings,omitempty"`
	Certificate               *JSONCertificate  `json:"certificate,omitempty"`
	CertValidationStatus      string            `json:"certificate_validation_status,omitempty"`
	CertValidationMessage     string            `json:"certificate_validation_message,omitempty"`
}

type JSONProbeResult struct {
	CipherSuite              string `json:"cipher_suite"`
	Status                   string `json:"status"`
	Evidence                 string `json:"evidence,omitempty"`
	Alert                    string `json:"alert,omitempty"`
	AlertLevel               *uint8 `json:"alert_level,omitempty"`
	AlertDescription         *uint8 `json:"alert_description,omitempty"`
	SelectedGroup            string `json:"selected_group,omitempty"`
	HelloRetryRequest        bool   `json:"hello_retry_request,omitempty"`
	HelloRetryRequestRetried bool   `json:"hello_retry_request_retried,omitempty"`
	Error                    string `json:"error,omitempty"`
}

type JSONCertificate struct {
	SubjectCommonName  string   `json:"subject_common_name"`
	IssuerCommonName   string   `json:"issuer_common_name"`
	ValidFrom          string   `json:"valid_from"`
	ValidTo            string   `json:"valid_to"`
	DaysUntilExpiry    int      `json:"days_until_expiry"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm,omitempty"`
	PublicKeyBits      int      `json:"public_key_bits,omitempty"`
	PublicKeyCurve     string   `json:"public_key_curve,omitempty"`
	SignatureAlgorithm string   `json:"signature_algorithm,omitempty"`
	DNSNames           []string `json:"dns_names,omitempty"`
}

func BuildJSONReport(host, port, serverName, scannerVersion string, generatedAt time.Time, results []scan.TLSScanResult, policyResults ...*policy.Result) ([]byte, error) {
	policyResult := firstPolicyResult(policyResults)
	report := JSONReport{
		Host:           host,
		Port:           port,
		ServerName:     serverName,
		SchemaVersion:  JSONSchemaVersion,
		ScannerVersion: scannerVersion,
		GeneratedAt:    generatedAt.UTC().Format(time.RFC3339),
		Policy:         policyResult,
		Results:        make([]JSONScanResult, 0, len(results)),
	}

	for _, r := range results {
		jsonResult := JSONScanResult{
			Version:                   r.Version,
			VersionID:                 r.VersionID,
			Supported:                 r.Supported,
			Status:                    r.Status,
			ErrorMessage:              r.ErrorMessage,
			DurationMillis:            r.DurationMillis,
			HandshakeAttempts:         r.HandshakeAttempts,
			KeyExchangeGroup:          r.KeyExchangeGroup,
			ALPNProtocol:              r.ALPNProtocol,
			CipherDiscovery:           r.CipherDiscovery,
			NegotiatedCipherSuite:     r.NegotiatedCipherSuite,
			CipherSuites:              r.CipherSuites,
			CipherSuitesObserved:      r.CipherSuitesObserved,
			CipherProbeDurationMillis: r.CipherProbeDurationMillis,
			CipherProbeResults:        buildJSONProbeResults(r.CipherProbeResults),
			RawProbeFullHandshake:     rawProbeFullHandshakeFlag(r),
			Warnings:                  r.Warnings,
			CertValidationStatus:      r.CertValidationStatus,
			CertValidationMessage:     r.CertValidationMessage,
		}
		if r.Certificate != nil {
			publicKeyAlgorithm, publicKeyBits, publicKeyCurve := certificatePublicKeyMetadata(r.Certificate)
			daysUntilExpiry := daysUntilCertificateExpiry(r.Certificate, generatedAt)
			jsonResult.Certificate = &JSONCertificate{
				SubjectCommonName:  r.Certificate.Subject.CommonName,
				IssuerCommonName:   r.Certificate.Issuer.CommonName,
				ValidFrom:          r.Certificate.NotBefore.Format(time.RFC3339),
				ValidTo:            r.Certificate.NotAfter.Format(time.RFC3339),
				DaysUntilExpiry:    daysUntilExpiry,
				PublicKeyAlgorithm: publicKeyAlgorithm,
				PublicKeyBits:      publicKeyBits,
				PublicKeyCurve:     publicKeyCurve,
				SignatureAlgorithm: certificateSignatureAlgorithm(r.Certificate),
				DNSNames:           r.Certificate.DNSNames,
			}
		}
		report.Results = append(report.Results, jsonResult)
	}

	return json.MarshalIndent(report, "", "  ")
}

func buildJSONProbeResults(results []scan.CipherProbeStatus) []JSONProbeResult {
	if len(results) == 0 {
		return nil
	}
	jsonResults := make([]JSONProbeResult, 0, len(results))
	for _, result := range results {
		jsonResults = append(jsonResults, JSONProbeResult{
			CipherSuite:              result.CipherSuite,
			Status:                   result.Status,
			Evidence:                 result.Evidence,
			Alert:                    result.Alert,
			AlertLevel:               alertCodePointer(result.Alert, result.AlertLevel),
			AlertDescription:         alertCodePointer(result.Alert, result.AlertDescription),
			SelectedGroup:            result.SelectedGroup,
			HelloRetryRequest:        result.HelloRetryRequest,
			HelloRetryRequestRetried: result.HelloRetryRequestRetried,
			Error:                    result.Error,
		})
	}
	return jsonResults
}

func alertCodePointer(alert string, code uint8) *uint8 {
	if alert == "" {
		return nil
	}
	return &code
}

func rawProbeFullHandshakeFlag(result scan.TLSScanResult) *bool {
	if result.CipherDiscovery != scan.CipherDiscoveryRawProbed {
		return nil
	}
	completed := false
	return &completed
}
