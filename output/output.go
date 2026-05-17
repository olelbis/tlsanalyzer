// File: output/output.go
package output

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/olelbis/tlsanalyzer/policy"
	"github.com/olelbis/tlsanalyzer/scan"
	"github.com/olelbis/tlsanalyzer/utils"
)

const JSONSchemaVersion = "1.0"

type JSONReport struct {
	Host           string           `json:"host"`
	Port           string           `json:"port"`
	SchemaVersion  string           `json:"schema_version"`
	ScannerVersion string           `json:"scanner_version"`
	GeneratedAt    string           `json:"generated_at"`
	Policy         *policy.Result   `json:"policy,omitempty"`
	Results        []JSONScanResult `json:"results"`
}

type JSONScanResult struct {
	Version                   string           `json:"version"`
	VersionID                 uint16           `json:"version_id"`
	Supported                 bool             `json:"supported"`
	Status                    string           `json:"status"`
	ErrorMessage              string           `json:"error_message,omitempty"`
	DurationMillis            int64            `json:"duration_millis"`
	HandshakeAttempts         int              `json:"handshake_attempts"`
	CipherDiscovery           string           `json:"cipher_discovery"`
	NegotiatedCipherSuite     string           `json:"negotiated_cipher_suite,omitempty"`
	CipherSuites              []string         `json:"cipher_suites,omitempty"`
	CipherSuitesObserved      bool             `json:"cipher_suites_observed"`
	CipherProbeDurationMillis int64            `json:"cipher_probe_duration_millis,omitempty"`
	Warnings                  []string         `json:"warnings,omitempty"`
	Certificate               *JSONCertificate `json:"certificate,omitempty"`
	CertValidationStatus      string           `json:"certificate_validation_status,omitempty"`
	CertValidationMessage     string           `json:"certificate_validation_message,omitempty"`
}

type JSONCertificate struct {
	SubjectCommonName string   `json:"subject_common_name"`
	IssuerCommonName  string   `json:"issuer_common_name"`
	ValidFrom         string   `json:"valid_from"`
	ValidTo           string   `json:"valid_to"`
	DaysUntilExpiry   int      `json:"days_until_expiry"`
	DNSNames          []string `json:"dns_names,omitempty"`
}

func WriteMarkdownReportToFile(host, port, scannerVersion string, results []scan.TLSScanResult, outputPath string, policyResults ...*policy.Result) error {
	report := BuildMarkdownReportFromResults(host, port, scannerVersion, time.Now(), results, policyResults...)
	if !strings.HasSuffix(outputPath, ".md") {
		outputPath += ".md"
	}
	return os.WriteFile(outputPath, []byte(report), 0640)
}

func BuildMarkdownReportFromResults(host, port, scannerVersion string, generatedAt time.Time, results []scan.TLSScanResult, policyResults ...*policy.Result) string {
	policyResult := firstPolicyResult(policyResults)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# TLS Scan Report for host %s:%s\n\n", host, port))
	sb.WriteString(fmt.Sprintf("- **Generated At**: %s\n", generatedAt.UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("- **Scanner Version**: %s\n", scannerVersion))
	sb.WriteString(fmt.Sprintf("- **JSON Schema Version**: %s\n\n", JSONSchemaVersion))
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Supported TLS Versions**: %d\n", countSupported(results)))
	sb.WriteString(fmt.Sprintf("- **Certificate Validation**: %s\n", summarizeCertificateValidation(results)))
	sb.WriteString(fmt.Sprintf("- **Cipher Findings**: %s\n", summarizeCipherFindings(results)))
	if policyResult != nil && policyResult.Enabled {
		status := "passed"
		if !policyResult.Passed {
			status = "failed"
		}
		sb.WriteString(fmt.Sprintf("- **Policy**: %s (%s)\n", displayPolicyName(policyResult), status))
	}

	if policyResult != nil && policyResult.Enabled && len(policyResult.Failures) > 0 {
		sb.WriteString("\n## Policy Failures\n\n")
		sb.WriteString("| Check | TLS Version | Message |\n")
		sb.WriteString("| --- | --- | --- |\n")
		for _, failure := range policyResult.Failures {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", failure.Check, emptyDash(failure.Version), escapeTable(failure.Message)))
		}
	}

	sb.WriteString("\n## TLS Versions\n\n")
	sb.WriteString("| Version | Supported | Status | Certificate | Duration | Attempts |\n")
	sb.WriteString("| --- | --- | --- | --- | ---: | ---: |\n")
	for _, r := range results {
		supported := "no"
		if r.Supported {
			supported = "yes"
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %d ms | %d |\n", r.Version, supported, emptyDash(r.Status), emptyDash(r.CertValidationStatus), r.DurationMillis, r.HandshakeAttempts))
	}
	sb.WriteString("\n## Cipher Suites\n")
	for _, r := range results {
		if r.Supported && len(r.CipherSuites) > 0 {
			sb.WriteString(fmt.Sprintf("\n### %s\n\n", r.Version))
			sb.WriteString(fmt.Sprintf("- **Negotiated**: %s\n", emptyDash(r.NegotiatedCipherSuite)))
			sb.WriteString(fmt.Sprintf("- **Discovery**: %s\n", emptyDash(r.CipherDiscovery)))
			if r.CipherProbeDurationMillis > 0 {
				sb.WriteString(fmt.Sprintf("- **Cipher Probe Duration**: %d ms\n", r.CipherProbeDurationMillis))
			}
			for _, warning := range r.Warnings {
				sb.WriteString(fmt.Sprintf("- **Warning**: %s\n", warning))
			}
			sb.WriteString("\n| Cipher Suite | Classification |\n")
			sb.WriteString("| --- | --- |\n")
			for _, cs := range r.CipherSuites {
				label, ok := utils.CipherClassification[cs]
				if ok {
					sb.WriteString(fmt.Sprintf("| %s | %s |\n", cs, label))
				} else {
					sb.WriteString(fmt.Sprintf("| %s | ❓ UNKNOWN |\n", cs))
				}
			}
		}
	}

	certGroups := groupCertificateResults(results)
	if len(certGroups) > 0 {
		sb.WriteString("\n## Certificate Details\n")
		for _, group := range certGroups {
			sb.WriteString(fmt.Sprintf("\n### %s\n", strings.Join(group.Versions, ", ")))
			sb.WriteString(fmt.Sprintf("- **Subject CN**: %s\n", group.Certificate.Subject.CommonName))
			sb.WriteString(fmt.Sprintf("- **Issuer**: %s\n", group.Certificate.Issuer.CommonName))
			sb.WriteString(fmt.Sprintf("- **Valid From**: %s\n", group.Certificate.NotBefore.Format("2006-01-02")))
			sb.WriteString(fmt.Sprintf("- **Valid To**: %s\n", group.Certificate.NotAfter.Format("2006-01-02")))
			sb.WriteString(fmt.Sprintf("- **Days Until Expiry**: %d\n", int(time.Until(group.Certificate.NotAfter).Hours()/24)))
			sb.WriteString(fmt.Sprintf("- **Certificate Validation**: %s\n", group.ValidationStatus))
			if group.ValidationMessage != "" {
				sb.WriteString(fmt.Sprintf("- **Certificate Validation Details**: %s\n", group.ValidationMessage))
			}
			if len(group.Certificate.DNSNames) > 0 {
				sb.WriteString(fmt.Sprintf("- **DNS Names**: %s\n", strings.Join(group.Certificate.DNSNames, ", ")))
			}
		}
	}

	return sb.String()
}

func BuildJSONReport(host, port, scannerVersion string, generatedAt time.Time, results []scan.TLSScanResult, policyResults ...*policy.Result) ([]byte, error) {
	policyResult := firstPolicyResult(policyResults)
	report := JSONReport{
		Host:           host,
		Port:           port,
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
			CipherDiscovery:           r.CipherDiscovery,
			NegotiatedCipherSuite:     r.NegotiatedCipherSuite,
			CipherSuites:              r.CipherSuites,
			CipherSuitesObserved:      r.CipherSuitesObserved,
			CipherProbeDurationMillis: r.CipherProbeDurationMillis,
			Warnings:                  r.Warnings,
			CertValidationStatus:      r.CertValidationStatus,
			CertValidationMessage:     r.CertValidationMessage,
		}
		if r.Certificate != nil {
			jsonResult.Certificate = &JSONCertificate{
				SubjectCommonName: r.Certificate.Subject.CommonName,
				IssuerCommonName:  r.Certificate.Issuer.CommonName,
				ValidFrom:         r.Certificate.NotBefore.Format(time.RFC3339),
				ValidTo:           r.Certificate.NotAfter.Format(time.RFC3339),
				DaysUntilExpiry:   int(time.Until(r.Certificate.NotAfter).Hours() / 24),
				DNSNames:          r.Certificate.DNSNames,
			}
		}
		report.Results = append(report.Results, jsonResult)
	}

	return json.MarshalIndent(report, "", "  ")
}

func PrintScanSummary(w io.Writer, results []scan.TLSScanResult) {
	fmt.Fprintln(w, "\nSummary:")
	fmt.Fprintf(w, "  Supported TLS versions: %d\n", countSupported(results))
	fmt.Fprintf(w, "  Certificate validation: %s\n", summarizeCertificateValidation(results))
	fmt.Fprintf(w, "  Cipher findings: %s\n", summarizeCipherFindings(results))
}

func firstPolicyResult(policyResults []*policy.Result) *policy.Result {
	if len(policyResults) == 0 {
		return nil
	}
	return policyResults[0]
}

func countSupported(results []scan.TLSScanResult) int {
	count := 0
	for _, r := range results {
		if r.Supported {
			count++
		}
	}
	return count
}

func summarizeCertificateValidation(results []scan.TLSScanResult) string {
	statuses := make(map[string]bool)
	for _, r := range results {
		if r.Supported && r.CertValidationStatus != "" {
			statuses[r.CertValidationStatus] = true
		}
	}
	if len(statuses) == 0 {
		return "unavailable"
	}
	if statuses[scan.CertValidationInvalid] {
		return "invalid"
	}
	if statuses[scan.CertValidationSkipped] {
		return "skipped"
	}
	if statuses[scan.CertValidationUnavailable] {
		return "unavailable"
	}
	if statuses[scan.CertValidationValid] {
		return "valid"
	}
	return "mixed"
}

func summarizeCipherFindings(results []scan.TLSScanResult) string {
	for _, r := range results {
		for _, cipher := range r.CipherSuites {
			classification := utils.CipherClassification[cipher]
			if strings.Contains(classification, "INSECURE") {
				return "insecure cipher suites detected"
			}
			if strings.Contains(classification, "WEAK") {
				return "weak cipher suites detected"
			}
		}
	}
	return "no weak cipher suites detected"
}

func displayPolicyName(result *policy.Result) string {
	if result.Name == "" {
		return "custom"
	}
	return result.Name
}

func emptyDash(value string) string {
	if value == "" {
		return "-"
	}
	return escapeTable(value)
}

func escapeTable(value string) string {
	return strings.ReplaceAll(value, "|", "\\|")
}

type certificateGroup struct {
	Versions          []string
	Certificate       *x509.Certificate
	ValidationStatus  string
	ValidationMessage string
}

func groupCertificateResults(results []scan.TLSScanResult) []certificateGroup {
	var groups []certificateGroup
	indexByFingerprint := make(map[string]int)

	for _, result := range results {
		if !result.Supported || result.Certificate == nil {
			continue
		}

		fingerprint := certificateFingerprint(result.Certificate)
		if index, exists := indexByFingerprint[fingerprint]; exists {
			groups[index].Versions = append(groups[index].Versions, result.Version)
			continue
		}

		indexByFingerprint[fingerprint] = len(groups)
		groups = append(groups, certificateGroup{
			Versions:          []string{result.Version},
			Certificate:       result.Certificate,
			ValidationStatus:  result.CertValidationStatus,
			ValidationMessage: result.CertValidationMessage,
		})
	}

	return groups
}

func certificateFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func PrintCertSummary(w io.Writer, cert *x509.Certificate, cipher string, version string, checkExpiry bool, validation scan.CertValidation) {
	fmt.Fprintf(w, "✅ \033[1m%s\033[0m: supported\n", version)
	fmt.Fprintf(w, "   Negotiated Cipher suite: %s\n", cipher)
	fmt.Fprintf(w, "   CN: %s\n", cert.Subject.CommonName)
	fmt.Fprintf(w, "   Issuer: %s\n", cert.Issuer.CommonName)
	fmt.Fprintf(w, "   Valid: %s - %s\n", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	if validation.Status != "" {
		fmt.Fprintf(w, "   Certificate validation: %s\n", validation.Status)
	}
	if validation.Message != "" {
		fmt.Fprintf(w, "   Certificate validation details: %s\n", validation.Message)
	}

	if checkExpiry {
		fmt.Fprintf(w, "   Days to Expiration: %d\n", int(time.Until(cert.NotAfter).Hours()/24))
	}
	fmt.Fprintf(w, "   DNS: %v\n", cert.DNSNames)
}

func PrintCipherSuites(w io.Writer, ciphers []string, discovery string) {
	if len(ciphers) > 0 {
		switch discovery {
		case scan.CipherDiscoveryObserved:
			fmt.Fprintln(w, "   Observed cipher suites:")
		case scan.CipherDiscoveryProbed:
			fmt.Fprintln(w, "   Probed cipher suites:")
		default:
			fmt.Fprintln(w, "   Negotiated cipher suite:")
		}
		for _, cs := range ciphers {
			fmt.Fprintf(w, "     • %s\n", cs)
		}
	}
}
