// File: output/output.go
package output

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/olelbis/tlsanalyzer/scan"
	"github.com/olelbis/tlsanalyzer/utils"
)

type JSONReport struct {
	Host           string           `json:"host"`
	Port           string           `json:"port"`
	ScannerVersion string           `json:"scanner_version"`
	GeneratedAt    string           `json:"generated_at"`
	Results        []JSONScanResult `json:"results"`
}

type JSONScanResult struct {
	Version               string           `json:"version"`
	Supported             bool             `json:"supported"`
	Status                string           `json:"status"`
	ErrorMessage          string           `json:"error_message,omitempty"`
	CipherSuites          []string         `json:"cipher_suites,omitempty"`
	CipherSuitesObserved  bool             `json:"cipher_suites_observed"`
	Certificate           *JSONCertificate `json:"certificate,omitempty"`
	CertValidationStatus  string           `json:"certificate_validation_status,omitempty"`
	CertValidationMessage string           `json:"certificate_validation_message,omitempty"`
}

type JSONCertificate struct {
	SubjectCommonName string   `json:"subject_common_name"`
	IssuerCommonName  string   `json:"issuer_common_name"`
	ValidFrom         string   `json:"valid_from"`
	ValidTo           string   `json:"valid_to"`
	DaysUntilExpiry   int      `json:"days_until_expiry"`
	DNSNames          []string `json:"dns_names,omitempty"`
}

func WriteMarkdownReportToFile(host, port, scannerVersion string, results []scan.TLSScanResult, outputPath string) error {
	report := BuildMarkdownReportFromResults(host, port, scannerVersion, time.Now(), results)
	if !strings.HasSuffix(outputPath, ".md") {
		outputPath += ".md"
	}
	return os.WriteFile(outputPath, []byte(report), 0640)
}

func BuildMarkdownReportFromResults(host, port, scannerVersion string, generatedAt time.Time, results []scan.TLSScanResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# TLS Scan Report for host %s:%s\n\n", host, port))
	sb.WriteString(fmt.Sprintf("- **Generated At**: %s\n", generatedAt.UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("- **Scanner Version**: %s\n\n", scannerVersion))
	sb.WriteString("## TLS Versions Supported\n")
	for _, r := range results {
		if r.Supported {
			sb.WriteString(fmt.Sprintf("- ✅ %s", r.Version))
			if r.CertValidationStatus != "" {
				sb.WriteString(fmt.Sprintf(" (certificate: %s", r.CertValidationStatus))
				if r.CertValidationMessage != "" {
					sb.WriteString(fmt.Sprintf(" - %s", r.CertValidationMessage))
				}
				sb.WriteString(")")
			}
			sb.WriteString("\n")
		} else {
			sb.WriteString(fmt.Sprintf("- ❌ %s", r.Version))
			if r.Status != "" {
				sb.WriteString(fmt.Sprintf(" (%s", r.Status))
				if r.ErrorMessage != "" {
					sb.WriteString(fmt.Sprintf(" - %s", r.ErrorMessage))
				}
				sb.WriteString(")")
			}
			sb.WriteString("\n")
		}
	}
	sb.WriteString("\n## Cipher Suites\n")
	for _, r := range results {
		if r.Supported && len(r.CipherSuites) > 0 {
			if r.CipherSuitesObserved {
				sb.WriteString(fmt.Sprintf("\n### %s Observed Cipher Suites\n", r.Version))
			} else {
				sb.WriteString(fmt.Sprintf("\n### %s Supported Cipher Suites\n", r.Version))
			}
			for _, cs := range r.CipherSuites {
				label, ok := utils.CipherClassification[cs]
				if ok {
					sb.WriteString(fmt.Sprintf("- %s %s\n", cs, label))
				} else {
					sb.WriteString(fmt.Sprintf("- %s ❓ UNKNOWN\n", cs))
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

func BuildJSONReport(host, port, scannerVersion string, generatedAt time.Time, results []scan.TLSScanResult) ([]byte, error) {
	report := JSONReport{
		Host:           host,
		Port:           port,
		ScannerVersion: scannerVersion,
		GeneratedAt:    generatedAt.UTC().Format(time.RFC3339),
		Results:        make([]JSONScanResult, 0, len(results)),
	}

	for _, r := range results {
		jsonResult := JSONScanResult{
			Version:               r.Version,
			Supported:             r.Supported,
			Status:                r.Status,
			ErrorMessage:          r.ErrorMessage,
			CipherSuites:          r.CipherSuites,
			CipherSuitesObserved:  r.CipherSuitesObserved,
			CertValidationStatus:  r.CertValidationStatus,
			CertValidationMessage: r.CertValidationMessage,
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

func PrintCertSummary(cert *x509.Certificate, cipher string, version string, checkExpiry bool, validation scan.CertValidation) {
	fmt.Printf("✅ \033[1m%s\033[0m: supported\n", version)
	fmt.Printf("   Negotiated Cipher suite: %s\n", cipher)
	fmt.Printf("   CN: %s\n", cert.Subject.CommonName)
	fmt.Printf("   Issuer: %s\n", cert.Issuer.CommonName)
	fmt.Printf("   Valid: %s - %s\n", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	if validation.Status != "" {
		fmt.Printf("   Certificate validation: %s\n", validation.Status)
	}
	if validation.Message != "" {
		fmt.Printf("   Certificate validation details: %s\n", validation.Message)
	}

	if checkExpiry {
		fmt.Printf("   Days to Expiration: %d\n", int(time.Until(cert.NotAfter).Hours()/24))
	}
	fmt.Printf("   DNS: %v\n", cert.DNSNames)
}

func PrintCipherSuites(ciphers []string, observed bool) {
	if len(ciphers) > 0 {
		if observed {
			fmt.Println("   Observed cipher suites:")
		} else {
			fmt.Println("   Supported cipher suites:")
		}
		for _, cs := range ciphers {
			fmt.Printf("     • %s\n", cs)
		}
	}
}
