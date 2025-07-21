// File: output/output.go
package output

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"
	"tlsanalyzer/scan"
	"tlsanalyzer/utils"
)

func WriteMarkdownReportToFile(host, port string, results []scan.TLSScanResult, outputPath string) error {
	report := BuildMarkdownReportFromResults(host, port, results)
	if !strings.HasSuffix(outputPath, ".md") {
		outputPath += ".md"
	}
	return os.WriteFile(outputPath, []byte(report), 0640)
}

func BuildMarkdownReportFromResults(host, port string, results []scan.TLSScanResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# TLS Scan Report for host %s:%s\n\n", host, port))
	sb.WriteString("## TLS Versions Supported\n")
	for _, r := range results {
		if r.Supported {
			sb.WriteString(fmt.Sprintf("- ✅ %s\n", r.Version))
		} else {
			sb.WriteString(fmt.Sprintf("- ❌ %s\n", r.Version))
		}
	}
	sb.WriteString("\n## Cipher Suites\n")
	for _, r := range results {
		if r.Supported && len(r.CipherSuites) > 0 {
			sb.WriteString(fmt.Sprintf("\n### %s\n", r.Version))
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

	for _, r := range results {
		if r.Supported && r.Certificate != nil {
			sb.WriteString("\n## Certificate Details\n")
			sb.WriteString(fmt.Sprintf("- **Subject CN**: %s\n", r.Certificate.Subject.CommonName))
			sb.WriteString(fmt.Sprintf("- **Issuer**: %s\n", r.Certificate.Issuer.CommonName))
			sb.WriteString(fmt.Sprintf("- **Valid From**: %s\n", r.Certificate.NotBefore.Format("2006-01-02")))
			sb.WriteString(fmt.Sprintf("- **Valid To**: %s\n", r.Certificate.NotAfter.Format("2006-01-02")))
			sb.WriteString(fmt.Sprintf("- **Days Until Expiry**: %d\n", int(time.Until(r.Certificate.NotAfter).Hours()/24)))
			if len(r.Certificate.DNSNames) > 0 {
				sb.WriteString(fmt.Sprintf("- **DNS Names**: %s\n", strings.Join(r.Certificate.DNSNames, ", ")))
			}
			break
		}
	}

	return sb.String()
}

func PrintCertSummary(cert *x509.Certificate, cipher string, version string, checkExpiry bool) {
	fmt.Printf("✅ \033[1m%s\033[0m: supported\n", version)
	fmt.Printf("   Negotiated Cipher suite: %s\n", cipher)
	fmt.Printf("   CN: %s\n", cert.Subject.CommonName)
	fmt.Printf("   Issuer: %s\n", cert.Issuer.CommonName)
	fmt.Printf("   Valid: %s - %s\n", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))

	if checkExpiry {
		fmt.Printf("   Days to Expiration: %d\n", int(time.Until(cert.NotAfter).Hours()/24))
	}
	fmt.Printf("   DNS: %v\n", cert.DNSNames)
}

func PrintCipherSuites(ciphers []string) {
	if len(ciphers) > 0 {
		fmt.Println("   Supported cipher suites:")
		for _, cs := range ciphers {
			fmt.Printf("     • %s\n", cs)
		}
	}
}
