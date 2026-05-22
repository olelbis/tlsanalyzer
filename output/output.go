package output

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/olelbis/tlsanalyzer/policy"
	"github.com/olelbis/tlsanalyzer/scan"
	"github.com/olelbis/tlsanalyzer/utils"
)

func WriteMarkdownReportToFile(host, port, serverName, scannerVersion string, results []scan.TLSScanResult, outputPath string, policyResults ...*policy.Result) error {
	report := BuildMarkdownReportFromResults(host, port, serverName, scannerVersion, time.Now(), results, policyResults...)
	if !strings.HasSuffix(outputPath, ".md") {
		outputPath += ".md"
	}
	return os.WriteFile(outputPath, []byte(report), 0640)
}

func BuildMarkdownReportFromResults(host, port, serverName, scannerVersion string, generatedAt time.Time, results []scan.TLSScanResult, policyResults ...*policy.Result) string {
	policyResult := firstPolicyResult(policyResults)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# TLS Scan Report for host %s:%s\n\n", host, port))
	if serverName != "" {
		sb.WriteString(fmt.Sprintf("- **Server Name**: %s\n", serverName))
	}
	sb.WriteString(fmt.Sprintf("- **Generated At**: %s\n", generatedAt.UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("- **Scanner Version**: %s\n", scannerVersion))
	sb.WriteString(fmt.Sprintf("- **JSON Schema Version**: %s\n\n", JSONSchemaVersion))
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Supported TLS Versions**: %s\n", summarizeSupportedTLSVersions(results)))
	sb.WriteString(fmt.Sprintf("- **Protocol Findings**: %s\n", summarizeProtocolFindings(results)))
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
	sb.WriteString("| Version | Supported | Status | Certificate | Key Exchange | ALPN | Duration | Attempts |\n")
	sb.WriteString("| --- | --- | --- | --- | --- | --- | ---: | ---: |\n")
	for _, r := range results {
		supported := "no"
		if r.Supported {
			supported = "yes"
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %d ms | %d |\n", r.Version, supported, emptyDash(r.Status), emptyDash(r.CertValidationStatus), emptyDash(r.KeyExchangeGroup), emptyDash(r.ALPNProtocol), r.DurationMillis, r.HandshakeAttempts))
	}
	sb.WriteString("\n## Cipher Suites\n")
	for _, r := range results {
		if r.Supported && (len(r.CipherSuites) > 0 || len(r.CipherProbeResults) > 0) {
			sb.WriteString(fmt.Sprintf("\n### %s\n\n", r.Version))
			sb.WriteString(fmt.Sprintf("- **Negotiated**: %s\n", emptyDash(r.NegotiatedCipherSuite)))
			sb.WriteString(fmt.Sprintf("- **Discovery**: %s\n", emptyDash(r.CipherDiscovery)))
			if r.CipherProbeDurationMillis > 0 {
				sb.WriteString(fmt.Sprintf("- **Cipher Probe Duration**: %d ms\n", r.CipherProbeDurationMillis))
			}
			for _, warning := range r.Warnings {
				sb.WriteString(fmt.Sprintf("- **Warning**: %s\n", warning))
			}
			if len(r.CipherSuites) > 0 {
				sb.WriteString("\n| Cipher Suite | Classification |\n")
				sb.WriteString("| --- | --- |\n")
				for _, cs := range r.CipherSuites {
					label, ok := utils.CipherClassificationForVersion(r.VersionID, cs)
					if ok {
						sb.WriteString(fmt.Sprintf("| %s | %s |\n", cs, label))
					} else {
						sb.WriteString(fmt.Sprintf("| %s | ❓ UNKNOWN |\n", cs))
					}
				}
			}
			appendCipherProbeResultsMarkdown(&sb, r)
		}
	}

	certGroups := groupCertificateResults(results)
	if len(certGroups) > 0 {
		sb.WriteString("\n## Certificate Details\n")
		for _, group := range certGroups {
			sb.WriteString(fmt.Sprintf("\n### %s\n", strings.Join(group.Versions, ", ")))
			sb.WriteString(fmt.Sprintf("- **Subject CN**: %s\n", group.Certificate.Subject.CommonName))
			sb.WriteString(fmt.Sprintf("- **Issuer**: %s\n", group.Certificate.Issuer.CommonName))
			if publicKey := certificatePublicKeySummary(group.Certificate); publicKey != "" {
				sb.WriteString(fmt.Sprintf("- **Public Key**: %s\n", publicKey))
			}
			if signature := certificateSignatureAlgorithm(group.Certificate); signature != "" {
				sb.WriteString(fmt.Sprintf("- **Signature Algorithm**: %s\n", signature))
			}
			sb.WriteString(fmt.Sprintf("- **Valid From**: %s\n", group.Certificate.NotBefore.Format("2006-01-02")))
			sb.WriteString(fmt.Sprintf("- **Valid To**: %s\n", group.Certificate.NotAfter.Format("2006-01-02")))
			sb.WriteString(fmt.Sprintf("- **Days Until Expiry**: %d\n", daysUntilCertificateExpiry(group.Certificate, generatedAt)))
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

func appendCipherProbeResultsMarkdown(sb *strings.Builder, result scan.TLSScanResult) {
	if len(result.CipherProbeResults) == 0 {
		return
	}

	sb.WriteString("\n#### Cipher Probe Results\n\n")
	if result.CipherDiscovery == scan.CipherDiscoveryRawProbed {
		sb.WriteString("Raw probe evidence is ClientHello-only. `clienthello-serverhello` and `clienthello-hrr-serverhello` evidence means the server selected a cipher in ServerHello, but the probe still does not complete a full TLS handshake.\n\n")
	}
	sb.WriteString("| Cipher Suite | Status | Evidence | Group | HRR | Alert | Error |\n")
	sb.WriteString("| --- | --- | --- | --- | --- | --- | --- |\n")
	for _, probe := range result.CipherProbeResults {
		hrr := "-"
		if probe.HelloRetryRequest {
			hrr = "yes"
			if probe.HelloRetryRequestRetried {
				hrr = "retried"
			}
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s |\n", escapeTable(probe.CipherSuite), emptyDash(probe.Status), emptyDash(probe.Evidence), emptyDash(probe.SelectedGroup), hrr, emptyDash(probe.Alert), emptyDash(probe.Error)))
	}
}

func PrintScanSummary(w io.Writer, results []scan.TLSScanResult) {
	fmt.Fprintln(w, "\nSummary:")
	fmt.Fprintf(w, "  Supported TLS versions: %s\n", summarizeSupportedTLSVersions(results))
	fmt.Fprintf(w, "  Protocol findings: %s\n", summarizeProtocolFindings(results))
	fmt.Fprintf(w, "  Certificate validation: %s\n", summarizeCertificateValidation(results))
	fmt.Fprintf(w, "  Cipher findings: %s\n", summarizeCipherFindings(results))
	if rawProbeSummary, ok := summarizeRawProbeResults(results); ok {
		fmt.Fprintf(w, "  Raw probe: %s\n", rawProbeSummary)
	}
}

func PrintCompactScanResults(w io.Writer, results []scan.TLSScanResult) {
	fmt.Fprintln(w, "\nTLS Results:")
	for _, result := range results {
		status := result.Status
		if status == "" {
			status = "unknown"
		}
		certificate := valueOrDash(result.CertValidationStatus)
		cipherEvidence := valueOrDash(result.CipherDiscovery)
		keyExchange := valueOrDash(result.KeyExchangeGroup)
		alpn := valueOrDash(result.ALPNProtocol)
		if result.Supported {
			fmt.Fprintf(w, "  %-7s supported cert=%s cipher=%s kx=%s alpn=%s attempts=%d\n", result.Version, certificate, cipherEvidence, keyExchange, alpn, result.HandshakeAttempts)
			continue
		}
		fmt.Fprintf(w, "  %-7s %-9s error=%s attempts=%d\n", result.Version, status, valueOrDash(result.ErrorMessage), result.HandshakeAttempts)
	}
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

func summarizeSupportedTLSVersions(results []scan.TLSScanResult) string {
	return fmt.Sprintf("%d of %d tested", countSupported(results), len(results))
}

func summarizeRawProbeResults(results []scan.TLSScanResult) (string, bool) {
	supported := 0
	total := 0
	for _, result := range results {
		if result.CipherDiscovery != scan.CipherDiscoveryRawProbed {
			continue
		}
		for _, probe := range result.CipherProbeResults {
			total++
			if probe.Status == "supported" {
				supported++
			}
		}
	}
	if total == 0 {
		return "", false
	}
	return fmt.Sprintf("%d/%d ciphers supported (ClientHello-only ServerHello evidence; no full handshakes)", supported, total), true
}

func summarizeProtocolFindings(results []scan.TLSScanResult) string {
	var legacyVersions []string
	supported := false
	for _, r := range results {
		if !r.Supported {
			continue
		}
		supported = true
		if isLegacyTLSResult(r) {
			legacyVersions = append(legacyVersions, r.Version)
		}
	}
	if len(legacyVersions) > 0 {
		return "legacy TLS versions supported: " + strings.Join(legacyVersions, ", ")
	}
	if supported {
		return "no legacy TLS versions detected"
	}
	return "no supported TLS versions detected"
}

func isLegacyTLSResult(r scan.TLSScanResult) bool {
	if r.VersionID != 0 {
		return r.VersionID < tls.VersionTLS12
	}
	return r.Version == "TLS 1.0" || r.Version == "TLS 1.1"
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
	evidence := make(map[string]bool)
	for _, r := range results {
		for _, cipher := range r.CipherSuites {
			if r.CipherDiscovery != "" {
				evidence[r.CipherDiscovery] = true
			}
			if utils.IsLegacyCBCForVersion(r.VersionID, cipher) {
				return fmt.Sprintf("legacy CBC cipher suites detected in %s evidence", describeCipherEvidence(evidence))
			}
			severity := utils.CipherSuiteSeverityForVersion(r.VersionID, cipher)
			if severity == utils.CipherSeverityInsecure {
				return fmt.Sprintf("insecure cipher suites detected in %s evidence", describeCipherEvidence(evidence))
			}
			if severity == utils.CipherSeverityWeak {
				return fmt.Sprintf("weak cipher suites detected in %s evidence", describeCipherEvidence(evidence))
			}
			if severity == utils.CipherSeverityUnknown {
				return fmt.Sprintf("unknown cipher suites detected in %s evidence", describeCipherEvidence(evidence))
			}
		}
	}
	if len(evidence) == 0 {
		return "cipher evidence unavailable"
	}
	return fmt.Sprintf("no weak cipher suites detected in %s evidence", describeCipherEvidence(evidence))
}

func describeCipherEvidence(evidence map[string]bool) string {
	if len(evidence) == 0 {
		return "unknown"
	}
	modes := make([]string, 0, len(evidence))
	for mode := range evidence {
		modes = append(modes, mode)
	}
	sort.Strings(modes)
	if len(modes) == 1 {
		return modes[0]
	}
	return "mixed (" + strings.Join(modes, ", ") + ")"
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

func valueOrDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
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

func certificatePublicKeySummary(cert *x509.Certificate) string {
	algorithm, bits, curve := certificatePublicKeyMetadata(cert)
	if algorithm == "" {
		return ""
	}
	if curve != "" && bits > 0 {
		return fmt.Sprintf("%s %s (%d-bit)", algorithm, curve, bits)
	}
	if bits > 0 {
		return fmt.Sprintf("%s %d-bit", algorithm, bits)
	}
	return algorithm
}

func certificatePublicKeyMetadata(cert *x509.Certificate) (algorithm string, bits int, curve string) {
	if cert == nil {
		return "", 0, ""
	}
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", key.N.BitLen(), ""
	case *ecdsa.PublicKey:
		if key.Curve == nil || key.Curve.Params() == nil {
			return "ECDSA", 0, ""
		}
		return "ECDSA", key.Curve.Params().BitSize, key.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519", len(key) * 8, ""
	case *dsa.PublicKey:
		return "DSA", key.P.BitLen(), ""
	default:
		if cert.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
			return cert.PublicKeyAlgorithm.String(), 0, ""
		}
		return "", 0, ""
	}
}

func certificateSignatureAlgorithm(cert *x509.Certificate) string {
	if cert == nil || cert.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		return ""
	}
	return cert.SignatureAlgorithm.String()
}

func daysUntilCertificateExpiry(cert *x509.Certificate, reference time.Time) int {
	return int(cert.NotAfter.Sub(reference).Hours() / 24)
}

func PrintCertSummary(w io.Writer, cert *x509.Certificate, cipher string, version string, checkExpiry bool, validation scan.CertValidation) {
	fmt.Fprintf(w, "✅ \033[1m%s\033[0m: supported\n", version)
	if cipher != "" {
		fmt.Fprintf(w, "   Negotiated cipher suite (selected in this handshake): %s\n", cipher)
	}
	fmt.Fprintf(w, "   CN: %s\n", cert.Subject.CommonName)
	fmt.Fprintf(w, "   Issuer: %s\n", cert.Issuer.CommonName)
	if publicKey := certificatePublicKeySummary(cert); publicKey != "" {
		fmt.Fprintf(w, "   Public Key: %s\n", publicKey)
	}
	if signature := certificateSignatureAlgorithm(cert); signature != "" {
		fmt.Fprintf(w, "   Signature Algorithm: %s\n", signature)
	}
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

func PrintTLSPosture(w io.Writer, result scan.TLSScanResult) {
	if result.KeyExchangeGroup != "" {
		fmt.Fprintf(w, "   Key Exchange Group: %s\n", result.KeyExchangeGroup)
	}
	if result.ALPNProtocol != "" {
		fmt.Fprintf(w, "   ALPN: %s\n", result.ALPNProtocol)
	}
}

func PrintCipherSuites(w io.Writer, ciphers []string, discovery string) {
	if len(ciphers) > 0 {
		switch discovery {
		case scan.CipherDiscoveryRawProbed:
			fmt.Fprintln(w, "   Raw-probed cipher suites (ClientHello-only support evidence):")
		case scan.CipherDiscoveryObserved:
			fmt.Fprintln(w, "   Observed cipher suites (handshake evidence):")
		case scan.CipherDiscoveryProbed:
			fmt.Fprintln(w, "   Probed cipher suites (per-cipher handshake evidence):")
		default:
			return
		}
		for _, cs := range ciphers {
			fmt.Fprintf(w, "     • %s\n", cs)
		}
	}
}
