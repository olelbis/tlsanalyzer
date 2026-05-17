package policy

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/olelbis/tlsanalyzer/scan"
	"github.com/olelbis/tlsanalyzer/utils"
)

const (
	NameNone   = ""
	NameModern = "modern"

	CheckLegacyTLS   = "legacy-tls"
	CheckWeakCipher  = "weak-cipher"
	CheckInvalidCert = "invalid-cert"
	CheckExpiredCert = "expired-cert"

	CheckRequiredTLS    = "required-tls"
	CheckForbiddenTLS   = "forbidden-tls"
	CheckRequiredALPN   = "required-alpn"
	CheckForbiddenALPN  = "forbidden-alpn"
	CheckMinCertKeyBits = "min-cert-key-bits"
	CheckMinCertDays    = "min-cert-days"
)

type Config struct {
	Name                       string
	FailOn                     []string
	RequiredTLSVersions        []uint16
	ForbiddenTLSVersions       []uint16
	RequiredALPNProtocols      []string
	ForbiddenALPNProtocols     []string
	MinCertificateKeyBits      int
	MinCertificateValidityDays int
}

type Result struct {
	Enabled  bool      `json:"enabled"`
	Name     string    `json:"name,omitempty"`
	Passed   bool      `json:"passed"`
	Failures []Failure `json:"failures,omitempty"`
}

type Failure struct {
	Check   string `json:"check"`
	Version string `json:"version,omitempty"`
	Message string `json:"message"`
}

func ParseFailOn(value string) []string {
	return parseCommaList(value)
}

func ParseALPNProtocols(value string) []string {
	return parseCommaList(value)
}

func ParseTLSVersions(value string) ([]uint16, error) {
	if value == "" {
		return nil, nil
	}
	parts := parseCommaList(value)
	versions := make([]uint16, 0, len(parts))
	for _, part := range parts {
		version := utils.TLSVersionToUint16(part)
		if version == 0 {
			return nil, fmt.Errorf("invalid TLS version %q; use 1.0, 1.1, 1.2 or 1.3", part)
		}
		versions = append(versions, version)
	}
	return versions, nil
}

func ValidateConfig(config Config) error {
	if config.Name != "" && config.Name != NameModern {
		return fmt.Errorf("unknown policy %q", config.Name)
	}
	for _, check := range config.FailOn {
		if !isKnownCheck(check) {
			return fmt.Errorf("unknown fail-on check %q", check)
		}
	}
	if config.MinCertificateKeyBits < 0 {
		return fmt.Errorf("minimum certificate key bits cannot be negative")
	}
	if config.MinCertificateValidityDays < 0 {
		return fmt.Errorf("minimum certificate validity days cannot be negative")
	}
	if err := validateTLSVersionList(config.RequiredTLSVersions); err != nil {
		return err
	}
	if err := validateTLSVersionList(config.ForbiddenTLSVersions); err != nil {
		return err
	}
	if overlap := firstTLSVersionOverlap(config.RequiredTLSVersions, config.ForbiddenTLSVersions); overlap != 0 {
		return fmt.Errorf("%s cannot be both required and forbidden", tlsVersionName(overlap))
	}
	if err := validateALPNProtocols(config.RequiredALPNProtocols); err != nil {
		return err
	}
	if err := validateALPNProtocols(config.ForbiddenALPNProtocols); err != nil {
		return err
	}
	if overlap := firstStringOverlap(config.RequiredALPNProtocols, config.ForbiddenALPNProtocols); overlap != "" {
		return fmt.Errorf("ALPN protocol %q cannot be both required and forbidden", overlap)
	}
	return nil
}

func RequiresCipherProbe(config Config) bool {
	checks := checksForConfig(config)
	return checks[CheckWeakCipher]
}

func Evaluate(results []scan.TLSScanResult, config Config, now time.Time) Result {
	checks := checksForConfig(config)
	result := Result{
		Enabled: policyEnabled(config, checks),
		Name:    config.Name,
		Passed:  true,
	}
	if !result.Enabled {
		return result
	}

	supportedVersions := make(map[uint16]bool)
	for _, r := range results {
		if !r.Supported {
			continue
		}
		supportedVersions[r.VersionID] = true
		if checks[CheckLegacyTLS] && r.VersionID < tls.VersionTLS12 {
			result.Failures = append(result.Failures, Failure{
				Check:   CheckLegacyTLS,
				Version: r.Version,
				Message: fmt.Sprintf("%s is supported; modern policy requires TLS 1.2 or newer", r.Version),
			})
		}
		if checks[CheckInvalidCert] {
			if failure, ok := certificateValidationFailure(r); ok {
				result.Failures = append(result.Failures, failure)
			}
		}
		if checks[CheckExpiredCert] && r.Certificate != nil && !r.Certificate.NotAfter.After(now) {
			result.Failures = append(result.Failures, Failure{
				Check:   CheckExpiredCert,
				Version: r.Version,
				Message: fmt.Sprintf("%s certificate is expired", r.Version),
			})
		}
		if checks[CheckWeakCipher] {
			for _, cipher := range r.CipherSuites {
				if failure, ok := cipherPolicyFailure(r.Version, r.VersionID, cipher); ok {
					result.Failures = append(result.Failures, failure)
				}
			}
		}
		if containsTLSVersion(config.ForbiddenTLSVersions, r.VersionID) {
			result.Failures = append(result.Failures, Failure{
				Check:   CheckForbiddenTLS,
				Version: r.Version,
				Message: fmt.Sprintf("%s is supported but is forbidden by policy", r.Version),
			})
		}
		if config.MinCertificateKeyBits > 0 {
			if failure, ok := minCertificateKeyFailure(r, config.MinCertificateKeyBits); ok {
				result.Failures = append(result.Failures, failure)
			}
		}
		if config.MinCertificateValidityDays > 0 {
			if failure, ok := minCertificateValidityFailure(r, config.MinCertificateValidityDays, now); ok {
				result.Failures = append(result.Failures, failure)
			}
		}
		if len(config.RequiredALPNProtocols) > 0 && !containsString(config.RequiredALPNProtocols, r.ALPNProtocol) {
			result.Failures = append(result.Failures, Failure{
				Check:   CheckRequiredALPN,
				Version: r.Version,
				Message: fmt.Sprintf("%s negotiated ALPN %q; policy requires one of: %s", r.Version, valueOrNone(r.ALPNProtocol), strings.Join(config.RequiredALPNProtocols, ", ")),
			})
		}
		if r.ALPNProtocol != "" && containsString(config.ForbiddenALPNProtocols, r.ALPNProtocol) {
			result.Failures = append(result.Failures, Failure{
				Check:   CheckForbiddenALPN,
				Version: r.Version,
				Message: fmt.Sprintf("%s negotiated forbidden ALPN protocol %q", r.Version, r.ALPNProtocol),
			})
		}
	}

	for _, version := range config.RequiredTLSVersions {
		if !supportedVersions[version] {
			result.Failures = append(result.Failures, Failure{
				Check:   CheckRequiredTLS,
				Version: tlsVersionName(version),
				Message: fmt.Sprintf("%s is required by policy but was not supported", tlsVersionName(version)),
			})
		}
	}

	result.Passed = len(result.Failures) == 0
	return result
}

func checksForConfig(config Config) map[string]bool {
	checks := make(map[string]bool)
	if config.Name == NameModern {
		checks[CheckLegacyTLS] = true
		checks[CheckWeakCipher] = true
		checks[CheckInvalidCert] = true
		checks[CheckExpiredCert] = true
	}
	for _, check := range config.FailOn {
		checks[check] = true
	}
	return checks
}

func isKnownCheck(check string) bool {
	switch check {
	case CheckLegacyTLS, CheckWeakCipher, CheckInvalidCert, CheckExpiredCert:
		return true
	default:
		return false
	}
}

func policyEnabled(config Config, checks map[string]bool) bool {
	return len(checks) > 0 ||
		len(config.RequiredTLSVersions) > 0 ||
		len(config.ForbiddenTLSVersions) > 0 ||
		len(config.RequiredALPNProtocols) > 0 ||
		len(config.ForbiddenALPNProtocols) > 0 ||
		config.MinCertificateKeyBits > 0 ||
		config.MinCertificateValidityDays > 0
}

func cipherPolicyFailure(version string, versionID uint16, cipher string) (Failure, bool) {
	severity := utils.CipherSuiteSeverityForVersion(versionID, cipher)
	if severity == utils.CipherSeverityInsecure || severity == utils.CipherSeverityWeak {
		return Failure{
			Check:   CheckWeakCipher,
			Version: version,
			Message: fmt.Sprintf("%s allows weak cipher %s", version, cipher),
		}, true
	}
	if severity == utils.CipherSeverityUnknown {
		return Failure{
			Check:   CheckWeakCipher,
			Version: version,
			Message: fmt.Sprintf("%s allows unclassified cipher %s", version, cipher),
		}, true
	}
	return Failure{}, false
}

func certificateValidationFailure(r scan.TLSScanResult) (Failure, bool) {
	switch r.CertValidationStatus {
	case scan.CertValidationInvalid:
		return Failure{
			Check:   CheckInvalidCert,
			Version: r.Version,
			Message: fmt.Sprintf("%s certificate validation failed", r.Version),
		}, true
	case scan.CertValidationSkipped:
		return Failure{
			Check:   CheckInvalidCert,
			Version: r.Version,
			Message: fmt.Sprintf("%s certificate validation was skipped", r.Version),
		}, true
	case scan.CertValidationUnavailable, "":
		return Failure{
			Check:   CheckInvalidCert,
			Version: r.Version,
			Message: fmt.Sprintf("%s certificate validation is unavailable", r.Version),
		}, true
	default:
		return Failure{}, false
	}
}

func minCertificateKeyFailure(r scan.TLSScanResult, minimumBits int) (Failure, bool) {
	algorithm, bits := certificatePublicKeyMetadata(r.Certificate)
	if bits == 0 {
		return Failure{
			Check:   CheckMinCertKeyBits,
			Version: r.Version,
			Message: fmt.Sprintf("%s certificate public key size is unavailable; policy requires at least %d bits", r.Version, minimumBits),
		}, true
	}
	if bits < minimumBits {
		return Failure{
			Check:   CheckMinCertKeyBits,
			Version: r.Version,
			Message: fmt.Sprintf("%s certificate public key is %s %d-bit; policy requires at least %d bits", r.Version, algorithm, bits, minimumBits),
		}, true
	}
	return Failure{}, false
}

func minCertificateValidityFailure(r scan.TLSScanResult, minimumDays int, now time.Time) (Failure, bool) {
	if r.Certificate == nil {
		return Failure{
			Check:   CheckMinCertDays,
			Version: r.Version,
			Message: fmt.Sprintf("%s certificate expiry is unavailable; policy requires at least %d valid days", r.Version, minimumDays),
		}, true
	}
	days := int(r.Certificate.NotAfter.Sub(now).Hours() / 24)
	if days < minimumDays {
		return Failure{
			Check:   CheckMinCertDays,
			Version: r.Version,
			Message: fmt.Sprintf("%s certificate expires in %d days; policy requires at least %d valid days", r.Version, days, minimumDays),
		}, true
	}
	return Failure{}, false
}

func certificatePublicKeyMetadata(cert *x509.Certificate) (string, int) {
	if cert == nil {
		return "", 0
	}
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", key.N.BitLen()
	case *ecdsa.PublicKey:
		if key.Curve == nil || key.Curve.Params() == nil {
			return "ECDSA", 0
		}
		return "ECDSA", key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", len(key) * 8
	case *dsa.PublicKey:
		return "DSA", key.P.BitLen()
	default:
		if cert.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
			return cert.PublicKeyAlgorithm.String(), 0
		}
		return "", 0
	}
}

func parseCommaList(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			values = append(values, item)
		}
	}
	return values
}

func validateTLSVersionList(versions []uint16) error {
	for _, version := range versions {
		if _, ok := utils.TLSVersions[version]; !ok {
			return fmt.Errorf("invalid TLS version 0x%04x; use 1.0, 1.1, 1.2 or 1.3", version)
		}
	}
	return nil
}

func validateALPNProtocols(protocols []string) error {
	for _, protocol := range protocols {
		if strings.ContainsFunc(protocol, unicode.IsSpace) {
			return fmt.Errorf("ALPN protocol %q cannot contain whitespace", protocol)
		}
		if len(protocol) > 255 {
			return fmt.Errorf("ALPN protocol %q is longer than 255 bytes", protocol)
		}
	}
	return nil
}

func firstTLSVersionOverlap(left []uint16, right []uint16) uint16 {
	for _, version := range left {
		if containsTLSVersion(right, version) {
			return version
		}
	}
	return 0
}

func firstStringOverlap(left []string, right []string) string {
	for _, value := range left {
		if containsString(right, value) {
			return value
		}
	}
	return ""
}

func containsTLSVersion(versions []uint16, target uint16) bool {
	for _, version := range versions {
		if version == target {
			return true
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func tlsVersionName(version uint16) string {
	if name, ok := utils.TLSVersions[version]; ok {
		return name
	}
	return fmt.Sprintf("TLS 0x%04x", version)
}

func valueOrNone(value string) string {
	if value == "" {
		return "none"
	}
	return value
}
