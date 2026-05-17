package policy

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"

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
)

type Config struct {
	Name   string
	FailOn []string
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
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	checks := make([]string, 0, len(parts))
	for _, part := range parts {
		check := strings.TrimSpace(part)
		if check != "" {
			checks = append(checks, check)
		}
	}
	return checks
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
	return nil
}

func RequiresCipherProbe(config Config) bool {
	checks := checksForConfig(config)
	return checks[CheckWeakCipher]
}

func Evaluate(results []scan.TLSScanResult, config Config, now time.Time) Result {
	checks := checksForConfig(config)
	result := Result{
		Enabled: len(checks) > 0,
		Name:    config.Name,
		Passed:  true,
	}
	if !result.Enabled {
		return result
	}

	for _, r := range results {
		if !r.Supported {
			continue
		}
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
