package analyzer

import (
	"crypto/tls"
	"fmt"
	"sort"
	"time"

	"github.com/olelbis/tlsanalyzer/policy"
	"github.com/olelbis/tlsanalyzer/scan"
	"github.com/olelbis/tlsanalyzer/utils"
)

const (
	// DefaultPort is used when Options.Port is empty.
	DefaultPort = "443"
	// DefaultTimeout is used when Options.Timeout is zero.
	DefaultTimeout = 5 * time.Second
	// DefaultMinVersion is used when Options.MinVersion is zero.
	//
	// TLS 1.0 is intentional: the analyzer is a scanner and must be able to
	// detect and report legacy protocol support on the target. It does not
	// mean TLS 1.0 is recommended for clients or servers; use a policy (for
	// example --policy modern) to fail on legacy versions. Explicit version
	// gates (RequiredTLSVersions, ForbiddenTLSVersions, FailOn legacy-tls)
	// extend the scan below MinVersion when they refer to older versions.
	DefaultMinVersion = tls.VersionTLS10
)

// HookStage identifies the callback that failed.
type HookStage string

const (
	// HookStageSupported identifies errors returned by Hooks.Supported.
	HookStageSupported HookStage = "supported"
)

// Options configures one TLS analysis run for a single target.
type Options struct {
	Host         string
	Port         string
	ServerName   string
	Timeout      time.Duration
	MinVersion   uint16
	ForceCiphers bool
	SkipVerify   bool
	PolicyConfig policy.Config
	Now          time.Time
}

// DefaultOptions returns a single-target configuration matching CLI defaults.
func DefaultOptions(host string) Options {
	return Options{
		Host:       host,
		Port:       DefaultPort,
		Timeout:    DefaultTimeout,
		MinVersion: DefaultMinVersion,
	}
}

// Result contains scan evidence and the evaluated policy result.
type Result struct {
	Results []scan.TLSScanResult
	Policy  policy.Result
}

// HookError wraps errors returned by caller-provided hooks.
type HookError struct {
	Stage   HookStage
	Version string
	Err     error
}

func (e *HookError) Error() string {
	if e.Version == "" {
		return fmt.Sprintf("analyzer %s hook failed: %v", e.Stage, e.Err)
	}
	return fmt.Sprintf("analyzer %s hook failed for %s: %v", e.Stage, e.Version, e.Err)
}

func (e *HookError) Unwrap() error {
	return e.Err
}

// Hooks lets callers observe scan progress without coupling core analysis to UI output.
type Hooks struct {
	VersionStart func(versionName string, version uint16, probeCiphers bool)
	Unsupported  func(result scan.TLSScanResult)
	Supported    func(result scan.TLSScanResult, negotiatedCipher string) error
}

// Run executes the TLS scan matrix and evaluates the configured policy.
func Run(opts Options, hooks Hooks) (Result, error) {
	opts = normalizeOptions(opts)
	probeCiphers := opts.ForceCiphers || policy.RequiresCipherProbe(opts.PolicyConfig)
	scanOptions := scan.Options{
		Host:         opts.Host,
		Port:         opts.Port,
		ServerName:   opts.ServerName,
		Timeout:      opts.Timeout,
		MinVersion:   opts.MinVersion,
		ForceCiphers: opts.ForceCiphers,
		SkipVerify:   opts.SkipVerify,
	}

	// Explicit policy gates (--forbid-tls, --require-tls, --fail-on legacy-tls)
	// can only judge the versions that were scanned, so the scan range is
	// extended down to the versions they refer to.
	scanMinVersion := policy.MinimumScanVersion(opts.PolicyConfig, opts.MinVersion)

	var results []scan.TLSScanResult
	for _, version := range utils.FilterTLSVersions(scanMinVersion) {
		name := utils.TLSVersions[version]
		if hooks.VersionStart != nil {
			hooks.VersionStart(name, version, probeCiphers)
		}

		result := scan.ScanTLSVersion(scanOptions, version)
		if !result.Supported {
			if hooks.Unsupported != nil {
				hooks.Unsupported(result)
			}
			results = append(results, result)
			continue
		}

		negotiatedCipher := ""
		if len(result.CipherSuites) > 0 {
			negotiatedCipher = result.CipherSuites[0]
		}
		if probeCiphers {
			probe := scan.ProbeCipherSuitesForVersion(scanOptions, version)
			suites, probeMissedNegotiated := mergeNegotiatedCipher(probe.CipherSuites, negotiatedCipher)
			result.CipherSuites = suites
			result.CipherDiscovery = probe.Discovery
			result.CipherSuitesObserved = probe.ObservedOnly
			result.CipherProbeDurationMillis = probe.DurationMillis
			result.CipherProbeResults = probe.Statuses
			result.HandshakeAttempts += probe.Attempts
			result.Warnings = append(result.Warnings, probe.Warnings...)
			if probeMissedNegotiated && !probe.ObservedOnly {
				result.Warnings = append(result.Warnings, fmt.Sprintf(
					"cipher probing did not confirm %s, which the %s handshake negotiated; the endpoint may be rate limiting or unstable and the cipher list may be incomplete.",
					negotiatedCipher, result.Version))
			}
		}

		if hooks.Supported != nil {
			if err := hooks.Supported(result, negotiatedCipher); err != nil {
				return Result{Results: results}, &HookError{
					Stage:   HookStageSupported,
					Version: result.Version,
					Err:     err,
				}
			}
		}
		results = append(results, result)
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	policyResult := policy.Evaluate(results, opts.PolicyConfig, now)
	if policyResult.Enabled {
		policyResult.Notes = append(policyResult.Notes, policy.ScanRangeNotes(opts.PolicyConfig, opts.MinVersion)...)
	}

	return Result{
		Results: results,
		Policy:  policyResult,
	}, nil
}

// mergeNegotiatedCipher makes sure the cipher suite negotiated by the version
// handshake is part of the reported list. A successful handshake is proof of
// support, so a cipher probe that did not see it (rate limiting, a flaky
// endpoint, a probe limitation) must not erase it. The boolean reports whether
// the suite had to be added.
func mergeNegotiatedCipher(suites []string, negotiated string) ([]string, bool) {
	if negotiated == "" {
		return suites, false
	}
	for _, suite := range suites {
		if suite == negotiated {
			return suites, false
		}
	}
	merged := append(append([]string(nil), suites...), negotiated)
	sort.Strings(merged)
	return merged, true
}

func normalizeOptions(opts Options) Options {
	if opts.Port == "" {
		opts.Port = DefaultPort
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MinVersion == 0 {
		opts.MinVersion = DefaultMinVersion
	}
	return opts
}

// RunFailed reports whether the run produced only operational scan errors.
func RunFailed(results []scan.TLSScanResult) bool {
	if len(results) == 0 {
		return true
	}
	for _, result := range results {
		if !scan.IsExecutionStatus(result.Status) {
			return false
		}
	}
	return true
}
