package analyzer

import (
	"crypto/tls"
	"fmt"
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

	var results []scan.TLSScanResult
	for _, version := range utils.FilterTLSVersions(opts.MinVersion) {
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
			result.CipherSuites = probe.CipherSuites
			result.CipherDiscovery = probe.Discovery
			result.CipherSuitesObserved = probe.ObservedOnly
			result.CipherProbeDurationMillis = probe.DurationMillis
			result.CipherProbeResults = probe.Statuses
			result.HandshakeAttempts += probe.Attempts
			result.Warnings = append(result.Warnings, probe.Warnings...)
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

	return Result{
		Results: results,
		Policy:  policy.Evaluate(results, opts.PolicyConfig, now),
	}, nil
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
