package analyzer

import (
	"time"

	"github.com/olelbis/tlsanalyzer/policy"
	"github.com/olelbis/tlsanalyzer/scan"
	"github.com/olelbis/tlsanalyzer/utils"
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

// Result contains scan evidence and the evaluated policy result.
type Result struct {
	Results []scan.TLSScanResult
	Policy  policy.Result
}

// Hooks lets callers observe scan progress without coupling core analysis to UI output.
type Hooks struct {
	VersionStart func(versionName string, version uint16, probeCiphers bool)
	Unsupported  func(result scan.TLSScanResult)
	Supported    func(result scan.TLSScanResult, negotiatedCipher string) error
}

// Run executes the TLS scan matrix and evaluates the configured policy.
func Run(opts Options, hooks Hooks) (Result, error) {
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
				return Result{Results: results}, err
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
