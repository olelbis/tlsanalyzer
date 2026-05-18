package main

import (
	"crypto/tls"
	"time"

	"github.com/olelbis/tlsanalyzer/policy"
	"github.com/olelbis/tlsanalyzer/scan"
	"github.com/olelbis/tlsanalyzer/utils"
)

type scanRunOptions struct {
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

type scanRunResult struct {
	Results []scan.TLSScanResult
	Policy  policy.Result
}

type scanRunHooks struct {
	VersionStart func(versionName string, version uint16, probeCiphers bool)
	Unsupported  func(result scan.TLSScanResult)
	Supported    func(result scan.TLSScanResult, negotiatedCipher string) error
}

func executeScanRun(opts scanRunOptions, hooks scanRunHooks) (scanRunResult, error) {
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
				return scanRunResult{Results: results}, err
			}
		}
		results = append(results, result)
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	return scanRunResult{
		Results: results,
		Policy:  policy.Evaluate(results, opts.PolicyConfig, now),
	}, nil
}

func isPreTLS13(version uint16) bool {
	return version <= tls.VersionTLS12
}

func isTLS13(version uint16) bool {
	return version == tls.VersionTLS13
}
