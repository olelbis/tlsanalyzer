package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/olelbis/tlsanalyzer/build"
	"github.com/olelbis/tlsanalyzer/output"
	"github.com/olelbis/tlsanalyzer/policy"
	"github.com/olelbis/tlsanalyzer/scan"
	"github.com/olelbis/tlsanalyzer/utils"
)

type targetSpec struct {
	Host string `json:"host"`
	Port string `json:"port,omitempty"`
	SNI  string `json:"sni,omitempty"`
}

type targetsFile struct {
	Targets []targetSpec `json:"targets"`
}

type batchTargetResult struct {
	Target   targetSpec
	Attempts int
	Results  []scan.TLSScanResult
	Policy   policy.Result
	Error    string
}

func runBatch(cfg cliConfig, stdout io.Writer, stderr io.Writer) int {
	if cfg.certChain {
		fmt.Fprintln(stderr, "Error: --cert is not supported with --targets-file")
		return 1
	}
	if cfg.outputMarkdown != "" {
		fmt.Fprintln(stderr, "Error: --markdown is not supported with --targets-file")
		return 1
	}

	settings, err := buildBatchSettings(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	targets, err := loadTargetsFile(cfg.targetsFile, settings.defaultPort, cfg.sni)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if len(targets) == 0 {
		fmt.Fprintln(stderr, "Error: --targets-file must contain at least one target")
		return 1
	}
	for i := range targets {
		if err := validateTarget(targets[i]); err != nil {
			fmt.Fprintf(stderr, "Error: target %d: %v\n", i+1, err)
			return 1
		}
	}

	humanOutput := !cfg.outputJSON
	if humanOutput {
		fmt.Fprintf(stdout, "Starting batch TLS analysis for %d targets with concurrency %d\n", len(targets), settings.concurrency)
	}

	results := executeBatch(targets, settings)
	reports := make([]output.TargetReport, 0, len(results))
	failedRuntime := false
	failedPolicy := false
	for _, result := range results {
		exitCode := exitCodeForTarget(result)
		report := output.TargetReport{
			Host:           result.Target.Host,
			Port:           result.Target.Port,
			ServerName:     result.Target.SNI,
			ScannerVersion: build.Version,
			Attempts:       result.Attempts,
			Results:        result.Results,
			Policy:         policyResultPointer(result.Policy),
			Error:          result.Error,
			ExitCode:       exitCode,
		}
		reports = append(reports, report)
		if exitCode == 1 {
			failedRuntime = true
		}
		if result.Policy.Enabled && !result.Policy.Passed {
			failedPolicy = true
		}
	}

	if humanOutput {
		output.PrintBatchSummary(stdout, reports)
	}
	if cfg.outputSARIF != "" {
		if err := output.WriteSARIFBatchReportToFile(reports, cfg.outputSARIF); err != nil {
			fmt.Fprintf(stderr, "❌ Failed to write SARIF report: %v\n", err)
			return 1
		}
		if humanOutput {
			fmt.Fprintf(stdout, "✅ SARIF report saved to %s\n", cfg.outputSARIF)
		}
	}
	if cfg.outputJUnit != "" {
		if err := output.WriteJUnitBatchReportToFile(reports, cfg.outputJUnit); err != nil {
			fmt.Fprintf(stderr, "❌ Failed to write JUnit report: %v\n", err)
			return 1
		}
		if humanOutput {
			fmt.Fprintf(stdout, "✅ JUnit report saved to %s\n", cfg.outputJUnit)
		}
	}
	if cfg.outputJSON {
		jsonReport, err := output.BuildJSONBatchReport(build.Version, time.Now(), reports, output.BatchRunMetadata{
			TargetCount:  len(reports),
			Concurrency:  settings.concurrency,
			Retries:      settings.retries,
			RetryBackoff: settings.retryBackoff.String(),
		})
		if err != nil {
			fmt.Fprintf(stderr, "❌ Failed to build JSON report: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(jsonReport))
	}
	if failedRuntime {
		return 1
	}
	if failedPolicy {
		return 3
	}
	return 0
}

type batchSettings struct {
	defaultPort  string
	timeout      time.Duration
	minVersion   uint16
	forceCiphers bool
	skipVerify   bool
	policyConfig policy.Config
	concurrency  int
	retries      int
	retryBackoff time.Duration
}

func buildBatchSettings(cfg cliConfig) (batchSettings, error) {
	if cfg.timeout < 1 {
		return batchSettings{}, fmt.Errorf("--timeout must be at least 1 second")
	}
	if cfg.concurrency < 1 {
		return batchSettings{}, fmt.Errorf("--concurrency must be at least 1")
	}
	if cfg.retries < 0 {
		return batchSettings{}, fmt.Errorf("--retries cannot be negative")
	}
	if cfg.retryBackoff < 0 {
		return batchSettings{}, fmt.Errorf("--retry-backoff cannot be negative")
	}

	port := strings.TrimSpace(cfg.port)
	if err := validatePort(port); err != nil {
		return batchSettings{}, fmt.Errorf("invalid --port %q: %w", cfg.port, err)
	}

	minVersion := utils.TLSVersionToUint16(cfg.minVersionStr)
	if minVersion == 0 {
		return batchSettings{}, fmt.Errorf("invalid --min-version %q; use 1.0, 1.1, 1.2 or 1.3", cfg.minVersionStr)
	}

	policyConfig, err := buildPolicyConfig(cfg)
	if err != nil {
		return batchSettings{}, err
	}
	if err := policy.ValidateConfig(policyConfig); err != nil {
		return batchSettings{}, err
	}

	return batchSettings{
		defaultPort:  port,
		timeout:      time.Duration(cfg.timeout) * time.Second,
		minVersion:   minVersion,
		forceCiphers: cfg.forceCiphers,
		skipVerify:   cfg.skipVerify,
		policyConfig: policyConfig,
		concurrency:  cfg.concurrency,
		retries:      cfg.retries,
		retryBackoff: time.Duration(cfg.retryBackoff) * time.Second,
	}, nil
}

func loadTargetsFile(path, defaultPort, defaultSNI string) ([]targetSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load targets file %q: %w", path, err)
	}

	var direct []targetSpec
	if err := json.Unmarshal(data, &direct); err == nil {
		return normalizeTargets(direct, defaultPort, defaultSNI), nil
	}

	var wrapped targetsFile
	if err := json.Unmarshal(data, &wrapped); err != nil {
		return nil, fmt.Errorf("parse targets file %q: %w", path, err)
	}
	return normalizeTargets(wrapped.Targets, defaultPort, defaultSNI), nil
}

func normalizeTargets(targets []targetSpec, defaultPort, defaultSNI string) []targetSpec {
	normalized := make([]targetSpec, 0, len(targets))
	for _, target := range targets {
		target.Host = strings.TrimSpace(target.Host)
		target.Port = strings.TrimSpace(target.Port)
		target.SNI = strings.TrimSpace(target.SNI)
		if target.Port == "" {
			target.Port = defaultPort
		}
		if target.SNI == "" {
			target.SNI = strings.TrimSpace(defaultSNI)
		}
		normalized = append(normalized, target)
	}
	return normalized
}

func validateTarget(target targetSpec) error {
	if err := validateHost(target.Host); err != nil {
		return fmt.Errorf("invalid host %q: %w", target.Host, err)
	}
	if err := validatePort(target.Port); err != nil {
		return fmt.Errorf("invalid port %q: %w", target.Port, err)
	}
	if target.SNI != "" {
		if err := validateHost(target.SNI); err != nil {
			return fmt.Errorf("invalid sni %q: %w", target.SNI, err)
		}
	}
	return nil
}

func executeBatch(targets []targetSpec, settings batchSettings) []batchTargetResult {
	results := make([]batchTargetResult, len(targets))
	jobs := make(chan int)
	var wg sync.WaitGroup

	for worker := 0; worker < settings.concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				results[index] = executeBatchTarget(targets[index], settings)
			}
		}()
	}

	for index := range targets {
		jobs <- index
	}
	close(jobs)
	wg.Wait()
	return results
}

func executeBatchTarget(target targetSpec, settings batchSettings) batchTargetResult {
	attempts := 0
	var last scanRunResult
	var lastErr error
	for attempt := 0; attempt <= settings.retries; attempt++ {
		attempts++
		last, lastErr = executeScanRun(scanRunOptions{
			Host:         target.Host,
			Port:         target.Port,
			ServerName:   target.SNI,
			Timeout:      settings.timeout,
			MinVersion:   settings.minVersion,
			ForceCiphers: settings.forceCiphers,
			SkipVerify:   settings.skipVerify,
			PolicyConfig: settings.policyConfig,
		}, scanRunHooks{})
		if lastErr != nil || !hasTransientScanFailure(last.Results) || attempt == settings.retries {
			break
		}
		if settings.retryBackoff > 0 {
			time.Sleep(settings.retryBackoff * time.Duration(attempt+1))
		}
	}

	result := batchTargetResult{
		Target:   target,
		Attempts: attempts,
		Results:  last.Results,
		Policy:   last.Policy,
	}
	if lastErr != nil {
		result.Error = lastErr.Error()
	}
	return result
}

func hasTransientScanFailure(results []scan.TLSScanResult) bool {
	for _, result := range results {
		if result.Status == scan.ScanStatusNetworkError || result.Status == scan.ScanStatusTimeout {
			return true
		}
	}
	return false
}

func policyResultPointer(result policy.Result) *policy.Result {
	if !result.Enabled {
		return nil
	}
	return &result
}

func exitCodeForTarget(result batchTargetResult) int {
	if result.Error != "" {
		return 1
	}
	if result.Policy.Enabled && !result.Policy.Passed {
		return 3
	}
	return 0
}
