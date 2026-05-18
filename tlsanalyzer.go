package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/olelbis/tlsanalyzer/build"
	"github.com/olelbis/tlsanalyzer/certs"
	"github.com/olelbis/tlsanalyzer/output"
	"github.com/olelbis/tlsanalyzer/policy"
	"github.com/olelbis/tlsanalyzer/scan"
	"github.com/olelbis/tlsanalyzer/utils"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type cliConfig struct {
	configPath      string
	targetName      string
	profileName     string
	targetsFile     string
	host            string
	port            string
	sni             string
	certChain       bool
	checkCertExpiry bool
	timeout         int
	outputFile      string
	minVersionStr   string
	outputMarkdown  string
	outputSARIF     string
	outputJUnit     string
	forceCiphers    bool
	skipVerify      bool
	outputJSON      bool
	noClear         bool
	compact         bool
	showVersion     bool
	concurrency     int
	retries         int
	retryBackoff    int
	policy          string
	failOn          string
	requireTLS      string
	forbidTLS       string
	requireALPN     string
	forbidALPN      string
	minCertKeyBits  int
	minCertDays     int
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}

	cfg, err := parseCLIArgs(args, stderr)
	if err != nil {
		var inputErr cliInputError
		if errors.As(err, &inputErr) {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		return 2
	}

	if cfg.showVersion {
		fmt.Fprintln(stdout, formatVersion())
		return 0
	}

	if cfg.targetsFile != "" {
		return runBatch(cfg, stdout, stderr)
	}

	if cfg.host == "" {
		fmt.Fprintln(stderr, "Error: --host is required")
		writeUsage(stderr)
		return 1
	}

	h := strings.TrimSpace(cfg.host)
	if err := validateHost(h); err != nil {
		fmt.Fprintf(stderr, "Error: invalid --host '%s': %v\n", cfg.host, err)
		return 1
	}
	serverName := strings.TrimSpace(cfg.sni)
	if serverName != "" {
		if err := validateHost(serverName); err != nil {
			fmt.Fprintf(stderr, "Error: invalid --sni '%s': %v\n", cfg.sni, err)
			return 1
		}
	}

	port := strings.TrimSpace(cfg.port)
	if err := validatePort(port); err != nil {
		fmt.Fprintf(stderr, "Error: invalid --port '%s': %v\n", cfg.port, err)
		return 1
	}
	if cfg.timeout < 1 {
		fmt.Fprintln(stderr, "Error: --timeout must be at least 1 second")
		return 1
	}

	minVersion := utils.TLSVersionToUint16(cfg.minVersionStr)
	if minVersion == 0 {
		fmt.Fprintf(stderr, "Error: invalid --min-version '%s'. Use 1.0, 1.1, 1.2 or 1.3\n", cfg.minVersionStr)
		return 1
	}
	if err := validateFlagCombination(cfg.outputJSON, cfg.certChain, strings.TrimSpace(cfg.outputFile)); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	policyConfig, err := buildPolicyConfig(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if err := policy.ValidateConfig(policyConfig); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	humanOutput := !cfg.outputJSON
	verboseOutput := humanOutput && !cfg.compact

	if !cfg.noClear && verboseOutput {
		utils.ClearScreenTo(stdout)
	}

	if verboseOutput {
		fmt.Fprintf(stdout, "\nStarting TLS analysis for %s:%s with minimum TLS version %s\n", h, port, cfg.minVersionStr)
		if serverName != "" {
			fmt.Fprintf(stdout, "Using SNI/certificate name %s\n", serverName)
		}
	}
	if verboseOutput {
		fmt.Fprintf(stdout, "\n\033[1mTLS Analysis for:\033[0m [%s:%s]\n", h, port)
	}

	runResult, err := executeScanRun(scanRunOptions{
		Host:         h,
		Port:         port,
		ServerName:   serverName,
		Timeout:      time.Duration(cfg.timeout) * time.Second,
		MinVersion:   minVersion,
		ForceCiphers: cfg.forceCiphers,
		SkipVerify:   cfg.skipVerify,
		PolicyConfig: policyConfig,
	}, scanRunHooks{
		VersionStart: func(name string, version uint16, probeCiphers bool) {
			if verboseOutput {
				fmt.Fprintf(stdout, "\n👉 Trying TLS version %s\n", name)
				if probeCiphers && isPreTLS13(version) {
					fmt.Fprintf(stdout, "🔧 Probing cipher suites for %s\n", name)
				}
				if probeCiphers && isTLS13(version) {
					fmt.Fprintf(stdout, "🔧 Inspecting TLS 1.3 cipher suites for %s\n", name)
				}
			}
		},
		Unsupported: func(result scan.TLSScanResult) {
			if verboseOutput {
				fmt.Fprintf(stdout, "\n🚫 %s: %s\n", result.Version, result.Status)
				if result.ErrorMessage != "" {
					fmt.Fprintf(stdout, "   %s\n", result.ErrorMessage)
				}
			}
		},
		Supported: func(result scan.TLSScanResult, negotiatedCipher string) error {
			if result.Certificate == nil {
				return nil
			}
			if verboseOutput {
				output.PrintCertSummary(stdout, result.Certificate, negotiatedCipher, result.Version, cfg.checkCertExpiry, scan.CertValidation{
					Status:  result.CertValidationStatus,
					Message: result.CertValidationMessage,
				})
				output.PrintTLSPosture(stdout, result)
				output.PrintCipherSuites(stdout, result.CipherSuites, result.CipherDiscovery)
			}
			if !cfg.certChain {
				return nil
			}

			prefix := strings.ReplaceAll(result.Version, " ", "")
			if cfg.outputJSON {
				_, err := certs.SaveCertChainToFile(prefix, result.CertInfos, cfg.outputFile)
				return err
			}
			return certs.SaveOrPrintCertToFile(stdout, prefix, result.CertInfos, cfg.outputFile)
		},
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error saving certificate chain: %v\n", err)
		return 1
	}

	results := runResult.Results
	policyResult := runResult.Policy
	if humanOutput {
		if cfg.compact {
			output.PrintCompactScanResults(stdout, results)
		}
		output.PrintScanSummary(stdout, results)
	}

	var reportPolicy *policy.Result
	if policyResult.Enabled {
		reportPolicy = &policyResult
		if humanOutput {
			printPolicyResult(stdout, policyResult)
		}
	}

	if cfg.outputMarkdown != "" {
		err := output.WriteMarkdownReportToFile(h, port, serverName, build.Version, results, cfg.outputMarkdown, reportPolicy)
		if err != nil {
			fmt.Fprintf(stderr, "❌ Failed to write markdown report: %v\n", err)
			return 1
		} else {
			if humanOutput {
				fmt.Fprintf(stdout, "✅ Markdown report saved to %s\n", cfg.outputMarkdown)
			}
		}
	}

	if cfg.outputSARIF != "" {
		err := output.WriteSARIFReportToFile(h, port, serverName, build.Version, results, cfg.outputSARIF, reportPolicy)
		if err != nil {
			fmt.Fprintf(stderr, "❌ Failed to write SARIF report: %v\n", err)
			return 1
		}
		if humanOutput {
			fmt.Fprintf(stdout, "✅ SARIF report saved to %s\n", cfg.outputSARIF)
		}
	}

	if cfg.outputJUnit != "" {
		err := output.WriteJUnitReportToFile(h, port, serverName, build.Version, results, cfg.outputJUnit, reportPolicy)
		if err != nil {
			fmt.Fprintf(stderr, "❌ Failed to write JUnit report: %v\n", err)
			return 1
		}
		if humanOutput {
			fmt.Fprintf(stdout, "✅ JUnit report saved to %s\n", cfg.outputJUnit)
		}
	}

	if cfg.outputJSON {
		jsonReport, err := output.BuildJSONReport(h, port, serverName, build.Version, time.Now(), results, reportPolicy)
		if err != nil {
			fmt.Fprintf(stderr, "❌ Failed to build JSON report: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(jsonReport))
	}
	if scanRunFailed(results) {
		return 1
	}
	if policyResult.Enabled && !policyResult.Passed {
		return 3
	}
	return 0
}

func printPolicyResult(stdout io.Writer, result policy.Result) {
	status := "passed"
	if !result.Passed {
		status = "failed"
	}
	name := result.Name
	if name == "" {
		name = "custom"
	}
	fmt.Fprintf(stdout, "\nPolicy %s: %s\n", name, status)
	for _, failure := range result.Failures {
		fmt.Fprintf(stdout, "  - [%s] %s\n", failure.Check, failure.Message)
	}
}

func parseCLIArgs(args []string, stderr io.Writer) (cliConfig, error) {
	var cfg cliConfig
	fs := newFlagSet(&cfg, stderr)
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	explicit := make(map[string]bool)
	fs.Visit(func(flag *flag.Flag) {
		explicit[flag.Name] = true
	})

	if cfg.configPath == "" {
		return cfg, nil
	}

	file, err := loadFileConfig(cfg.configPath)
	if err != nil {
		return cfg, cliInputError{err: fmt.Errorf("load config %q: %w", cfg.configPath, err)}
	}

	merged := defaultCLIConfig(stderr)
	merged.configPath = cfg.configPath
	if err := applyFileConfig(&merged, file, cfg.targetName, cfg.profileName); err != nil {
		return cfg, cliInputError{err: err}
	}
	overlayExplicitCLIValues(&merged, cfg, explicit)
	return merged, nil
}

func newFlagSet(cfg *cliConfig, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("tlsanalyzer", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.configPath, "config", "", "JSON config file")
	fs.StringVar(&cfg.targetName, "target", "", "Named target from --config")
	fs.StringVar(&cfg.profileName, "profile", "", "Named policy profile from --config")
	fs.StringVar(&cfg.targetsFile, "targets-file", "", "JSON file with targets to scan in batch mode")
	fs.StringVar(&cfg.host, "host", "", "Hostname or server IP")
	fs.StringVar(&cfg.port, "port", "443", "TLS server port")
	fs.StringVar(&cfg.sni, "sni", "", "TLS Server Name Indication and certificate validation name")
	fs.BoolVar(&cfg.certChain, "cert", false, "Print certificate chain")
	fs.BoolVar(&cfg.checkCertExpiry, "checkcert", false, "Check if the certificate is about to expire")
	fs.IntVar(&cfg.timeout, "timeout", 5, "Connection timeout in seconds")
	fs.StringVar(&cfg.outputFile, "output", "", "Output file for PEM (only with --cert)")
	fs.StringVar(&cfg.minVersionStr, "min-version", "1.0", "Minimum TLS version to test (1.0, 1.1, 1.2, 1.3)")
	fs.StringVar(&cfg.outputMarkdown, "markdown", "", "Write scan result to markdown file")
	fs.StringVar(&cfg.outputSARIF, "sarif", "", "Write policy findings to a SARIF file")
	fs.StringVar(&cfg.outputJUnit, "junit", "", "Write scan and policy results to a JUnit XML file")
	fs.BoolVar(&cfg.forceCiphers, "force-ciphers", false, "Force all cipher suites during version scan")
	fs.BoolVar(&cfg.skipVerify, "skip-verify", false, "Skip certificate validation and report TLS handshake support only")
	fs.BoolVar(&cfg.outputJSON, "json", false, "Write scan result as JSON to stdout")
	fs.BoolVar(&cfg.noClear, "no-clear", false, "Do not clear the terminal before scanning")
	fs.BoolVar(&cfg.compact, "compact", false, "Use compact human-readable console output")
	fs.BoolVar(&cfg.showVersion, "version", false, "Print version information and exit")
	fs.IntVar(&cfg.concurrency, "concurrency", 4, "Maximum concurrent targets in batch mode")
	fs.IntVar(&cfg.retries, "retries", 0, "Retry count for transient network failures")
	fs.IntVar(&cfg.retryBackoff, "retry-backoff", 1, "Base retry backoff in seconds")
	fs.StringVar(&cfg.policy, "policy", "", "Policy to evaluate: modern")
	fs.StringVar(&cfg.failOn, "fail-on", "", "Comma-separated checks that fail the run: legacy-tls, weak-cipher, invalid-cert, expired-cert")
	fs.StringVar(&cfg.requireTLS, "require-tls", "", "Comma-separated TLS versions that must be supported, such as 1.3")
	fs.StringVar(&cfg.forbidTLS, "forbid-tls", "", "Comma-separated TLS versions that must not be supported, such as 1.0,1.1")
	fs.StringVar(&cfg.requireALPN, "require-alpn", "", "Comma-separated ALPN protocols that supported handshakes must negotiate")
	fs.StringVar(&cfg.forbidALPN, "forbid-alpn", "", "Comma-separated ALPN protocols that must not be negotiated")
	fs.IntVar(&cfg.minCertKeyBits, "min-cert-key-bits", 0, "Minimum certificate public key size in bits")
	fs.IntVar(&cfg.minCertDays, "min-cert-days", 0, "Minimum number of days before certificate expiry")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage of tlsanalyzer:")
		fs.PrintDefaults()
	}
	return fs
}

func buildPolicyConfig(cfg cliConfig) (policy.Config, error) {
	requiredTLS, err := policy.ParseTLSVersions(cfg.requireTLS)
	if err != nil {
		return policy.Config{}, err
	}
	forbiddenTLS, err := policy.ParseTLSVersions(cfg.forbidTLS)
	if err != nil {
		return policy.Config{}, err
	}
	return policy.Config{
		Name:                       cfg.policy,
		FailOn:                     policy.ParseFailOn(cfg.failOn),
		RequiredTLSVersions:        requiredTLS,
		ForbiddenTLSVersions:       forbiddenTLS,
		RequiredALPNProtocols:      policy.ParseALPNProtocols(cfg.requireALPN),
		ForbiddenALPNProtocols:     policy.ParseALPNProtocols(cfg.forbidALPN),
		MinCertificateKeyBits:      cfg.minCertKeyBits,
		MinCertificateValidityDays: cfg.minCertDays,
	}, nil
}

func formatVersion() string {
	parts := []string{"tlsanalyzer", build.Version}
	if build.BuildTime != "" {
		parts = append(parts, "built "+build.BuildTime)
	}
	if build.BuildUser != "" {
		parts = append(parts, "by "+build.BuildUser)
	}
	return strings.Join(parts, " ")
}

func writeUsage(stderr io.Writer) {
	var cfg cliConfig
	newFlagSet(&cfg, stderr).Usage()
}

func validateFlagCombination(outputJSON bool, certChain bool, outputFile string) error {
	if outputJSON && certChain && outputFile == "" {
		return fmt.Errorf("--json with --cert requires --output to avoid mixing PEM data with JSON stdout")
	}
	return nil
}

func validateHost(host string) error {
	if host == "" {
		return fmt.Errorf("host cannot be empty")
	}
	if strings.ContainsFunc(host, unicode.IsSpace) {
		return fmt.Errorf("host cannot contain whitespace")
	}
	return nil
}

func validatePort(port string) error {
	if port == "" {
		return fmt.Errorf("port cannot be empty")
	}
	value, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("port must be numeric")
	}
	if value < 1 || value > 65535 {
		return fmt.Errorf("port must be in range 1..65535")
	}
	return nil
}
