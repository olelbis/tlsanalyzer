package main

import (
	"crypto/tls"
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
	host            string
	port            string
	sni             string
	certChain       bool
	checkCertExpiry bool
	timeout         int
	outputFile      string
	minVersionStr   string
	outputMarkdown  string
	forceCiphers    bool
	skipVerify      bool
	outputJSON      bool
	noClear         bool
	policy          string
	failOn          string
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
		return 2
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
	policyConfig := policy.Config{
		Name:   cfg.policy,
		FailOn: policy.ParseFailOn(cfg.failOn),
	}
	if err := policy.ValidateConfig(policyConfig); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	probeCiphers := cfg.forceCiphers || policy.RequiresCipherProbe(policyConfig)

	if !cfg.noClear && !cfg.outputJSON {
		utils.ClearScreenTo(stdout)
	}

	if !cfg.outputJSON {
		fmt.Fprintf(stdout, "\nStarting TLS analysis for %s:%s with minimum TLS version %s\n", h, port, cfg.minVersionStr)
		if serverName != "" {
			fmt.Fprintf(stdout, "Using SNI/certificate name %s\n", serverName)
		}
	}
	keys := utils.FilterTLSVersions(minVersion)
	opts := scan.Options{
		Host:         h,
		Port:         port,
		ServerName:   serverName,
		Timeout:      time.Duration(cfg.timeout) * time.Second,
		MinVersion:   minVersion,
		ForceCiphers: cfg.forceCiphers,
		SkipVerify:   cfg.skipVerify,
	}

	if !cfg.outputJSON {
		fmt.Fprintf(stdout, "\n\033[1mTLS Analysis for:\033[0m [%s:%s]\n", opts.Host, opts.Port)
	}
	var results []scan.TLSScanResult

	for _, version := range keys {
		name := utils.TLSVersions[version]
		if !cfg.outputJSON {
			fmt.Fprintf(stdout, "\n👉 Trying TLS version %s", name)
			if probeCiphers && version <= tls.VersionTLS12 {
				fmt.Fprintf(stdout, "\n🔧 Probing cipher suites for %s", name)
			}
			if probeCiphers && version == tls.VersionTLS13 {
				fmt.Fprintf(stdout, "\n👀 Observing TLS 1.3 cipher suites for %s", name)
			}
		}

		result := scan.ScanTLSVersion(opts, version)
		if !result.Supported {
			if !cfg.outputJSON {
				fmt.Fprintf(stdout, "\n🚫 %s: %s\n", name, result.Status)
				if result.ErrorMessage != "" {
					fmt.Fprintf(stdout, "   %s\n", result.ErrorMessage)
				}
			}
			results = append(results, result)
			continue
		}

		negotiatedCipher := ""
		if len(result.CipherSuites) > 0 {
			negotiatedCipher = result.CipherSuites[0]
		}
		if probeCiphers {
			probe := scan.ProbeCipherSuitesForVersion(opts, version)
			result.CipherSuites = probe.CipherSuites
			result.CipherDiscovery = probe.Discovery
			result.CipherSuitesObserved = probe.ObservedOnly
			result.CipherProbeDurationMillis = probe.DurationMillis
			result.HandshakeAttempts += probe.Attempts
			result.Warnings = append(result.Warnings, probe.Warnings...)
		}
		results = append(results, result)

		if result.Certificate != nil {
			if !cfg.outputJSON {
				output.PrintCertSummary(stdout, result.Certificate, negotiatedCipher, name, cfg.checkCertExpiry, scan.CertValidation{
					Status:  result.CertValidationStatus,
					Message: result.CertValidationMessage,
				})
				output.PrintCipherSuites(stdout, result.CipherSuites, result.CipherDiscovery)
			}
			if cfg.certChain {
				prefix := strings.ReplaceAll(name, " ", "")
				if cfg.outputJSON {
					if _, err := certs.SaveCertChainToFile(prefix, result.CertInfos, cfg.outputFile); err != nil {
						fmt.Fprintf(stderr, "Error saving certificate chain: %v\n", err)
						return 1
					}
				} else if err := certs.SaveOrPrintCertToFile(stdout, prefix, result.CertInfos, cfg.outputFile); err != nil {
					fmt.Fprintf(stderr, "Error saving certificate chain: %v\n", err)
					return 1
				}
			}
		}
	}

	policyResult := policy.Evaluate(results, policyConfig, time.Now())
	if !cfg.outputJSON {
		output.PrintScanSummary(stdout, results)
	}

	var reportPolicy *policy.Result
	if policyResult.Enabled {
		reportPolicy = &policyResult
		if !cfg.outputJSON {
			printPolicyResult(stdout, policyResult)
		}
	}

	if cfg.outputMarkdown != "" {
		err := output.WriteMarkdownReportToFile(h, port, serverName, build.Version, results, cfg.outputMarkdown, reportPolicy)
		if err != nil {
			fmt.Fprintf(stderr, "❌ Failed to write markdown report: %v\n", err)
			return 1
		} else {
			if !cfg.outputJSON {
				fmt.Fprintf(stdout, "✅ Markdown report saved to %s\n", cfg.outputMarkdown)
			}
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
	return cfg, nil
}

func newFlagSet(cfg *cliConfig, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("tlsanalyzer", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.host, "host", "", "Hostname or server IP (mandatory)")
	fs.StringVar(&cfg.port, "port", "443", "TLS server port")
	fs.StringVar(&cfg.sni, "sni", "", "TLS Server Name Indication and certificate validation name")
	fs.BoolVar(&cfg.certChain, "cert", false, "Print certificate chain")
	fs.BoolVar(&cfg.checkCertExpiry, "checkcert", false, "Check if the certificate is about to expire")
	fs.IntVar(&cfg.timeout, "timeout", 5, "Connection timeout in seconds")
	fs.StringVar(&cfg.outputFile, "output", "", "Output file for PEM (only with --cert)")
	fs.StringVar(&cfg.minVersionStr, "min-version", "1.0", "Minimum TLS version to test (1.0, 1.1, 1.2, 1.3)")
	fs.StringVar(&cfg.outputMarkdown, "markdown", "", "Write scan result to markdown file")
	fs.BoolVar(&cfg.forceCiphers, "force-ciphers", false, "Force all cipher suites during version scan")
	fs.BoolVar(&cfg.skipVerify, "skip-verify", false, "Skip certificate validation and report TLS handshake support only")
	fs.BoolVar(&cfg.outputJSON, "json", false, "Write scan result as JSON to stdout")
	fs.BoolVar(&cfg.noClear, "no-clear", false, "Do not clear the terminal before scanning")
	fs.StringVar(&cfg.policy, "policy", "", "Policy to evaluate: modern")
	fs.StringVar(&cfg.failOn, "fail-on", "", "Comma-separated checks that fail the run: legacy-tls, weak-cipher, invalid-cert, expired-cert")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage of tlsanalyzer:")
		fs.PrintDefaults()
	}
	return fs
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
