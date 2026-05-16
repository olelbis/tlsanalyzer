package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/olelbis/tlsanalyzer/build"
	"github.com/olelbis/tlsanalyzer/certs"
	"github.com/olelbis/tlsanalyzer/output"
	"github.com/olelbis/tlsanalyzer/scan"
	"github.com/olelbis/tlsanalyzer/utils"
)

func main() {
	flag.Parse()
	if !*scan.NoClear && !*scan.OutputJSON {
		utils.ClearScreen()
	}

	if *scan.Host == "" {
		fmt.Println("Error: --host is required")
		flag.Usage()
		os.Exit(1)
	}

	h := strings.TrimSpace(*scan.Host)
	if err := validateHost(h); err != nil {
		fmt.Printf("Error: invalid --host '%s': %v\n", *scan.Host, err)
		os.Exit(1)
	}

	port := strings.TrimSpace(*scan.Port)
	if err := validatePort(port); err != nil {
		fmt.Printf("Error: invalid --port '%s': %v\n", *scan.Port, err)
		os.Exit(1)
	}
	if *scan.Timeout < 1 {
		fmt.Println("Error: --timeout must be at least 1 second")
		os.Exit(1)
	}

	minVersion := utils.TLSVersionToUint16(*scan.MinVersionStr)
	if minVersion == 0 {
		fmt.Printf("Error: invalid --min-version '%s'. Use 1.0, 1.1, 1.2 or 1.3\n", *scan.MinVersionStr)
		os.Exit(1)
	}
	if err := validateFlagCombination(*scan.OutputJSON, *scan.CertChain, strings.TrimSpace(*scan.OutputFile)); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if !*scan.OutputJSON {
		fmt.Printf("\nStarting TLS analysis for %s:%s with minimum TLS version %s\n", h, port, *scan.MinVersionStr)
	}
	keys := utils.FilterTLSVersions(minVersion)
	opts := scan.Options{
		Host:         h,
		Port:         port,
		Timeout:      time.Duration(*scan.Timeout) * time.Second,
		MinVersion:   minVersion,
		ForceCiphers: *scan.ForceCiphers,
		SkipVerify:   *scan.SkipVerify,
	}

	if !*scan.OutputJSON {
		fmt.Printf("\n\033[1mTLS Analysis for:\033[0m [%s:%s]\n", opts.Host, opts.Port)
	}
	var results []scan.TLSScanResult

	for _, version := range keys {
		name := utils.TLSVersions[version]
		if !*scan.OutputJSON {
			fmt.Printf("\n👉 Trying TLS version %s", name)
			if opts.ForceCiphers && version <= tls.VersionTLS12 {
				fmt.Printf("\n🔧 Forcing cipher suites for %s", name)
			}
		}

		result := scan.ScanTLSVersion(opts, version)
		if !result.Supported {
			if !*scan.OutputJSON {
				fmt.Printf("\n🚫 %s: %s\n", name, result.Status)
				if result.ErrorMessage != "" {
					fmt.Printf("   %s\n", result.ErrorMessage)
				}
			}
			results = append(results, result)
			continue
		}

		negotiatedCipher := ""
		if len(result.CipherSuites) > 0 {
			negotiatedCipher = result.CipherSuites[0]
		}
		result.CipherSuites = scan.GetSupportedCiphersForVersion(opts, version)
		result.CipherSuitesObserved = version == tls.VersionTLS13
		results = append(results, result)

		if result.Certificate != nil {
			if !*scan.OutputJSON {
				output.PrintCertSummary(result.Certificate, negotiatedCipher, name, *scan.CheckCertExpiry, scan.CertValidation{
					Status:  result.CertValidationStatus,
					Message: result.CertValidationMessage,
				})
				output.PrintCipherSuites(result.CipherSuites, result.CipherSuitesObserved)
			}
			if *scan.CertChain {
				prefix := strings.ReplaceAll(name, " ", "")
				if *scan.OutputJSON {
					if _, err := certs.SaveCertChainToFile(prefix, result.CertInfos, *scan.OutputFile); err != nil {
						fmt.Fprintf(os.Stderr, "Error saving certificate chain: %v\n", err)
						os.Exit(1)
					}
				} else if err := certs.SaveOrPrintCertToFile(prefix, result.CertInfos, *scan.OutputFile); err != nil {
					fmt.Fprintf(os.Stderr, "Error saving certificate chain: %v\n", err)
					os.Exit(1)
				}
			}
		}
	}

	if *scan.OutputMarkdown != "" {
		err := output.WriteMarkdownReportToFile(h, port, build.Version, results, *scan.OutputMarkdown)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to write markdown report: %v\n", err)
			os.Exit(1)
		} else {
			if !*scan.OutputJSON {
				fmt.Printf("✅ Markdown report saved to %s\n", *scan.OutputMarkdown)
			}
		}
	}

	if *scan.OutputJSON {
		jsonReport, err := output.BuildJSONReport(h, port, build.Version, time.Now(), results)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to build JSON report: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(jsonReport))
	}
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
