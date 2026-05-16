package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"

	"github.com/olelbis/tlsanalyzer/certs"
	"github.com/olelbis/tlsanalyzer/output"
	"github.com/olelbis/tlsanalyzer/scan"
	"github.com/olelbis/tlsanalyzer/utils"
)

func main() {
	utils.ClearScreen()
	flag.Parse()

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

	fmt.Printf("\nStarting TLS analysis for %s:%s with minimum TLS version %s\n", h, port, *scan.MinVersionStr)
	keys := utils.FilterTLSVersions(minVersion)

	fmt.Printf("\n\033[1mTLS Analysis for:\033[0m [%s:%s]\n", h, port)
	var results []scan.TLSScanResult

	for _, version := range keys {
		name := utils.TLSVersions[version]
		supported, cert, cipher, infos, validation, err := scan.ScanTLSVersion(h, port, version, *scan.Timeout, *scan.SkipVerify)
		if err != nil {
			fmt.Printf("\n🚫 %s: unsupported\n", name)
			results = append(results, scan.TLSScanResult{Version: name, Supported: false})
			continue
		}

		if supported {
			ciphers := scan.GetSupportedCiphersForVersion(h, port, *scan.Timeout, version)

			results = append(results, scan.TLSScanResult{
				Version:               name,
				CipherSuites:          ciphers,
				CipherSuitesObserved:  version == tls.VersionTLS13,
				Supported:             true,
				Certificate:           cert,
				CertValidationStatus:  validation.Status,
				CertValidationMessage: validation.Message,
			})

			if cert != nil {
				output.PrintCertSummary(cert, cipher, name, *scan.CheckCertExpiry, validation)
				output.PrintCipherSuites(ciphers, version == tls.VersionTLS13)
				if *scan.CertChain {
					certs.SaveOrPrintCertToFile(strings.ReplaceAll(name, " ", ""), infos, *scan.OutputFile)
				}
			}
		} else {
			fmt.Printf("\n🚫 %s: unsupported\n", name)
			results = append(results, scan.TLSScanResult{Version: name, Supported: false})
		}
	}

	if *scan.OutputMarkdown != "" {
		err := output.WriteMarkdownReportToFile(h, port, results, *scan.OutputMarkdown)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to write markdown report: %v\n", err)
		} else {
			fmt.Printf("✅ Markdown report saved to %s\n", *scan.OutputMarkdown)
		}
	}
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
