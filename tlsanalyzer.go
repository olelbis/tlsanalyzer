package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"tlsanalyzer/certs"
	"tlsanalyzer/output"
	"tlsanalyzer/scan"
	"tlsanalyzer/utils"
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
	if h == "" {
		fmt.Println("Error: host cannot be empty")
		os.Exit(1)
	}

	minVersion := utils.TLSVersionToUint16(*scan.MinVersionStr)
	if minVersion == 0 {
		fmt.Printf("Error: invalid --min-version '%s'. Use 1.0, 1.1, 1.2 or 1.3\n", *scan.MinVersionStr)
		os.Exit(1)
	}

	fmt.Printf("\nStarting TLS analysis for %s:%s with minimum TLS version %s\n", h, *scan.Port, *scan.MinVersionStr)
	keys := utils.FilterTLSVersions(minVersion)

	fmt.Printf("\n\033[1mTLS Analysis for:\033[0m [%s:%s]\n", *scan.Host, *scan.Port)
	var results []scan.TLSScanResult

	for _, version := range keys {
		name := utils.TLSVersions[version]
		supported, cert, cipher, infos, err := scan.ScanTLSVersion(*scan.Host, *scan.Port, version, *scan.Timeout)
		if err != nil {
			fmt.Printf("\n🚫 %s: unsupported\n", name)
			results = append(results, scan.TLSScanResult{Version: name, Supported: false})
			continue
		}

		if supported {
			ciphers := scan.GetSupportedCiphersForVersion(*scan.Host, *scan.Port, *scan.Timeout, version)

			results = append(results, scan.TLSScanResult{
				Version:      name,
				CipherSuites: ciphers,
				Supported:    true,
				Certificate:  cert,
			})

			if cert != nil {
				output.PrintCertSummary(cert, cipher, name, *scan.CheckCertExpiry)
				output.PrintCipherSuites(ciphers)
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
		err := output.WriteMarkdownReportToFile(*scan.Host, *scan.Port, results, *scan.OutputMarkdown)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to write markdown report: %v\n", err)
		} else {
			fmt.Printf("✅ Markdown report saved to %s\n", *scan.OutputMarkdown)
		}
	}
}
