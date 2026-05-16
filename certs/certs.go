// File: certs/certs.go
package certs

import (
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/olelbis/tlsanalyzer/utils"
)

func SaveOrPrintCertToFile(prefix string, certInfos []utils.CertInfo, outputFile string) {
	var output = ""
	if outputFile != "" {
		for _, ci := range certInfos {
			output += ci.PEM
		}
		err := os.WriteFile(prefix+"_"+outputFile, []byte(output), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error saving to file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Output saved to %s\n", prefix+"_"+outputFile)
	} else {
		PrintCertInfos(certInfos)
	}
}

func PrintCertInfos(certInfos []utils.CertInfo) {
	for i, ci := range certInfos {
		fmt.Printf("\nCertificate %d:\n", i)
		fmt.Printf("  CN:  %s\n", ci.CommonName)
		fmt.Printf("  PEM:\n%s\n", ci.PEM)
	}
}

func CheckCertificateExpiry(cert *x509.Certificate) int {
	return daysUntilCertificateExpiry(cert, time.Now())
}

func daysUntilCertificateExpiry(cert *x509.Certificate, now time.Time) int {
	return int(cert.NotAfter.Sub(now).Hours() / 24)
}
