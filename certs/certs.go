// File: certs/certs.go
package certs

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/olelbis/tlsanalyzer/utils"
)

func SaveOrPrintCertToFile(prefix string, certInfos []utils.CertInfo, outputFile string) error {
	if outputFile != "" {
		outputPath, err := SaveCertChainToFile(prefix, certInfos, outputFile)
		if err != nil {
			return err
		}
		fmt.Printf("Output saved to %s\n", outputPath)
		return nil
	} else {
		PrintCertInfos(certInfos)
	}
	return nil
}

func SaveCertChainToFile(prefix string, certInfos []utils.CertInfo, outputFile string) (string, error) {
	if outputFile == "" {
		return "", fmt.Errorf("output file is required")
	}
	var output strings.Builder
	for _, ci := range certInfos {
		output.WriteString(ci.PEM)
	}
	outputPath := filepath.Join(filepath.Dir(outputFile), prefix+"_"+filepath.Base(outputFile))
	if err := os.WriteFile(outputPath, []byte(output.String()), 0644); err != nil {
		return "", fmt.Errorf("saving certificate chain: %w", err)
	}
	return outputPath, nil
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
