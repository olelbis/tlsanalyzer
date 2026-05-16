package certs

import (
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"

	"github.com/olelbis/tlsanalyzer/utils"
)

func TestDaysUntilCertificateExpiry(t *testing.T) {
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	cert := &x509.Certificate{
		NotAfter: now.Add(72 * time.Hour),
	}

	got := daysUntilCertificateExpiry(cert, now)
	if got != 3 {
		t.Fatalf("daysUntilCertificateExpiry() = %d, want 3", got)
	}
}

func TestSaveOrPrintCertToFileReturnsWriteErrors(t *testing.T) {
	certInfos := []utils.CertInfo{{PEM: "pem"}}
	outputFile := filepath.Join("missing-dir", "chain.pem")

	err := SaveOrPrintCertToFile("TLS12", certInfos, outputFile)
	if err == nil {
		t.Fatal("SaveOrPrintCertToFile() error = nil, want error")
	}
}
