package certs

import (
	"crypto/x509"
	"io"
	"os"
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

	err := SaveOrPrintCertToFile(io.Discard, "TLS12", certInfos, outputFile)
	if err == nil {
		t.Fatal("SaveOrPrintCertToFile() error = nil, want error")
	}
}

func TestSaveCertChainToFile(t *testing.T) {
	certInfos := []utils.CertInfo{{PEM: "pem-one\n"}, {PEM: "pem-two\n"}}
	outputFile := filepath.Join(t.TempDir(), "chain.pem")

	outputPath, err := SaveCertChainToFile("TLS12", certInfos, outputFile)
	if err != nil {
		t.Fatalf("SaveCertChainToFile() error = %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", outputPath, err)
	}
	if string(data) != "pem-one\npem-two\n" {
		t.Fatalf("saved certificate chain = %q", string(data))
	}
}
