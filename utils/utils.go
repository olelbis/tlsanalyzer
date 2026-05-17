package utils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
)

type CertInfo struct {
	CommonName string
	PEM        string
}

func ClearScreen() {
	ClearScreenTo(os.Stdout)
}

func ClearScreenTo(w io.Writer) {
	switch runtime.GOOS {
	case "linux", "darwin":
		fmt.Fprint(w, "\033[H\033[2J")
	case "windows":
		exec.Command("cmd", "/c", "cls").Run()
	default:
		fmt.Fprintln(w, "Screen cleaning not supported on this system!")
	}
}

func ExtractCertInfos(certs []*x509.Certificate) []CertInfo {
	var infos []CertInfo
	for _, cert := range certs {
		infos = append(infos, CertInfo{
			CommonName: cert.Subject.CommonName,
			PEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		})
	}
	return infos
}

func UniqueStrings(input []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, s := range input {
		if _, exists := seen[s]; !exists {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}
