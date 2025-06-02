package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	b "github.com/olelbis/sslscango/build"
)

var tlsVersions = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

type CertInfo struct {
	CommonName string
	PEM        string
}

var certInfos []CertInfo

// Command line flags definition
var (
	host            = flag.String("host", "", "Hostname or server IP (mandatory)")
	port            = flag.String("port", "443", "TLS server port")
	certChain       = flag.Bool("cert", false, "Print cerificate chain")
	checkCertExpiry = flag.Bool("checkcert", false, "Check if the certificate is about to expire")
	timeout         = flag.Int("timeout", 5, "Connection Timeout")
	outputFile      = flag.String("output", "", "File to save the PEM output to (optional), only used with --cert")
	minVersionStr   = flag.String("min-version", "1.0", "Minimum TLS version to test (1.0, 1.1, 1.2, 1.3)")
)

// TLS String to Constant Conversion
func tlsVersionToUint16(ver string) uint16 {
	switch ver {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS10
	}
}

func scanTLSVersion(host string, port string, version uint16, timeoutSec int) (bool, *x509.Certificate, string, error) {
	address := net.JoinHostPort(host, port)
	config := &tls.Config{
		ServerName:         host, // Enable SNI support
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second}, "tcp", address, config)
	if err != nil {
		return false, nil, "", nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	for _, cert := range state.PeerCertificates {
		ci := CertInfo{
			CommonName: cert.Subject.CommonName,
			PEM: string(pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})),
		}
		certInfos = append(certInfos, ci)
	}
	cipher := tls.CipherSuiteName(state.CipherSuite)
	if len(state.PeerCertificates) > 0 {
		return true, state.PeerCertificates[0], cipher, nil
	}
	return true, nil, cipher, nil
}

// Certificate Informaion print function
func printCertInfos(certInfos []CertInfo) {
	for i, ci := range certInfos {
		fmt.Printf("\nCertificate %d:\n", i)
		fmt.Printf("  CN:  %s\n", ci.CommonName)
		fmt.Printf("  PEM:\n%s\n", ci.PEM)
	}
}

// Calculate the days remaining until the certificate expires
func checkCertificateExpiry(cert *x509.Certificate) int {
	return int(time.Until(cert.NotAfter).Hours() / 24)
}

func saveOrPrintCertToFile(prefix string, certInfos []CertInfo) {
	var output = ""
	if *outputFile != "" {
		for _, ci := range certInfos {

			output += ci.PEM
		}
		err := os.WriteFile(prefix+"_"+*outputFile, []byte(output), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error saving to file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Output saved to %s\n", prefix+"_"+*outputFile)
		output = ""
	} else {
		printCertInfos(certInfos)
	}
}

func main() {

	flag.Parse()

	exePath, err := os.Executable()
	if err != nil {
		fmt.Println("Errore nel recuperare il path dell'eseguibile:", err)
		os.Exit(1)
	}

	exeName := filepath.Base(exePath)
	if *host == "" {
		fmt.Printf("\n"+exeName+" Release: %s - Build Time: %s - Build User: %s\n", b.Version, b.BuildTime, b.BuildUser)
		fmt.Println("Error: parameter --host is mandatory.")
		fmt.Println("Usage: " + exeName + " [--cert] [--checkcert] --host <host> [--port <portnumber>] [--timeout <sec>] [--output <file>]")

		os.Exit(1)
	}

	minVersion := tlsVersionToUint16(*minVersionStr)
	//results := []Result{}

	// Sort versions in ascending order
	keys := make([]uint16, 0, len(tlsVersions))
	for v := range tlsVersions {
		if v >= minVersion {
			keys = append(keys, v)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	fmt.Printf("\n\033[1mTLS Analisys for:\033[0m [%s:%s]\n", *host, *port)

	//for version, name := range tlsVersions {
	for _, version := range keys {
		name := tlsVersions[version]
		supported, cert, cipher, err := scanTLSVersion(*host, *port, version, *timeout)
		if err != nil {
			fmt.Printf("%s: errore %v\n", name, err)
			continue
		}
		if supported {
			fmt.Printf("\n✅ "+"\033[1m%s\033[0m: supported\n", name)
			fmt.Printf("   Cipher suite: %s\n", cipher)
			if cert != nil {
				fmt.Printf("   CN: %s\n", cert.Subject.CommonName)
				fmt.Printf("   Issuer: %s\n", cert.Issuer.CommonName)
				fmt.Printf("   Valid: %s - %s\n", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))

				if *checkCertExpiry {
					fmt.Printf("   Days to Expiration: %d\n", checkCertificateExpiry(cert))

				}

				fmt.Printf("   DNS: %s\n", cert.DNSNames)

				if *certChain {
					saveOrPrintCertToFile(strings.ReplaceAll(name, " ", ""), certInfos)
				}
				certInfos = nil
			}

		} else {
			fmt.Printf("\n🚫 "+"%s: unsupported\n", name)
		}
	}
}
