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
var (
	host      = flag.String("host", "", "Hostname or server IP (mandatory)")
	port      = flag.String("port", "443", "TLS server port")
	certChain = flag.Bool("cert", false, "Print cerificate chain")
)

func scanTLSVersion(host string, port string, version uint16) (bool, *x509.Certificate, string, error) {
	address := net.JoinHostPort(host, port)
	config := &tls.Config{
		ServerName:         host, // Abilita il supporto SNI
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, config)
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

// Funzione che stampa i certificati
func PrintCertInfos(certInfos []CertInfo) {
	for i, ci := range certInfos {
		fmt.Printf("Certificato %d:\n", i)
		fmt.Printf("  CN:  %s\n", ci.CommonName)
		fmt.Printf("  PEM:\n%s\n", ci.PEM)
	}
}

func main() {

	flag.Parse()
	//args := flag.Args()

	exePath, err := os.Executable()
	if err != nil {
		fmt.Println("Errore nel recuperare il path dell'eseguibile:", err)
		os.Exit(1)
	}

	exeName := filepath.Base(exePath)
	if *host == "" {
		fmt.Printf("\n"+exeName+" Release: %s - Build Time: %s - Build User: %s\n", b.Version, b.BuildTime, b.BuildUser)
		fmt.Println("Error: il parametro --host è obbligatorio.")
		fmt.Println("Usage: " + exeName + " [-cert] -host <host> [-port port]")

		os.Exit(1)
	}
	/**
	if len(args) < 1 {
		fmt.Println("Usage: " + exeName + " [-cert] -host <host> [-port port]")
		fmt.Printf("\n"+exeName+" Release: %s\nBuild Time: %s\nBuild User: %s\n", b.Version, b.BuildTime, b.BuildUser)
		os.Exit(1)
	}

		exeName := filepath.Base(exePath)
		if len(os.Args) < 2 {
			fmt.Println("Usage: " + exeName + " [-cert] <host>[:port]")
			fmt.Printf("\n"+exeName+" Release: %s\nBuild Time: %s\nBuild User: %s\n", b.Version, b.BuildTime, b.BuildUser)
			os.Exit(0)
		}

		input := os.Args[1]
		host, port, err := net.SplitHostPort(input)
		if err != nil {
			host = input
			port = "443"
		}
	**/
	fmt.Printf("\n\033[1mTLS Analisys for:\033[0m [%s:%s]\n", *host, *port)

	for version, name := range tlsVersions {
		supported, cert, cipher, err := scanTLSVersion(*host, *port, version)
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
				fmt.Printf("   DNS: %s\n", cert.DNSNames)
				if *certChain {
					PrintCertInfos(certInfos)
				}
			}
		} else {
			fmt.Printf("\n🚫 "+"%s: unsupported\n", name)
		}
	}
}
