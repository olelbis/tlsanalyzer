package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"
)

var tlsVersions = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

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
	cipher := tls.CipherSuiteName(state.CipherSuite)
	if len(state.PeerCertificates) > 0 {
		return true, state.PeerCertificates[0], cipher, nil
	}
	return true, nil, cipher, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Uso: go run sslscan <host>[:port]")
		return
	}

	input := os.Args[1]
	host, port, err := net.SplitHostPort(input)
	if err != nil {
		host = input
		port = "443"
	}

	fmt.Printf("Analisi TLS per %s:%s\n\n", host, port)

	for version, name := range tlsVersions {
		supported, cert, cipher, err := scanTLSVersion(host, port, version)
		if err != nil {
			fmt.Printf("%s: errore %v\n", name, err)
			continue
		}
		if supported {
			fmt.Printf("✅ "+"%s: supportato\n", name)
			fmt.Printf("  Cipher suite: %s\n", cipher)
			if cert != nil {
				fmt.Printf("  CN: %s\n", cert.Subject.CommonName)
				fmt.Printf("  Issuer: %s\n", cert.Issuer.CommonName)
				fmt.Printf("  Valido: %s - %s\n", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
				fmt.Printf("  DNS: %s\n", cert.DNSNames)
			}
		} else {
			fmt.Printf("🚫 "+"%s: non supportato\n", name)
		}
	}
}
