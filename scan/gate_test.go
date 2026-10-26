package scan

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestScanTLSVersionSeesRSAKeyExchangeOnlyEndpoint(t *testing.T) {
	// crypto/tls leaves static RSA key exchange out of its default cipher
	// suites. An endpoint that only offers it must still be reported as
	// supporting the protocol version, otherwise legacy-only servers vanish
	// from the scan (and from every policy gate).
	server, host, port := newLocalTLSServerWithConfig(t, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
	})
	defer server.Close()

	// Sanity check: skip when this Go version cannot negotiate the suite at all.
	conn, err := tls.Dial("tcp", net.JoinHostPort(host, port), &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- test client for a local fixture
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
	})
	if err != nil {
		t.Skipf("this Go version cannot negotiate TLS_RSA_WITH_AES_128_GCM_SHA256: %v", err)
	}
	conn.Close()

	result := ScanTLSVersion(Options{Host: host, Port: port, Timeout: 3 * time.Second, SkipVerify: true}, tls.VersionTLS12)
	if !result.Supported {
		t.Fatalf("Status = %q (%s), want the RSA-key-exchange-only endpoint to be supported", result.Status, result.ErrorMessage)
	}
	if result.NegotiatedCipherSuite != "TLS_RSA_WITH_AES_128_GCM_SHA256" {
		t.Fatalf("NegotiatedCipherSuite = %q, want TLS_RSA_WITH_AES_128_GCM_SHA256", result.NegotiatedCipherSuite)
	}
}

func TestScanTLSVersionStillNegotiatesForwardSecretSuiteFirst(t *testing.T) {
	// The offered list is ordered by preference, so a server that follows the
	// client's order must not end up reporting a static RSA or 3DES suite.
	server, host, port := newLocalTLSServerWithConfig(t, &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	})
	defer server.Close()

	result := ScanTLSVersion(Options{Host: host, Port: port, Timeout: 3 * time.Second, SkipVerify: true}, tls.VersionTLS12)
	if !result.Supported {
		t.Fatalf("Status = %q (%s), want supported", result.Status, result.ErrorMessage)
	}
	if result.NegotiatedCipherSuite != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Fatalf("NegotiatedCipherSuite = %q, want TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", result.NegotiatedCipherSuite)
	}
}
