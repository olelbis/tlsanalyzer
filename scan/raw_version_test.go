package scan

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

// rawOnlySuites are suites a crypto/tls server can serve but ScanTLSVersion
// never offers, because utils.AllCipherSuites leaves them out.
var rawOnlySuites = []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA}

func TestScanTLSVersionDetectsVersionWithRawProbe(t *testing.T) {
	server, host, port := newLocalTLSServerWithConfig(t, &tls.Config{
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: rawOnlySuites,
	})
	defer server.Close()

	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12} {
		result := ScanTLSVersion(Options{Host: host, Port: port, Timeout: 2 * time.Second, SkipVerify: true}, version)

		if !result.Supported || result.Status != ScanStatusSupported {
			t.Fatalf("%s Status = %q (%s), want an RC4-only endpoint to be reported as supported", result.Version, result.Status, result.ErrorMessage)
		}
		if result.VersionEvidence != VersionEvidenceRawProbe {
			t.Fatalf("%s VersionEvidence = %q, want %q", result.Version, result.VersionEvidence, VersionEvidenceRawProbe)
		}
		if !strings.Contains(result.NegotiatedCipherSuite, "_RC4_128_SHA") || len(result.CipherSuites) != 1 {
			t.Fatalf("%s NegotiatedCipherSuite = %q CipherSuites = %v, want the RC4 suite the server selected", result.Version, result.NegotiatedCipherSuite, result.CipherSuites)
		}
		if result.Certificate != nil || result.CertValidationStatus != CertValidationUnavailable {
			t.Fatalf("%s certificate = %v status = %q, want no certificate and %q", result.Version, result.Certificate, result.CertValidationStatus, CertValidationUnavailable)
		}
		if result.HandshakeAttempts != 2 {
			t.Fatalf("%s HandshakeAttempts = %d, want the failed handshake plus one raw probe", result.Version, result.HandshakeAttempts)
		}
		if !strings.Contains(result.ErrorMessage, "handshake failure") {
			t.Fatalf("%s ErrorMessage = %q, want the reason the full handshake failed", result.Version, result.ErrorMessage)
		}
		if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "ClientHello-only raw probe") {
			t.Fatalf("%s Warnings = %v, want one warning about raw version evidence", result.Version, result.Warnings)
		}
	}
}

func TestScanTLSVersionFullHandshakeHasNoRawEvidence(t *testing.T) {
	server, host, port := newLocalTLSServerWithConfig(t, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
	defer server.Close()

	result := ScanTLSVersion(Options{Host: host, Port: port, Timeout: 2 * time.Second, SkipVerify: true}, tls.VersionTLS12)
	if !result.Supported || result.VersionEvidence != "" || result.HandshakeAttempts != 1 || result.Certificate == nil {
		t.Fatalf("result = supported %t evidence %q attempts %d, want a plain full-handshake result", result.Supported, result.VersionEvidence, result.HandshakeAttempts)
	}
}

// A version the server rejects outright is final: no raw probe is spent on it.
func TestScanTLSVersionDoesNotRawProbeRejectedVersion(t *testing.T) {
	server, host, port := newLocalTLSServerWithConfig(t, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: rawOnlySuites,
	})
	defer server.Close()

	result := ScanTLSVersion(Options{Host: host, Port: port, Timeout: 2 * time.Second, SkipVerify: true}, tls.VersionTLS10)
	if result.Supported || result.Status != ScanStatusUnsupported || result.HandshakeAttempts != 1 {
		t.Fatalf("result = supported %t status %q attempts %d, want unsupported after one attempt", result.Supported, result.Status, result.HandshakeAttempts)
	}
}

func TestScanTLSVersionDoesNotRawProbeUnreachablePort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	listener.Close()

	result := ScanTLSVersion(Options{Host: host, Port: port, Timeout: time.Second, SkipVerify: true}, tls.VersionTLS12)
	if result.Supported || result.Status != ScanStatusNetworkError || result.HandshakeAttempts != 1 {
		t.Fatalf("result = supported %t status %q attempts %d, want a network error after one attempt", result.Supported, result.Status, result.HandshakeAttempts)
	}
}

// When the raw probe is refused as well, the original failure is reported.
func TestScanTLSVersionKeepsFailureWhenRawProbeIsRefused(t *testing.T) {
	// The fixture answers every ClientHello with a fatal handshake_failure.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 4096)
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte{21, 3, 3, 0, 2, 2, 40})
			}()
		}
	}()
	host, port, _ := net.SplitHostPort(listener.Addr().String())

	result := ScanTLSVersion(Options{Host: host, Port: port, Timeout: time.Second, SkipVerify: true}, tls.VersionTLS12)
	if result.Supported || result.Status != ScanStatusHandshake {
		t.Fatalf("result = supported %t status %q, want the handshake error to stand", result.Supported, result.Status)
	}
	if result.HandshakeAttempts != 2 || result.VersionEvidence != "" {
		t.Fatalf("attempts %d evidence %q, want two attempts and no raw evidence", result.HandshakeAttempts, result.VersionEvidence)
	}
}

// The cipher probe must not flag a raw-only endpoint as incomplete just
// because none of its suites can be confirmed with a full handshake.
func TestProbeCipherSuitesOnRawOnlyEndpointIsComplete(t *testing.T) {
	server, host, port := newLocalTLSServerWithConfig(t, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: rawOnlySuites,
	})
	defer server.Close()

	result := ProbeCipherSuitesForVersion(Options{Host: host, Port: port, Timeout: 2 * time.Second, SkipVerify: true}, tls.VersionTLS12)

	if result.Incomplete {
		t.Fatalf("Incomplete = true, warnings %v", result.Warnings)
	}
	if len(result.CipherSuites) != 2 {
		t.Fatalf("CipherSuites = %v, want both RC4 suites", result.CipherSuites)
	}
	for _, status := range result.Statuses {
		if status.Status != "supported" || status.Evidence != "clienthello-serverhello" {
			t.Fatalf("Statuses = %+v, want ClientHello-only rows for both suites", result.Statuses)
		}
	}
}

// A TLS 1.2 endpoint that demands a client certificate aborts the crypto/tls
// handshake too. The version is still supported, and the result keeps the
// real reason the handshake failed instead of blaming the cipher suites.
func TestScanTLSVersionReportsVersionBehindClientCertificateRequirement(t *testing.T) {
	server, host, port := newLocalTLSServerWithConfig(t, &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAnyClientCert,
	})
	defer server.Close()

	result := ScanTLSVersion(Options{Host: host, Port: port, Timeout: 2 * time.Second, SkipVerify: true}, tls.VersionTLS12)
	if !result.Supported || result.VersionEvidence != VersionEvidenceRawProbe {
		t.Fatalf("result = supported %t status %q evidence %q (%s), want supported with raw evidence", result.Supported, result.Status, result.VersionEvidence, result.ErrorMessage)
	}
	if result.ErrorMessage == "" {
		t.Fatal("ErrorMessage is empty, want the reason the full handshake failed")
	}
}
