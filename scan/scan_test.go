package scan

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidatePeerCertificatesSkipVerify(t *testing.T) {
	got := ValidatePeerCertificates("example.com", nil, true)

	if got.Status != CertValidationSkipped {
		t.Fatalf("Status = %q, want %q", got.Status, CertValidationSkipped)
	}
	if got.Message == "" {
		t.Fatal("Message should explain that validation was skipped")
	}
}

func TestValidatePeerCertificatesUnavailable(t *testing.T) {
	got := ValidatePeerCertificates("example.com", nil, false)

	if got.Status != CertValidationUnavailable {
		t.Fatalf("Status = %q, want %q", got.Status, CertValidationUnavailable)
	}
	if got.Message == "" {
		t.Fatal("Message should explain why validation is unavailable")
	}
}

func TestScanTLSVersionLocalTLS12(t *testing.T) {
	server, host, port := newLocalTLSServer(t, tls.VersionTLS12, tls.VersionTLS12)
	defer server.Close()

	result := ScanTLSVersion(Options{
		Host:       host,
		Port:       port,
		Timeout:    time.Second,
		SkipVerify: true,
	}, tls.VersionTLS12)

	if !result.Supported {
		t.Fatalf("Supported = false, status %q, error %q", result.Status, result.ErrorMessage)
	}
	if result.Status != ScanStatusSupported {
		t.Fatalf("Status = %q, want %q", result.Status, ScanStatusSupported)
	}
	if result.CertValidationStatus != CertValidationSkipped {
		t.Fatalf("CertValidationStatus = %q, want %q", result.CertValidationStatus, CertValidationSkipped)
	}
	if result.Certificate == nil {
		t.Fatal("Certificate should be captured")
	}
	if result.NegotiatedCipherSuite == "" {
		t.Fatal("NegotiatedCipherSuite should be captured")
	}
	if result.DurationMillis < 0 {
		t.Fatalf("DurationMillis = %d, want non-negative", result.DurationMillis)
	}
}

func TestScanTLSVersionLocalTLS13(t *testing.T) {
	server, host, port := newLocalTLSServer(t, tls.VersionTLS13, tls.VersionTLS13)
	defer server.Close()

	result := ScanTLSVersion(Options{
		Host:       host,
		Port:       port,
		Timeout:    time.Second,
		SkipVerify: true,
	}, tls.VersionTLS13)

	if !result.Supported {
		t.Fatalf("Supported = false, status %q, error %q", result.Status, result.ErrorMessage)
	}
	if len(result.CipherSuites) != 1 {
		t.Fatalf("CipherSuites = %v, want negotiated cipher", result.CipherSuites)
	}
	if result.CipherDiscovery != CipherDiscoveryNegotiated {
		t.Fatalf("CipherDiscovery = %q, want %q", result.CipherDiscovery, CipherDiscoveryNegotiated)
	}
	if result.HandshakeAttempts != 1 {
		t.Fatalf("HandshakeAttempts = %d, want 1", result.HandshakeAttempts)
	}
}

func TestOptionsTLSServerNameUsesOverride(t *testing.T) {
	opts := Options{Host: "127.0.0.1", ServerName: "example.com"}
	if got := opts.tlsServerName(); got != "example.com" {
		t.Fatalf("tlsServerName() = %q, want example.com", got)
	}

	opts = Options{Host: "example.org"}
	if got := opts.tlsServerName(); got != "example.org" {
		t.Fatalf("tlsServerName() = %q, want example.org", got)
	}
}

func TestScanTLSVersionSendsServerName(t *testing.T) {
	const expectedServerName = "service.example.test"
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if hello.ServerName != expectedServerName {
				return nil, errors.New("unexpected SNI")
			}
			return nil, nil
		},
	}
	server.StartTLS()
	defer server.Close()

	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split server address: %v", err)
	}

	result := ScanTLSVersion(Options{
		Host:       host,
		Port:       port,
		ServerName: expectedServerName,
		Timeout:    time.Second,
		SkipVerify: true,
	}, tls.VersionTLS12)

	if !result.Supported {
		t.Fatalf("Supported = false, status %q, error %q", result.Status, result.ErrorMessage)
	}
	if result.CertValidationStatus != CertValidationSkipped {
		t.Fatalf("CertValidationStatus = %q, want %q", result.CertValidationStatus, CertValidationSkipped)
	}
}

func TestScanTLSVersionInvalidCertificateIsNotUnsupportedTLS(t *testing.T) {
	server, host, port := newLocalTLSServer(t, tls.VersionTLS12, tls.VersionTLS12)
	defer server.Close()

	result := ScanTLSVersion(Options{
		Host:    host,
		Port:    port,
		Timeout: time.Second,
	}, tls.VersionTLS12)

	if !result.Supported {
		t.Fatalf("Supported = false, status %q, error %q", result.Status, result.ErrorMessage)
	}
	if result.CertValidationStatus != CertValidationInvalid {
		t.Fatalf("CertValidationStatus = %q, want %q", result.CertValidationStatus, CertValidationInvalid)
	}
}

func TestScanTLSVersionUnsupportedProtocol(t *testing.T) {
	server, host, port := newLocalTLSServer(t, tls.VersionTLS12, tls.VersionTLS12)
	defer server.Close()

	result := ScanTLSVersion(Options{
		Host:    host,
		Port:    port,
		Timeout: time.Second,
	}, tls.VersionTLS13)

	if result.Supported {
		t.Fatal("Supported = true, want false")
	}
	if result.Status != ScanStatusUnsupported {
		t.Fatalf("Status = %q, want %q; error %q", result.Status, ScanStatusUnsupported, result.ErrorMessage)
	}
}

func TestScanTLSVersionTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		time.Sleep(500 * time.Millisecond)
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}

	result := ScanTLSVersion(Options{
		Host:    host,
		Port:    port,
		Timeout: 100 * time.Millisecond,
	}, tls.VersionTLS12)

	if result.Status != ScanStatusTimeout {
		t.Fatalf("Status = %q, want %q; error %q", result.Status, ScanStatusTimeout, result.ErrorMessage)
	}
	select {
	case <-accepted:
	default:
		t.Fatal("test listener did not accept a connection")
	}
}

func TestClassifyScanError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus string
	}{
		{
			name:       "unsupported protocol version",
			err:        errors.New("remote error: tls: protocol version not supported"),
			wantStatus: ScanStatusUnsupported,
		},
		{
			name:       "no supported versions",
			err:        errors.New("tls: no supported versions satisfy MinVersion and MaxVersion"),
			wantStatus: ScanStatusUnsupported,
		},
		{
			name:       "generic handshake failure",
			err:        errors.New("remote error: tls: handshake failure"),
			wantStatus: ScanStatusHandshake,
		},
		{
			name:       "network error",
			err:        errors.New("connect: connection refused"),
			wantStatus: ScanStatusNetworkError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, message := classifyScanError(tt.err)
			if status != tt.wantStatus {
				t.Fatalf("status = %q, want %q", status, tt.wantStatus)
			}
			if message == "" {
				t.Fatal("message should preserve the original error")
			}
		})
	}
}

func TestProbeCipherSuitesTLS13MarksObservedOnly(t *testing.T) {
	server, host, port := newLocalTLSServer(t, tls.VersionTLS13, tls.VersionTLS13)
	defer server.Close()

	result := ProbeCipherSuitesForVersion(Options{
		Host:       host,
		Port:       port,
		Timeout:    time.Second,
		SkipVerify: true,
	}, tls.VersionTLS13)

	if result.Discovery != CipherDiscoveryObserved {
		t.Fatalf("Discovery = %q, want %q", result.Discovery, CipherDiscoveryObserved)
	}
	if !result.ObservedOnly {
		t.Fatal("ObservedOnly = false, want true")
	}
	if result.Attempts != 10 {
		t.Fatalf("Attempts = %d, want 10", result.Attempts)
	}
	if len(result.Warnings) == 0 {
		t.Fatal("Warnings should explain TLS 1.3 observation semantics")
	}
}

func newLocalTLSServer(t *testing.T, minVersion, maxVersion uint16) (*httptest.Server, string, string) {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{
		MinVersion: minVersion,
		MaxVersion: maxVersion,
	}
	server.StartTLS()

	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		server.Close()
		t.Fatalf("split server address: %v", err)
	}
	return server, host, port
}
