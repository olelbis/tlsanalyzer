package tlsprobe

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbeTLS13CipherSuiteSupported(t *testing.T) {
	server := newTLS13TestServer(&tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	})
	defer server.Close()

	result, err := ProbeTLS13CipherSuite(context.Background(), Options{
		Address: server.Listener.Addr().String(),
		Timeout: time.Second,
	}, tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("ProbeTLS13CipherSuite() error = %v", err)
	}

	if result.Status != StatusSupported {
		t.Fatalf("Status = %q, want %q; alert %q error %q", result.Status, StatusSupported, result.Alert, result.Error)
	}
	if result.Name != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("Name = %q, want TLS_AES_128_GCM_SHA256", result.Name)
	}
}

func TestProbeTLS13CipherSuiteSendsSNI(t *testing.T) {
	const expectedServerName = "service.example.test"
	seenServerName := make(chan string, 1)
	server := newTLS13TestServer(&tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			seenServerName <- hello.ServerName
			return nil, nil
		},
	})
	defer server.Close()

	result, err := ProbeTLS13CipherSuite(context.Background(), Options{
		Address:    server.Listener.Addr().String(),
		ServerName: expectedServerName,
		Timeout:    time.Second,
	}, tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("ProbeTLS13CipherSuite() error = %v", err)
	}
	if result.Status != StatusSupported {
		t.Fatalf("Status = %q, want %q; alert %q error %q", result.Status, StatusSupported, result.Alert, result.Error)
	}

	select {
	case got := <-seenServerName:
		if got != expectedServerName {
			t.Fatalf("ServerName = %q, want %q", got, expectedServerName)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not observe ClientHello")
	}
}

func TestProbeTLS13CipherSuiteReportsAlert(t *testing.T) {
	server := newTLS13TestServer(&tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	})
	defer server.Close()

	result, err := ProbeTLS13CipherSuite(context.Background(), Options{
		Address: server.Listener.Addr().String(),
		Timeout: time.Second,
	}, tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("ProbeTLS13CipherSuite() error = %v", err)
	}

	if result.Status != StatusAlert {
		t.Fatalf("Status = %q, want %q; alert %q error %q", result.Status, StatusAlert, result.Alert, result.Error)
	}
	if result.Alert == "" {
		t.Fatal("Alert should describe the TLS alert")
	}
}

func TestProbeTLS13CipherSuitesReturnsOneResultPerCipher(t *testing.T) {
	server := newTLS13TestServer(&tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	})
	defer server.Close()

	results, err := ProbeTLS13CipherSuites(context.Background(), Options{
		Address: server.Listener.Addr().String(),
		Timeout: time.Second,
	}, []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384})
	if err != nil {
		t.Fatalf("ProbeTLS13CipherSuites() error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	for _, result := range results {
		if result.Status != StatusSupported {
			t.Fatalf("Status for %s = %q, want %q; alert %q error %q", result.Name, result.Status, StatusSupported, result.Alert, result.Error)
		}
	}
}

func newTLS13TestServer(config *tls.Config) *httptest.Server {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = config
	server.StartTLS()
	return server
}
