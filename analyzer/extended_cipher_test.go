package analyzer

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/olelbis/tlsanalyzer/policy"
)

func cipherServer(t *testing.T, cipherSuites []uint16) (host, port string) {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: cipherSuites}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)

	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split server address: %v", err)
	}
	return host, port
}

// Regression test for the weak-cipher false negative: the endpoint negotiates
// a modern suite but also accepts RC4, which the full-handshake probe never
// offers. The gate must fail, and name the suite it found.
func TestWeakCipherGateSeesSuitesOutsideFullHandshakeSet(t *testing.T) {
	host, port := cipherServer(t, []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_RC4_128_SHA,
	})

	result, err := Run(scanRangeOptions(host, port, tls.VersionTLS12, policy.Config{FailOn: []string{policy.CheckWeakCipher}}), Hooks{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Policy.Passed {
		t.Fatal("weak-cipher gate passed on an endpoint that accepts RC4")
	}
	found := false
	for _, failure := range result.Policy.Failures {
		if failure.Check == policy.CheckWeakCipher && strings.Contains(failure.Message, "TLS_RSA_WITH_RC4_128_SHA") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Failures = %+v, want a weak-cipher failure naming TLS_RSA_WITH_RC4_128_SHA", result.Policy.Failures)
	}
}

func TestWeakCipherGateStillPassesOnCleanEndpoint(t *testing.T) {
	host, port := cipherServer(t, []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	})

	result, err := Run(scanRangeOptions(host, port, tls.VersionTLS12, policy.Config{FailOn: []string{policy.CheckWeakCipher}}), Hooks{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !result.Policy.Passed {
		t.Fatalf("weak-cipher gate failed on a clean endpoint: %+v", result.Policy.Failures)
	}
}
