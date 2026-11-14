package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testTLSCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mail.example.test"},
		DNSNames:     []string{"mail.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// newSMTPTLSServer speaks just enough SMTP to upgrade with STARTTLS and then
// serves TLS 1.2 and 1.3. sessions counts the connections that reached the
// STARTTLS command.
func newSMTPTLSServer(t *testing.T, offerSTARTTLS bool) (host, port string, sessions *atomic.Int32) {
	t.Helper()
	cert := testTLSCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	sessions = &atomic.Int32{}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				r := bufio.NewReader(conn)
				_, _ = conn.Write([]byte("220 mail.example.test ESMTP\r\n"))
				if _, err := r.ReadString('\n'); err != nil {
					return
				}
				if !offerSTARTTLS {
					_, _ = conn.Write([]byte("250-mail.example.test\r\n250 SIZE 100\r\n"))
					return
				}
				_, _ = conn.Write([]byte("250-mail.example.test\r\n250-STARTTLS\r\n250 SIZE 100\r\n"))
				if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "STARTTLS") {
					return
				}
				sessions.Add(1)
				_, _ = conn.Write([]byte("220 Ready to start TLS\r\n"))
				server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
				if err := server.Handshake(); err != nil {
					return
				}
				_ = server.Close()
			}(conn)
		}
	}()
	host, port, err = net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split address: %v", err)
	}
	return host, port, sessions
}

func TestRunStartTLSScansEveryProbeThroughSMTP(t *testing.T) {
	host, port, sessions := newSMTPTLSServer(t, true)

	var stdout, stderr bytes.Buffer
	code := run([]string{"--host", host, "--port", port, "--starttls", "smtp", "--min-version", "1.2",
		"--skip-verify", "--force-ciphers", "--enum-groups", "--json", "--no-clear"}, &stdout, &stderr)
	if code != exitCodeOK {
		t.Fatalf("run() exit code = %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	var report struct {
		Results []struct {
			Version    string     `json:"version"`
			Supported  bool       `json:"supported"`
			Ciphers    []string   `json:"cipher_suites"`
			Discovery  string     `json:"cipher_discovery"`
			Groups     []struct{} `json:"key_exchange_groups"`
			Incomplete bool       `json:"key_exchange_groups_incomplete"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
	}
	if len(report.Results) != 2 {
		t.Fatalf("results = %d, want TLS 1.2 and 1.3", len(report.Results))
	}
	for _, r := range report.Results {
		if !r.Supported {
			t.Fatalf("%s should be supported through STARTTLS: %+v", r.Version, r)
		}
		if len(r.Ciphers) == 0 || r.Discovery == "negotiated" {
			t.Fatalf("%s cipher probing should have run through STARTTLS: %+v", r.Version, r)
		}
	}
	tls13 := report.Results[1]
	if len(tls13.Groups) == 0 || tls13.Incomplete {
		t.Fatalf("TLS 1.3 key exchange groups should be enumerated through STARTTLS: %+v", tls13)
	}
	// One session per scanned version, per probe and per group enumeration
	// step; far more than the single connection a plain scan would make.
	if got := sessions.Load(); got < 8 {
		t.Fatalf("server saw %d STARTTLS sessions, want every probe connection to upgrade", got)
	}
}

func TestRunStartTLSReportsServerWithoutSTARTTLS(t *testing.T) {
	host, port, sessions := newSMTPTLSServer(t, false)

	var stdout, stderr bytes.Buffer
	code := run([]string{"--host", host, "--port", port, "--starttls", "smtp", "--json", "--no-clear"}, &stdout, &stderr)
	if code != exitCodeInputRuntimeFailure {
		t.Fatalf("run() exit code = %d, want %d", code, exitCodeInputRuntimeFailure)
	}
	if !strings.Contains(stderr.String(), "starttls smtp: the server does not offer STARTTLS") {
		t.Fatalf("stderr does not explain the failure:\n%s", stderr.String())
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if sessions.Load() != 0 {
		t.Fatalf("no TLS handshake should have been attempted, saw %d sessions", sessions.Load())
	}
}

func TestRunRejectsUnknownStartTLSProtocol(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--host", "example.com", "--starttls", "ftp", "--json"}, &stdout, &stderr)
	if code != exitCodeInputRuntimeFailure {
		t.Fatalf("run() exit code = %d, want %d", code, exitCodeInputRuntimeFailure)
	}
	if !strings.Contains(stderr.String(), `invalid --starttls: unsupported STARTTLS protocol "ftp"`) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestStartTLSDefaultPorts(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"smtp", []string{"--host", "h", "--starttls", "smtp"}, "25"},
		{"imap", []string{"--host", "h", "--starttls", "imap"}, "143"},
		{"pop3", []string{"--host", "h", "--starttls", "pop3"}, "110"},
		{"explicit port wins", []string{"--host", "h", "--starttls", "smtp", "--port", "587"}, "587"},
		{"explicit 443 wins", []string{"--host", "h", "--starttls", "smtp", "--port", "443"}, "443"},
		{"no starttls keeps 443", []string{"--host", "h"}, "443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseCLIArgs(tt.args, &bytes.Buffer{})
			if err != nil {
				t.Fatalf("parseCLIArgs() = %v", err)
			}
			if cfg.port != tt.want {
				t.Fatalf("port = %q, want %q", cfg.port, tt.want)
			}
		})
	}
}

func TestStartTLSFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tlsanalyzer.json")
	content := `{
  "targets": {
    "mail": {"host": "mail.example.test", "starttls": "imap"},
    "submission": {"host": "mail.example.test", "port": "587", "starttls": "smtp"}
  }
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := parseCLIArgs([]string{"--config", path, "--target", "mail"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseCLIArgs() = %v", err)
	}
	if cfg.startTLS != "imap" || cfg.port != "143" {
		t.Fatalf("target mail: starttls=%q port=%q, want imap and 143", cfg.startTLS, cfg.port)
	}

	cfg, err = parseCLIArgs([]string{"--config", path, "--target", "submission"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseCLIArgs() = %v", err)
	}
	if cfg.startTLS != "smtp" || cfg.port != "587" {
		t.Fatalf("target submission: starttls=%q port=%q, want smtp and the configured 587", cfg.startTLS, cfg.port)
	}
}
