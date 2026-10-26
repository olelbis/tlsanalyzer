package tlsprobe

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// These tests run the probe against a real crypto/tls server instead of a
// hand-written fixture, so they catch protocol-conformance bugs that a fixture
// built from the same assumptions cannot.

func confCert(t *testing.T, kind string) tls.Certificate {
	t.Helper()

	var key crypto.Signer
	var err error
	switch kind {
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case "p256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p521":
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatalf("unknown certificate kind %q", kind)
	}
	if err != nil {
		t.Fatalf("generate %s key: %v", kind, err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create %s certificate: %v", kind, err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// confTLS13Server starts a TLS 1.3 crypto/tls server and returns its address.
func confTLS13Server(t *testing.T, cert tls.Certificate, curves []tls.CurveID) string {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: curves,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()
	return listener.Addr().String()
}

// confRecorder records every write the probe performs on its connection.
type confRecorder struct {
	mu     sync.Mutex
	writes [][]byte
}

func (r *confRecorder) dial(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &confRecordingConn{Conn: conn, recorder: r}, nil
}

func (r *confRecorder) snapshot() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.writes...)
}

type confRecordingConn struct {
	net.Conn
	recorder *confRecorder
}

func (c *confRecordingConn) Write(b []byte) (int, error) {
	c.recorder.mu.Lock()
	c.recorder.writes = append(c.recorder.writes, append([]byte(nil), b...))
	c.recorder.mu.Unlock()
	return c.Conn.Write(b)
}

// confClientHelloExtensionTypes returns the extension types of a ClientHello record.
func confClientHelloExtensionTypes(t *testing.T, record []byte) []uint16 {
	t.Helper()

	// record header (5) + handshake header (4) + client_version (2) + random (32)
	offset := 5 + 4 + 2 + 32
	offset += 1 + int(record[offset])                                   // session_id
	offset += 2 + int(binary.BigEndian.Uint16(record[offset:offset+2])) // cipher_suites
	offset += 1 + int(record[offset])                                   // compression_methods
	extensionsLength := int(binary.BigEndian.Uint16(record[offset : offset+2]))
	offset += 2
	extensions := record[offset : offset+extensionsLength]

	var types []uint16
	for len(extensions) >= 4 {
		types = append(types, binary.BigEndian.Uint16(extensions[0:2]))
		length := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4+length:]
	}
	return types
}

func TestProbeTLS13CipherSuiteRetriesHelloRetryRequestAgainstCryptoTLS(t *testing.T) {
	// The probe offers an X25519 key share first; a server that only accepts
	// P-256 answers with a HelloRetryRequest.
	address := confTLS13Server(t, confCert(t, "p256"), []tls.CurveID{tls.CurveP256})

	recorder := &confRecorder{}
	result, err := ProbeTLS13CipherSuite(context.Background(), Options{
		Address:     address,
		ServerName:  "localhost",
		Timeout:     3 * time.Second,
		DialContext: recorder.dial,
	}, tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("ProbeTLS13CipherSuite() error = %v", err)
	}
	if !result.HelloRetryRequest || !result.HelloRetryRequestRetried {
		t.Fatalf("HelloRetryRequest = %t retried = %t, want true/true", result.HelloRetryRequest, result.HelloRetryRequestRetried)
	}
	if result.Status != StatusSupported {
		t.Fatalf("Status = %q, want %q; alert %q error %q", result.Status, StatusSupported, result.Alert, result.Error)
	}

	writes := recorder.snapshot()
	if len(writes) != 2 {
		t.Fatalf("probe wrote %d ClientHello records, want 2", len(writes))
	}
	first, second := writes[0], writes[1]
	if first[1] != 0x03 || first[2] != 0x01 {
		t.Errorf("initial ClientHello record version = %#02x%02x, want 0x0301", first[1], first[2])
	}
	// RFC 8446 section 5.1: the ClientHello after a HelloRetryRequest must use 0x0303.
	if second[1] != 0x03 || second[2] != 0x03 {
		t.Errorf("retry ClientHello record version = %#02x%02x, want 0x0303", second[1], second[2])
	}
	// RFC 8446 section 4.1.2: the retry must repeat random and session ID.
	if !bytes.Equal(first[11:43], second[11:43]) {
		t.Error("retry ClientHello changed ClientHello.random")
	}
	if !bytes.Equal(first[44:76], second[44:76]) {
		t.Error("retry ClientHello changed the legacy session ID")
	}
}

func TestProbeTLS13CipherSuiteSupportsCommonCertificateKeyTypes(t *testing.T) {
	// A server without a usable signature scheme aborts with handshake_failure
	// before ServerHello, which used to hide TLS 1.3 support for ECDSA P-384,
	// P-521 and Ed25519 certificates.
	for _, kind := range []string{"rsa", "p256", "p384", "p521", "ed25519"} {
		t.Run(kind, func(t *testing.T) {
			address := confTLS13Server(t, confCert(t, kind), nil)

			result, err := ProbeTLS13CipherSuite(context.Background(), Options{
				Address:    address,
				ServerName: "localhost",
				Timeout:    3 * time.Second,
			}, tls.TLS_AES_128_GCM_SHA256)
			if err != nil {
				t.Fatalf("ProbeTLS13CipherSuite() error = %v", err)
			}
			if result.Status != StatusSupported {
				t.Fatalf("Status = %q, want %q; alert %q error %q", result.Status, StatusSupported, result.Alert, result.Error)
			}
		})
	}
}

func TestProbeTLS13CipherSuiteSNI(t *testing.T) {
	address := confTLS13Server(t, confCert(t, "p256"), nil)

	for _, tc := range []struct {
		name       string
		serverName string
		wantSNI    bool
	}{
		{name: "hostname", serverName: "localhost", wantSNI: true},
		{name: "ipv4 literal", serverName: "127.0.0.1", wantSNI: false},
		{name: "ipv6 literal", serverName: "::1", wantSNI: false},
		{name: "bracketed ipv6 literal", serverName: "[::1]", wantSNI: false},
		{name: "empty", serverName: "", wantSNI: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &confRecorder{}
			if _, err := ProbeTLS13CipherSuite(context.Background(), Options{
				Address:     address,
				ServerName:  tc.serverName,
				Timeout:     3 * time.Second,
				DialContext: recorder.dial,
			}, tls.TLS_AES_128_GCM_SHA256); err != nil {
				t.Fatalf("ProbeTLS13CipherSuite() error = %v", err)
			}

			writes := recorder.snapshot()
			if len(writes) == 0 {
				t.Fatal("probe wrote nothing")
			}
			hasSNI := false
			for _, extensionType := range confClientHelloExtensionTypes(t, writes[0]) {
				if extensionType == extensionServerName {
					hasSNI = true
				}
			}
			if hasSNI != tc.wantSNI {
				t.Fatalf("server_name extension present = %t, want %t", hasSNI, tc.wantSNI)
			}
		})
	}
}

func TestProbeTLS13CipherSuiteHonoursContext(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var held []net.Conn
	var heldMu sync.Mutex
	t.Cleanup(func() {
		listener.Close()
		heldMu.Lock()
		defer heldMu.Unlock()
		for _, conn := range held {
			conn.Close()
		}
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			heldMu.Lock()
			held = append(held, conn) // accept, then stay silent
			heldMu.Unlock()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	result, err := ProbeTLS13CipherSuite(ctx, Options{
		Address:    listener.Addr().String(),
		ServerName: "localhost",
		Timeout:    10 * time.Second,
	}, tls.TLS_AES_128_GCM_SHA256)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("ProbeTLS13CipherSuite() error = %v", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("probe took %v, want it to stop shortly after the 150ms context deadline", elapsed)
	}
	if result.Status != StatusTimeout {
		t.Fatalf("Status = %q, want %q", result.Status, StatusTimeout)
	}
}

func TestProbeTLS13CipherSuitesStopsWhenContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := ProbeTLS13CipherSuites(ctx, Options{Address: "127.0.0.1:9"}, SupportedTLS13CipherSuites())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if len(results) != 0 {
		t.Fatalf("results = %d, want none because the context had already ended", len(results))
	}
}

func TestIsIPLiteral(t *testing.T) {
	for name, want := range map[string]bool{
		"127.0.0.1":    true,
		"::1":          true,
		"[::1]":        true,
		"fe80::1%eth0": true,
		"localhost":    false,
		"example.com":  false,
		"1.2.3":        false,
		"":             false,
	} {
		if got := isIPLiteral(name); got != want {
			t.Errorf("isIPLiteral(%q) = %t, want %t", name, got, want)
		}
	}
}
