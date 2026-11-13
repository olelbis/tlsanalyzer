package tlsprobe

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// legacyConfServer starts a crypto/tls server restricted to the given protocol
// range and cipher suites, and returns its address.
func legacyConfServer(t *testing.T, cert tls.Certificate, minVersion, maxVersion uint16, cipherSuites []uint16) string {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion,
		MaxVersion:   maxVersion,
		CipherSuites: cipherSuites,
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

func probeLegacy(t *testing.T, address string, version, cipherSuite uint16) Result {
	t.Helper()
	result, err := ProbeLegacyCipherSuite(context.Background(), Options{
		Address:    address,
		ServerName: "localhost",
		Timeout:    2 * time.Second,
	}, version, cipherSuite)
	if err != nil {
		t.Fatalf("ProbeLegacyCipherSuite(0x%04x) error = %v", cipherSuite, err)
	}
	return result
}

func TestLegacyCipherSuiteCatalogIsConsistent(t *testing.T) {
	ids := make(map[uint16]bool)
	names := make(map[string]bool)
	for _, suite := range LegacyCipherSuites() {
		if ids[suite.ID] {
			t.Errorf("duplicate cipher suite ID 0x%04x", suite.ID)
		}
		if names[suite.Name] {
			t.Errorf("duplicate cipher suite name %s", suite.Name)
		}
		ids[suite.ID] = true
		names[suite.Name] = true

		if suite.MinVersion != tls.VersionTLS10 && suite.MinVersion != tls.VersionTLS12 {
			t.Errorf("%s MinVersion = 0x%04x, want TLS 1.0 or TLS 1.2", suite.Name, suite.MinVersion)
		}
		if suite.ID>>8 == 0x13 {
			t.Errorf("%s is a TLS 1.3 cipher suite and does not belong to the legacy catalog", suite.Name)
		}
		// Suites crypto/tls knows must keep its spelling, so negotiated and
		// raw-probed evidence never disagree on a name.
		if goName := tls.CipherSuiteName(suite.ID); !strings.HasPrefix(goName, "0x") && goName != suite.Name {
			t.Errorf("0x%04x name = %s, crypto/tls calls it %s", suite.ID, suite.Name, goName)
		}
		// AEAD and SHA-2 MAC suites only exist from TLS 1.2 on.
		tls12Only := strings.Contains(suite.Name, "_GCM_") || strings.Contains(suite.Name, "_CCM") ||
			strings.Contains(suite.Name, "CHACHA20") || strings.HasSuffix(suite.Name, "_SHA256") || strings.HasSuffix(suite.Name, "_SHA384")
		if tls12Only != (suite.MinVersion == tls.VersionTLS12) {
			t.Errorf("%s MinVersion = 0x%04x does not match its construction", suite.Name, suite.MinVersion)
		}
	}

	// Every suite crypto/tls implements for TLS 1.0-1.2 must be probeable.
	for _, suite := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		if suite.ID>>8 == 0x13 {
			continue
		}
		if !ids[suite.ID] {
			t.Errorf("catalog is missing crypto/tls suite %s", suite.Name)
		}
	}
}

func TestLegacyCipherSuitesReturnsIndependentCopy(t *testing.T) {
	suites := LegacyCipherSuites()
	suites[0].Name = "mutated"
	if LegacyCipherSuites()[0].Name == "mutated" {
		t.Fatal("LegacyCipherSuites() must return a copy")
	}
}

func TestLegacyCipherSuitesForVersion(t *testing.T) {
	contains := func(ids []uint16, id uint16) bool {
		for _, candidate := range ids {
			if candidate == id {
				return true
			}
		}
		return false
	}

	tls10 := LegacyCipherSuitesForVersion(tls.VersionTLS10)
	tls12 := LegacyCipherSuitesForVersion(tls.VersionTLS12)
	if !contains(tls10, tls.TLS_RSA_WITH_RC4_128_SHA) {
		t.Fatal("TLS 1.0 list should include TLS_RSA_WITH_RC4_128_SHA")
	}
	if contains(tls10, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) {
		t.Fatal("TLS 1.0 list must not include AEAD suites")
	}
	if !contains(tls12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) || !contains(tls12, tls.TLS_RSA_WITH_RC4_128_SHA) {
		t.Fatal("TLS 1.2 list should include both AEAD and original suites")
	}
	if len(tls12) != len(LegacyCipherSuites()) {
		t.Fatalf("TLS 1.2 list has %d suites, want the whole catalog (%d)", len(tls12), len(LegacyCipherSuites()))
	}
	if got := LegacyCipherSuitesForVersion(tls.VersionTLS13); got != nil {
		t.Fatalf("TLS 1.3 list = %v, want nil", got)
	}
}

func TestCipherSuiteNameResolvesLegacyCatalog(t *testing.T) {
	tests := map[uint16]string{
		0x009e:                     "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", // not implemented by crypto/tls
		0x0004:                     "TLS_RSA_WITH_RC4_128_MD5",
		tls.TLS_AES_128_GCM_SHA256: "TLS_AES_128_GCM_SHA256",
		0xfafa:                     "0xFAFA",
	}
	for id, want := range tests {
		if got := CipherSuiteName(id); got != want {
			t.Errorf("CipherSuiteName(0x%04x) = %q, want %q", id, got, want)
		}
	}
}

func TestBuildLegacyClientHelloShape(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12} {
		record, err := buildLegacyClientHello(Options{ServerName: "example.test", ALPN: []string{"h2"}}, version, []uint16{0x009e})
		if err != nil {
			t.Fatalf("buildLegacyClientHello() error = %v", err)
		}

		if record[0] != 22 || binary.BigEndian.Uint16(record[1:3]) != tls.VersionTLS10 {
			t.Fatalf("record header = % x, want handshake record with version 0x0301", record[:3])
		}
		if int(binary.BigEndian.Uint16(record[3:5])) != len(record)-5 {
			t.Fatal("record length does not match payload")
		}
		if got := binary.BigEndian.Uint16(record[9:11]); got != version {
			t.Fatalf("client_version = 0x%04x, want 0x%04x", got, version)
		}
		offset := 5 + 4 + 2 + 32
		if record[offset] != 0 {
			t.Fatalf("session ID length = %d, want 0", record[offset])
		}
		offset++
		if got := binary.BigEndian.Uint16(record[offset : offset+2]); got != 2 {
			t.Fatalf("cipher_suites length = %d, want exactly one suite", got)
		}
		if got := binary.BigEndian.Uint16(record[offset+2 : offset+4]); got != 0x009e {
			t.Fatalf("offered cipher suite = 0x%04x, want 0x009e", got)
		}

		seen := make(map[uint16]bool)
		for _, extension := range confClientHelloExtensionTypes(t, record) {
			seen[extension] = true
		}
		for _, forbidden := range []uint16{extensionSupportedVersions, extensionKeyShare, extensionPSKModes} {
			if seen[forbidden] {
				t.Errorf("version 0x%04x ClientHello carries TLS 1.3 extension %d", version, forbidden)
			}
		}
		for _, required := range []uint16{extensionServerName, extensionSupportedGroups, extensionECPointFormats, extensionRenegotiationInfo, extensionALPN} {
			if !seen[required] {
				t.Errorf("version 0x%04x ClientHello is missing extension %d", version, required)
			}
		}
		if seen[extensionSignatureAlgorithms] != (version == tls.VersionTLS12) {
			t.Errorf("version 0x%04x signature_algorithms present = %t", version, seen[extensionSignatureAlgorithms])
		}
	}
}

func TestProbeLegacyCipherSuiteAgainstCryptoTLS(t *testing.T) {
	address := legacyConfServer(t, confCert(t, "rsa"), tls.VersionTLS12, tls.VersionTLS12, []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_RC4_128_SHA,
	})

	for _, suite := range []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_RC4_128_SHA} {
		result := probeLegacy(t, address, tls.VersionTLS12, suite)
		if result.Status != StatusSupported {
			t.Fatalf("%s Status = %q, want %q; alert %q error %q", result.Name, result.Status, StatusSupported, result.Alert, result.Error)
		}
		if result.EvidenceLevel != EvidenceClientHelloOnly || result.CompletedHandshake {
			t.Fatalf("%s evidence = %q completed = %t, want ClientHello-only", result.Name, result.EvidenceLevel, result.CompletedHandshake)
		}
	}

	// Suites the server does not enable, including ones crypto/tls cannot
	// offer as a client at all, are refused with handshake_failure.
	for _, suite := range []uint16{tls.TLS_RSA_WITH_AES_256_CBC_SHA, 0x009e, 0x0004, 0x0034} {
		result := probeLegacy(t, address, tls.VersionTLS12, suite)
		if result.Status != StatusAlert || result.AlertDescription != 40 {
			t.Fatalf("%s Status = %q alert %q, want fatal/handshake_failure", result.Name, result.Status, result.Alert)
		}
	}
}

func TestProbeLegacyCipherSuiteSupportsECDSACertificates(t *testing.T) {
	address := legacyConfServer(t, confCert(t, "p256"), tls.VersionTLS12, tls.VersionTLS12, []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	})

	result := probeLegacy(t, address, tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	if result.Status != StatusSupported {
		t.Fatalf("Status = %q, want %q; alert %q error %q", result.Status, StatusSupported, result.Alert, result.Error)
	}
	// An RSA-authenticated suite cannot be served with an ECDSA certificate.
	result = probeLegacy(t, address, tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	if result.Status != StatusAlert {
		t.Fatalf("RSA suite Status = %q, want %q", result.Status, StatusAlert)
	}
}

func TestProbeLegacyCipherSuiteEveryLegacyVersion(t *testing.T) {
	address := legacyConfServer(t, confCert(t, "rsa"), tls.VersionTLS10, tls.VersionTLS12, []uint16{
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	})

	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12} {
		result := probeLegacy(t, address, version, tls.TLS_RSA_WITH_AES_128_CBC_SHA)
		if result.Status != StatusSupported {
			t.Fatalf("version 0x%04x Status = %q, want %q; alert %q error %q", version, result.Status, StatusSupported, result.Alert, result.Error)
		}
	}

	// An AEAD suite offered in a TLS 1.0 ClientHello cannot be negotiated.
	result := probeLegacy(t, address, tls.VersionTLS10, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	if result.Status == StatusSupported {
		t.Fatal("AEAD suite must not be reported as supported on TLS 1.0")
	}
}

func TestProbeLegacyCipherSuiteReportsVersionMismatch(t *testing.T) {
	// The server stops at TLS 1.1, so it answers a TLS 1.2 ClientHello with a
	// TLS 1.1 ServerHello: the suite works, but not on the probed version.
	address := legacyConfServer(t, confCert(t, "rsa"), tls.VersionTLS10, tls.VersionTLS11, []uint16{
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	})

	result := probeLegacy(t, address, tls.VersionTLS12, tls.TLS_RSA_WITH_AES_128_CBC_SHA)
	if result.Status != StatusRejected {
		t.Fatalf("Status = %q, want %q; alert %q error %q", result.Status, StatusRejected, result.Alert, result.Error)
	}
	if result.ErrorCode != ErrorCodeVersionMismatch {
		t.Fatalf("ErrorCode = %q, want %q", result.ErrorCode, ErrorCodeVersionMismatch)
	}
	if !strings.Contains(result.Error, "TLS 1.1") {
		t.Fatalf("Error = %q, want it to name the negotiated version", result.Error)
	}
}

func TestProbeLegacyCipherSuiteAgainstTLS13OnlyServer(t *testing.T) {
	address := confTLS13Server(t, confCert(t, "rsa"), nil)

	result := probeLegacy(t, address, tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	if result.Status != StatusAlert || result.AlertDescription != 70 {
		t.Fatalf("Status = %q alert %q, want fatal/protocol_version", result.Status, result.Alert)
	}
}

func TestProbeLegacyCipherSuiteSendsSNI(t *testing.T) {
	const expectedServerName = "service.example.test"
	seenServerName := make(chan string, 1)
	server := newTLS13TestServer(&tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			seenServerName <- hello.ServerName
			return nil, nil
		},
	})
	defer server.Close()

	result, err := ProbeLegacyCipherSuite(context.Background(), Options{
		Address:    server.Listener.Addr().String(),
		ServerName: expectedServerName,
		Timeout:    time.Second,
	}, tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("ProbeLegacyCipherSuite() error = %v", err)
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

func TestProbeLegacyCipherSuiteFixtureSuiteUnknownToCryptoTLS(t *testing.T) {
	// crypto/tls has no DHE implementation; the fixture stands in for a server
	// that selects TLS_DHE_RSA_WITH_AES_128_GCM_SHA256.
	address, closeServer := newServerHelloFixtureServer(t, 0x009e)
	defer closeServer()

	result, err := ProbeLegacyCipherSuite(context.Background(), Options{Address: address, Timeout: time.Second}, tls.VersionTLS12, 0x009e)
	if err != nil {
		t.Fatalf("ProbeLegacyCipherSuite() error = %v", err)
	}
	if result.Status != StatusSupported {
		t.Fatalf("Status = %q, want %q; error %q", result.Status, StatusSupported, result.Error)
	}
	if result.Name != "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Fatalf("Name = %q, want TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", result.Name)
	}
}

func TestProbeLegacyCipherSuiteFixtureRejectedCipher(t *testing.T) {
	address, closeServer := newServerHelloFixtureServer(t, tls.TLS_RSA_WITH_AES_128_CBC_SHA)
	defer closeServer()

	result, err := ProbeLegacyCipherSuite(context.Background(), Options{Address: address, Timeout: time.Second}, tls.VersionTLS12, 0x009e)
	if err != nil {
		t.Fatalf("ProbeLegacyCipherSuite() error = %v", err)
	}
	if result.Status != StatusRejected || result.ErrorCode != ErrorCodeRejectedCipher {
		t.Fatalf("Status = %q ErrorCode = %q, want rejected/%s", result.Status, result.ErrorCode, ErrorCodeRejectedCipher)
	}
}

func TestProbeLegacyCipherSuiteReportsClosedConnection(t *testing.T) {
	address, closeServer := newCloseOnlyFixtureServer(t)
	defer closeServer()

	result, err := ProbeLegacyCipherSuite(context.Background(), Options{Address: address, Timeout: time.Second}, tls.VersionTLS12, 0x009e)
	if err != nil {
		t.Fatalf("ProbeLegacyCipherSuite() error = %v", err)
	}
	if result.Status != StatusClosed {
		t.Fatalf("Status = %q, want %q", result.Status, StatusClosed)
	}
}

func TestProbeLegacyCipherSuiteRejectsNonLegacyVersion(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS13, 0x0300, 0} {
		// Port 1 is never dialed: the configuration error comes first.
		_, err := ProbeLegacyCipherSuite(context.Background(), Options{Address: "127.0.0.1:1"}, version, 0x009e)
		var configErr *ConfigError
		if !errors.As(err, &configErr) || configErr.Field != "version" {
			t.Fatalf("version 0x%04x error = %v, want ConfigError for field version", version, err)
		}
		if _, err := ProbeLegacyCipherSuites(context.Background(), Options{Address: "127.0.0.1:1"}, version, []uint16{0x009e}); err == nil {
			t.Fatalf("ProbeLegacyCipherSuites(version 0x%04x) error = nil, want ConfigError", version)
		}
	}
}

func TestProbeLegacyCipherSuitesReturnsOneResultPerCipher(t *testing.T) {
	address := legacyConfServer(t, confCert(t, "rsa"), tls.VersionTLS12, tls.VersionTLS12, []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	})
	suites := []uint16{0x009e, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_RC4_128_SHA}

	results, err := ProbeLegacyCipherSuites(context.Background(), Options{Address: address, Timeout: 2 * time.Second}, tls.VersionTLS12, suites)
	if err != nil {
		t.Fatalf("ProbeLegacyCipherSuites() error = %v", err)
	}
	if len(results) != len(suites) {
		t.Fatalf("len(results) = %d, want %d", len(results), len(suites))
	}
	for i, result := range results {
		if result.CipherSuite != suites[i] {
			t.Fatalf("results[%d].CipherSuite = 0x%04x, want 0x%04x", i, result.CipherSuite, suites[i])
		}
	}
	summary := Summarize(results)
	if summary.Supported != 1 || summary.Alerts != 2 {
		t.Fatalf("summary = %+v, want 1 supported and 2 alerts", summary)
	}
}

func TestProbeLegacyCipherSuitesStopsWhenContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := ProbeLegacyCipherSuites(ctx, Options{Address: "127.0.0.1:1", Timeout: time.Second}, tls.VersionTLS12, []uint16{0x009e})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if len(results) != 0 {
		t.Fatalf("len(results) = %d, want 0", len(results))
	}
}

func shortenLegacyRetryPause(t *testing.T) {
	t.Helper()
	previous := legacyRetryPause
	legacyRetryPause = 10 * time.Millisecond
	t.Cleanup(func() { legacyRetryPause = previous })
}

func supportedIDs(enumeration LegacyEnumeration) map[uint16]bool {
	ids := make(map[uint16]bool)
	for _, result := range enumeration.Supported {
		ids[result.CipherSuite] = true
	}
	return ids
}

// legacyHoldingProxy forwards connections to backend, except the ones whose
// arrival order is listed in hold: those are accepted and never answered.
func legacyHoldingProxy(t *testing.T, backend string, hold map[int]bool) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var held []net.Conn
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range held {
			conn.Close()
		}
	})
	go func() {
		for n := 0; ; n++ {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if hold[n] {
				mu.Lock()
				held = append(held, conn)
				mu.Unlock()
				continue
			}
			go func() {
				defer conn.Close()
				upstream, err := net.Dial("tcp", backend)
				if err != nil {
					return
				}
				defer upstream.Close()
				go func() { _, _ = io.Copy(upstream, conn) }()
				_, _ = io.Copy(conn, upstream)
			}()
		}
	}()
	return listener.Addr().String()
}

func TestEnumerateLegacyCipherSuitesAgainstCryptoTLS(t *testing.T) {
	enabled := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_RC4_128_SHA,
	}
	address := legacyConfServer(t, confCert(t, "rsa"), tls.VersionTLS12, tls.VersionTLS12, enabled)
	catalog := LegacyCipherSuitesForVersion(tls.VersionTLS12)

	enumeration, err := EnumerateLegacyCipherSuites(context.Background(), Options{
		Address:    address,
		ServerName: "localhost",
		Timeout:    2 * time.Second,
	}, tls.VersionTLS12, catalog)
	if err != nil {
		t.Fatalf("EnumerateLegacyCipherSuites() error = %v", err)
	}

	if !enumeration.Complete || len(enumeration.Unresolved) != 0 {
		t.Fatalf("Complete = %t Unresolved = %d, want a complete enumeration; last %+v", enumeration.Complete, len(enumeration.Unresolved), enumeration.Last)
	}
	found := supportedIDs(enumeration)
	if len(found) != len(enabled) {
		t.Fatalf("found %d suites (%+v), want %d", len(found), enumeration.Supported, len(enabled))
	}
	for _, id := range enabled {
		if !found[id] {
			t.Errorf("enumeration missed %s", CipherSuiteName(id))
		}
	}
	// One connection per supported suite plus the refusal that ends the
	// enumeration, instead of one connection per catalog suite.
	if enumeration.Connections != len(enabled)+1 {
		t.Fatalf("Connections = %d, want %d for a catalog of %d suites", enumeration.Connections, len(enabled)+1, len(catalog))
	}
	if enumeration.Last.Status != StatusAlert {
		t.Fatalf("Last.Status = %q, want %q", enumeration.Last.Status, StatusAlert)
	}
	for _, result := range enumeration.Supported {
		if result.Status != StatusSupported || result.Name != CipherSuiteName(result.CipherSuite) || result.CompletedHandshake {
			t.Errorf("unexpected supported result %+v", result)
		}
	}
}

func TestEnumerateLegacyCipherSuitesOnTLS10(t *testing.T) {
	address := legacyConfServer(t, confCert(t, "rsa"), tls.VersionTLS10, tls.VersionTLS12, []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	})

	enumeration, err := EnumerateLegacyCipherSuites(context.Background(), Options{Address: address, Timeout: 2 * time.Second},
		tls.VersionTLS10, LegacyCipherSuitesForVersion(tls.VersionTLS10))
	if err != nil {
		t.Fatalf("EnumerateLegacyCipherSuites() error = %v", err)
	}
	found := supportedIDs(enumeration)
	if !enumeration.Complete || len(found) != 2 || !found[tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA] || !found[tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA] {
		t.Fatalf("TLS 1.0 enumeration = %+v (complete %t), want the two non-AEAD suites", enumeration.Supported, enumeration.Complete)
	}
}

func TestEnumerateLegacyCipherSuitesIgnoresDuplicates(t *testing.T) {
	address := legacyConfServer(t, confCert(t, "rsa"), tls.VersionTLS12, tls.VersionTLS12, []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA})

	enumeration, err := EnumerateLegacyCipherSuites(context.Background(), Options{Address: address, Timeout: 2 * time.Second}, tls.VersionTLS12,
		[]uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_128_CBC_SHA})
	if err != nil {
		t.Fatalf("EnumerateLegacyCipherSuites() error = %v", err)
	}
	// The only offered suite is supported, so no refusal is needed to finish.
	if !enumeration.Complete || len(enumeration.Supported) != 1 || enumeration.Connections != 1 {
		t.Fatalf("enumeration = %+v, want one supported suite in one connection", enumeration)
	}
}

func TestEnumerateLegacyCipherSuitesRetriesUnansweredClientHello(t *testing.T) {
	shortenLegacyRetryPause(t)
	enabled := []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_RC4_128_SHA}
	backend := legacyConfServer(t, confCert(t, "rsa"), tls.VersionTLS12, tls.VersionTLS12, enabled)
	// The first and the third ClientHello are dropped.
	address := legacyHoldingProxy(t, backend, map[int]bool{0: true, 2: true})

	enumeration, err := EnumerateLegacyCipherSuites(context.Background(), Options{Address: address, Timeout: 200 * time.Millisecond},
		tls.VersionTLS12, LegacyCipherSuitesForVersion(tls.VersionTLS12))
	if err != nil {
		t.Fatalf("EnumerateLegacyCipherSuites() error = %v", err)
	}
	if !enumeration.Complete || len(enumeration.Supported) != len(enabled) {
		t.Fatalf("enumeration = %+v, want both suites despite two dropped probes", enumeration)
	}
	if enumeration.Connections != len(enabled)+1+2 {
		t.Fatalf("Connections = %d, want %d (two of them repeated)", enumeration.Connections, len(enabled)+3)
	}
}

func TestEnumerateLegacyCipherSuitesGivesUpOnSilentServer(t *testing.T) {
	shortenLegacyRetryPause(t)
	// Every connection is held open and never answered.
	hold := make(map[int]bool)
	for n := 0; n < 16; n++ {
		hold[n] = true
	}
	address := legacyHoldingProxy(t, "127.0.0.1:1", hold)
	catalog := LegacyCipherSuitesForVersion(tls.VersionTLS12)
	const timeout = 100 * time.Millisecond

	start := time.Now()
	enumeration, err := EnumerateLegacyCipherSuites(context.Background(), Options{Address: address, Timeout: timeout}, tls.VersionTLS12, catalog)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("EnumerateLegacyCipherSuites() error = %v", err)
	}

	if enumeration.Complete {
		t.Fatal("Complete = true for a server that never answered")
	}
	if len(enumeration.Supported) != 0 || len(enumeration.Unresolved) != len(catalog) {
		t.Fatalf("Supported = %d Unresolved = %d, want 0 and %d", len(enumeration.Supported), len(enumeration.Unresolved), len(catalog))
	}
	if enumeration.Connections != 1+legacyEnumerationRetries || enumeration.Last.Status != StatusTimeout {
		t.Fatalf("Connections = %d Last.Status = %q, want %d and timeout", enumeration.Connections, enumeration.Last.Status, 1+legacyEnumerationRetries)
	}
	// The cost is bounded by the retries, not by the size of the catalog.
	if limit := time.Duration(2+legacyEnumerationRetries) * timeout; elapsed > limit {
		t.Fatalf("enumeration took %s, want less than %s", elapsed, limit)
	}
}

func TestEnumerateLegacyCipherSuitesAcceptsClosedConnectionAsRefusal(t *testing.T) {
	shortenLegacyRetryPause(t)
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
			_, _ = readTLSRecord(conn)
			conn.Close()
		}
	}()

	enumeration, err := EnumerateLegacyCipherSuites(context.Background(), Options{Address: listener.Addr().String(), Timeout: time.Second},
		tls.VersionTLS12, []uint16{0x009e, 0x0004})
	if err != nil {
		t.Fatalf("EnumerateLegacyCipherSuites() error = %v", err)
	}
	// Some stacks refuse a ClientHello by closing the connection instead of
	// sending an alert; once that repeats it is taken as the answer.
	if !enumeration.Complete || len(enumeration.Supported) != 0 || enumeration.Last.Status != StatusClosed {
		t.Fatalf("enumeration = %+v, want a complete enumeration ended by a closed connection", enumeration)
	}
}

func TestEnumerateLegacyCipherSuitesDistrustsUnofferedSelection(t *testing.T) {
	address, closeServer := newServerHelloFixtureServer(t, tls.TLS_RSA_WITH_AES_128_CBC_SHA)
	defer closeServer()

	enumeration, err := EnumerateLegacyCipherSuites(context.Background(), Options{Address: address, Timeout: time.Second}, tls.VersionTLS12, []uint16{0x009e, 0x0004})
	if err != nil {
		t.Fatalf("EnumerateLegacyCipherSuites() error = %v", err)
	}
	if enumeration.Complete || len(enumeration.Unresolved) != 2 || enumeration.Last.ErrorCode != ErrorCodeRejectedCipher {
		t.Fatalf("enumeration = %+v, want it to stop unresolved on a suite that was not offered", enumeration)
	}
}

func TestEnumerateLegacyCipherSuitesRejectsInvalidInput(t *testing.T) {
	_, err := EnumerateLegacyCipherSuites(context.Background(), Options{Address: "127.0.0.1:1"}, tls.VersionTLS13, []uint16{0x009e})
	var configErr *ConfigError
	if !errors.As(err, &configErr) || configErr.Field != "version" {
		t.Fatalf("error = %v, want ConfigError for field version", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	enumeration, err := EnumerateLegacyCipherSuites(ctx, Options{Address: "127.0.0.1:1"}, tls.VersionTLS12, []uint16{0x009e})
	if !errors.Is(err, context.Canceled) || enumeration.Complete || len(enumeration.Unresolved) != 1 {
		t.Fatalf("enumeration = %+v error = %v, want an unresolved enumeration and context.Canceled", enumeration, err)
	}

	enumeration, err = EnumerateLegacyCipherSuites(context.Background(), Options{Address: "127.0.0.1:1"}, tls.VersionTLS12, nil)
	if err != nil || !enumeration.Complete || enumeration.Connections != 0 {
		t.Fatalf("empty enumeration = %+v error = %v, want a complete no-op", enumeration, err)
	}
}

func TestBuildLegacyClientHelloPadsAwkwardLengths(t *testing.T) {
	handshakeLength := func(record []byte) int { return len(record) - 5 }
	hasPadding := func(record []byte) bool {
		for _, extension := range confClientHelloExtensionTypes(t, record) {
			if extension == extensionPadding {
				return true
			}
		}
		return false
	}

	small, err := buildLegacyClientHello(Options{ServerName: "example.test"}, tls.VersionTLS12, []uint16{0x009e})
	if err != nil {
		t.Fatalf("buildLegacyClientHello() error = %v", err)
	}
	if handshakeLength(small) >= 256 || hasPadding(small) {
		t.Fatalf("single-suite ClientHello is %d bytes with padding = %t, want a short unpadded message", handshakeLength(small), hasPadding(small))
	}

	// The whole catalog lands in the 256-511 byte range that needs padding.
	full, err := buildLegacyClientHello(Options{ServerName: "example.test"}, tls.VersionTLS12, LegacyCipherSuitesForVersion(tls.VersionTLS12))
	if err != nil {
		t.Fatalf("buildLegacyClientHello() error = %v", err)
	}
	if handshakeLength(full) != 512 || !hasPadding(full) {
		t.Fatalf("catalog ClientHello is %d bytes with padding = %t, want it padded to 512", handshakeLength(full), hasPadding(full))
	}

	if _, err := buildLegacyClientHello(Options{}, tls.VersionTLS12, nil); err == nil {
		t.Fatal("buildLegacyClientHello() with no cipher suite should fail")
	}
}

func TestSelectLegacyCipherSuiteReportsServerChoice(t *testing.T) {
	address := legacyConfServer(t, confCert(t, "rsa"), tls.VersionTLS12, tls.VersionTLS12, []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
	})
	opts := Options{Address: address, ServerName: "localhost", Timeout: 2 * time.Second}

	// Only one of the offered suites is enabled: the server must pick it.
	result, err := SelectLegacyCipherSuite(context.Background(), opts, tls.VersionTLS12,
		[]uint16{0x009e, tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_RC4_128_SHA})
	if err != nil {
		t.Fatalf("SelectLegacyCipherSuite() error = %v", err)
	}
	if result.Status != StatusSupported || result.CipherSuite != tls.TLS_RSA_WITH_RC4_128_SHA || result.Name != "TLS_RSA_WITH_RC4_128_SHA" {
		t.Fatalf("result = %q 0x%04x %s, want supported TLS_RSA_WITH_RC4_128_SHA", result.Status, result.CipherSuite, result.Name)
	}

	// None of the offered suites is enabled.
	result, err = SelectLegacyCipherSuite(context.Background(), opts, tls.VersionTLS12, []uint16{0x009e, tls.TLS_RSA_WITH_AES_128_CBC_SHA})
	if err != nil {
		t.Fatalf("SelectLegacyCipherSuite() error = %v", err)
	}
	if result.Status != StatusAlert {
		t.Fatalf("Status = %q, want %q", result.Status, StatusAlert)
	}

	if _, err := SelectLegacyCipherSuite(context.Background(), opts, tls.VersionTLS12, nil); err == nil {
		t.Fatal("SelectLegacyCipherSuite() with no suites should be a configuration error")
	}
}
