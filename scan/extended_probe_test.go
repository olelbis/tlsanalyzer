package scan

import (
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olelbis/tlsanalyzer/tlsprobe"
	"github.com/olelbis/tlsanalyzer/utils"
)

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func probeStatusFor(statuses []CipherProbeStatus, cipherSuite string) (CipherProbeStatus, bool) {
	for _, status := range statuses {
		if status.CipherSuite == cipherSuite {
			return status, true
		}
	}
	return CipherProbeStatus{}, false
}

// The endpoint enables two suites that the full-handshake probe never offers
// (utils.AllCipherSuites leaves them out). Before the raw enumeration they
// were invisible, so a weak-cipher policy gate passed on this server.
func TestProbeCipherSuitesFindsSuitesOutsideFullHandshakeSet(t *testing.T) {
	server, host, port := newLocalTLSServerWithConfig(t, &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		},
	})
	defer server.Close()

	result := ProbeCipherSuitesForVersion(Options{
		Host:       host,
		Port:       port,
		Timeout:    2 * time.Second,
		SkipVerify: true,
	}, tls.VersionTLS12)

	if result.Discovery != CipherDiscoveryProbed {
		t.Fatalf("Discovery = %q, want %q", result.Discovery, CipherDiscoveryProbed)
	}
	if result.Incomplete {
		t.Fatalf("Incomplete = true, warnings %v", result.Warnings)
	}
	for _, want := range []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	} {
		if !containsString(result.CipherSuites, want) {
			t.Errorf("CipherSuites = %v, want it to include %s", result.CipherSuites, want)
		}
	}
	if len(result.CipherSuites) != 3 {
		t.Errorf("CipherSuites = %v, want exactly the 3 suites the server enables", result.CipherSuites)
	}

	// Raw-only suites carry an explicit ClientHello-only evidence row; the
	// suite confirmed by a full handshake does not.
	for _, rawProbed := range []string{"TLS_RSA_WITH_RC4_128_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"} {
		status, ok := probeStatusFor(result.Statuses, rawProbed)
		if !ok {
			t.Fatalf("Statuses = %+v, want a row for %s", result.Statuses, rawProbed)
		}
		if status.Status != "supported" || status.Evidence != "clienthello-serverhello" {
			t.Errorf("%s status = %q evidence = %q, want supported/clienthello-serverhello", rawProbed, status.Status, status.Evidence)
		}
	}
	if _, ok := probeStatusFor(result.Statuses, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"); ok {
		t.Error("full-handshake suite must not get a raw probe row")
	}
	if len(result.Statuses) != 2 {
		t.Errorf("Statuses = %+v, want only the 2 raw-only suites", result.Statuses)
	}

	warned := false
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "TLS 1.2: 2 cipher suite(s)") && strings.Contains(warning, "ClientHello-only raw probes") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("Warnings = %v, want a note counting the raw-only suites", result.Warnings)
	}
}

// The scan must stay cheap for the endpoint: about one connection per
// supported suite, not one per catalog suite. Endpoints and firewalls that
// rate limit new connections drop probes otherwise.
func TestProbeCipherSuitesUsesFewConnections(t *testing.T) {
	enabled := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_RC4_128_SHA,
	}
	server, backendHost, backendPort := newLocalTLSServerWithConfig(t, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: enabled,
	})
	defer server.Close()

	var accepted atomic.Int32
	host, port := droppingProxy(t, net.JoinHostPort(backendHost, backendPort), nil, &accepted)

	result := ProbeCipherSuitesForVersion(Options{Host: host, Port: port, Timeout: 2 * time.Second, SkipVerify: true}, tls.VersionTLS12)

	if len(result.CipherSuites) != len(enabled) || result.Incomplete {
		t.Fatalf("CipherSuites = %v incomplete = %t, want the %d enabled suites", result.CipherSuites, result.Incomplete, len(enabled))
	}
	catalog := len(tlsprobe.LegacyCipherSuitesForVersion(tls.VersionTLS12))
	chunks := (catalog + legacyEnumerationChunk - 1) / legacyEnumerationChunk
	// One ClientHello per supported suite, one refusal per chunk, and one
	// full handshake for each of the 3 suites crypto/tls implements.
	want := len(enabled) + chunks + 3
	if got := int(accepted.Load()); got != want {
		t.Fatalf("the probe opened %d connections, want %d (catalog has %d suites)", got, want, catalog)
	}
	if result.Attempts != want {
		t.Fatalf("Attempts = %d, want %d", result.Attempts, want)
	}
}

func TestProbeCipherSuitesAddsNoRawEvidenceForCleanEndpoint(t *testing.T) {
	server, host, port := newLocalTLSServerWithConfig(t, &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	})
	defer server.Close()

	result := ProbeCipherSuitesForVersion(Options{
		Host:       host,
		Port:       port,
		Timeout:    2 * time.Second,
		SkipVerify: true,
	}, tls.VersionTLS12)

	if len(result.CipherSuites) != 2 {
		t.Fatalf("CipherSuites = %v, want the 2 suites the server enables", result.CipherSuites)
	}
	if len(result.Statuses) != 0 {
		t.Fatalf("Statuses = %+v, want none: refused suites are not reported", result.Statuses)
	}
	if len(result.Warnings) != 0 || result.Incomplete {
		t.Fatalf("Warnings = %v incomplete = %t, want a clean result", result.Warnings, result.Incomplete)
	}
}

func TestProbeCipherSuitesOnLegacyVersion(t *testing.T) {
	server, host, port := newLocalTLSServerWithConfig(t, &tls.Config{
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		},
	})
	defer server.Close()

	result := ProbeCipherSuitesForVersion(Options{
		Host:       host,
		Port:       port,
		Timeout:    2 * time.Second,
		SkipVerify: true,
	}, tls.VersionTLS10)

	if len(result.CipherSuites) != 2 || !containsString(result.CipherSuites, "TLS_ECDHE_RSA_WITH_RC4_128_SHA") {
		t.Fatalf("CipherSuites = %v, want both suites on TLS 1.0", result.CipherSuites)
	}
}

// A suite the scanner can detect but cannot classify would fail the
// weak-cipher gate as "unclassified" instead of with a meaningful severity.
func TestEveryProbeableLegacyCipherSuiteHasSeverity(t *testing.T) {
	for _, suite := range tlsprobe.LegacyCipherSuites() {
		if utils.CipherSuiteSeverity(suite.Name) == utils.CipherSeverityUnknown {
			t.Errorf("%s (0x%04x) has no severity", suite.Name, suite.ID)
		}
		if _, ok := utils.CipherClassificationForVersion(tls.VersionTLS12, suite.Name); !ok {
			t.Errorf("%s (0x%04x) has no display classification", suite.Name, suite.ID)
		}
	}
}

// Every suite the full-handshake probe can negotiate must be reachable by the
// enumeration, otherwise it would never be confirmed.
func TestLegacyCatalogCoversFullHandshakeSuites(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12} {
		catalog := make(map[uint16]bool)
		for _, id := range tlsprobe.LegacyCipherSuitesForVersion(version) {
			catalog[id] = true
		}
		for _, cs := range utils.AllCipherSuites {
			if cs.ID>>8 == 0x13 {
				continue
			}
			aead := strings.Contains(cs.Name, "_GCM_") || strings.Contains(cs.Name, "CHACHA20")
			if aead && version < tls.VersionTLS12 {
				continue
			}
			if !catalog[cs.ID] {
				t.Errorf("version 0x%04x catalog is missing %s", version, cs.Name)
			}
		}
	}
}

// silentServer accepts TCP connections and never answers, like an endpoint or
// a firewall that drops TLS probes.
func silentServer(t *testing.T) (host, port string) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()

	host, port, err = net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split address: %v", err)
	}
	return host, port
}

// An endpoint or firewall that drops every probe must cost a bounded amount
// of time, and the result must say that it proves nothing.
func TestProbeCipherSuitesReportsIncompleteWhenProbesAreDropped(t *testing.T) {
	host, port := silentServer(t)
	const timeout = 200 * time.Millisecond

	start := time.Now()
	result := ProbeCipherSuitesForVersion(Options{Host: host, Port: port, Timeout: timeout, SkipVerify: true}, tls.VersionTLS12)
	elapsed := time.Since(start)

	// Three enumeration attempts with two pauses, then two full-handshake passes.
	if limit := 5*timeout + 2*time.Second; elapsed > limit {
		t.Fatalf("probe took %s, want less than %s", elapsed, limit)
	}
	if len(result.CipherSuites) != 0 {
		t.Fatalf("CipherSuites = %v, want none", result.CipherSuites)
	}
	if !result.Incomplete {
		t.Fatal("Incomplete = false for an endpoint that never answered")
	}
	if len(result.Statuses) != 0 {
		t.Fatalf("Statuses = %+v, want no per-suite rows for unclassified suites", result.Statuses)
	}

	var sawEnumeration, sawFullHandshake bool
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "raw cipher enumeration could not finish (timeout") && strings.Contains(warning, "were not classified") {
			sawEnumeration = true
		}
		if strings.Contains(warning, "full-handshake cipher probes timed out twice") {
			sawFullHandshake = true
		}
	}
	if !sawEnumeration || !sawFullHandshake {
		t.Fatalf("Warnings = %v, want both the enumeration and the full-handshake warnings", result.Warnings)
	}
}

// droppingProxy forwards connections to backend but silently holds the ones
// whose arrival order is listed in drop, like a rate limiter that discards a
// few packets in a burst.
func droppingProxy(t *testing.T, backend string, drop map[int]bool, accepted *atomic.Int32) (host, port string) {
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
			if accepted != nil {
				accepted.Add(1)
			}
			if drop[n] {
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

	host, port, err = net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split address: %v", err)
	}
	return host, port
}

// A few dropped probes must not turn into missing cipher suites: both the
// enumeration and the full-handshake confirmation ask again.
func TestProbeCipherSuitesRetriesDroppedProbes(t *testing.T) {
	enabled := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	}
	server, backendHost, backendPort := newLocalTLSServerWithConfig(t, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: enabled,
	})
	defer server.Close()

	// Dropped by arrival order: two enumeration ClientHellos and, later, two
	// of the full-handshake confirmations.
	drop := map[int]bool{1: true, 5: true, 10: true, 12: true}
	host, port := droppingProxy(t, net.JoinHostPort(backendHost, backendPort), drop, nil)

	result := ProbeCipherSuitesForVersion(Options{Host: host, Port: port, Timeout: 300 * time.Millisecond, SkipVerify: true}, tls.VersionTLS12)

	if len(result.CipherSuites) != len(enabled) {
		t.Fatalf("CipherSuites = %v, want all %d suites the server enables; warnings %v", result.CipherSuites, len(enabled), result.Warnings)
	}
	if result.Incomplete {
		t.Fatalf("Incomplete = true after successful retries; warnings %v", result.Warnings)
	}
}

// If the enumeration is blind to the suites crypto/tls negotiates, its silence
// about legacy suites is not evidence either: fall back and say so.
func TestProbeCipherSuitesFallsBackWhenEnumerationSeesNothing(t *testing.T) {
	server, backendHost, backendPort := newLocalTLSServerWithConfig(t, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	})
	defer server.Close()

	// The first 4 connections are the 4 enumeration chunks: refuse them all
	// the way a middlebox would, by closing, including their retries.
	closeFirst := 4 * 3
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		for n := 0; ; n++ {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if n < closeFirst {
				conn.Close()
				continue
			}
			go func() {
				defer conn.Close()
				upstream, err := net.Dial("tcp", net.JoinHostPort(backendHost, backendPort))
				if err != nil {
					return
				}
				defer upstream.Close()
				go func() { _, _ = io.Copy(upstream, conn) }()
				_, _ = io.Copy(conn, upstream)
			}()
		}
	}()
	host, port, _ := net.SplitHostPort(listener.Addr().String())

	result := ProbeCipherSuitesForVersion(Options{Host: host, Port: port, Timeout: time.Second, SkipVerify: true}, tls.VersionTLS12)

	if len(result.CipherSuites) != 2 {
		t.Fatalf("CipherSuites = %v, want the 2 suites found by the full-handshake fallback; warnings %v", result.CipherSuites, result.Warnings)
	}
	if !result.Incomplete {
		t.Fatal("Incomplete = false although the enumeration saw nothing")
	}
	found := false
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "found none of the suites this endpoint negotiates") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Warnings = %v, want the blind-enumeration warning", result.Warnings)
	}
}
