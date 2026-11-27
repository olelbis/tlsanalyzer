package tlsprobe

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func tls12Server(t *testing.T, curves ...tls.CurveID) string {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CurvePreferences: curves}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.Listener.Addr().String()
}

func TestECDHECurveCatalogIsConsistent(t *testing.T) {
	seenID := make(map[uint16]bool)
	seenName := make(map[string]bool)
	for _, curve := range ECDHECurves() {
		if seenID[curve.ID] || seenName[curve.Name] {
			t.Errorf("duplicate curve %d %q", curve.ID, curve.Name)
		}
		seenID[curve.ID], seenName[curve.Name] = true, true
		if curve.Name == "" || curve.Bits <= 0 {
			t.Errorf("curve %d has no name or size", curve.ID)
		}
	}
	for id := uint16(1); id <= 30; id++ {
		if !seenID[id] {
			t.Errorf("IANA elliptic curve %d is missing from the catalog", id)
		}
	}
	for id, want := range map[uint16]bool{1: true, 15: true, 19: true, 21: false, 23: false, 29: false} {
		curve, ok := LookupECDHECurve(id)
		if !ok || curve.Weak() != want {
			t.Errorf("LookupECDHECurve(%d) = %+v, %t; Weak() want %t", id, curve, ok, want)
		}
	}
	// Curves that are also TLS 1.3 groups must use the same name.
	for _, curve := range ECDHECurves() {
		if name, ok := catalogGroupName(curve.ID); ok && name != curve.Name {
			t.Errorf("curve %d is %q here and %q in the group catalog", curve.ID, curve.Name, name)
		}
	}
	if len(ECDHECurveIDs()) != len(ECDHECurves()) {
		t.Error("ECDHECurveIDs and ECDHECurves disagree")
	}
	if suites := ecdheCipherSuites(); len(suites) == 0 {
		t.Fatal("no ECDHE cipher suite to offer")
	} else {
		for _, id := range suites {
			if !strings.HasPrefix(CipherSuiteName(id), "TLS_ECDHE_") {
				t.Errorf("suite %s is not ECDHE", CipherSuiteName(id))
			}
		}
	}
}

func TestEnumerateTLS12CurvesAgainstCryptoTLS(t *testing.T) {
	address := tls12Server(t, tls.X25519, tls.CurveP256)

	enumeration, err := EnumerateTLS12Curves(context.Background(), Options{Address: address, Timeout: 3 * time.Second}, ECDHECurveIDs())
	if err != nil {
		t.Fatalf("EnumerateTLS12Curves() error = %v", err)
	}
	if !enumeration.Complete || len(enumeration.Unresolved) != 0 {
		t.Fatalf("enumeration = %+v, want a complete result", enumeration)
	}
	got := map[string]bool{}
	for _, curve := range enumeration.Supported {
		got[curve.Name] = true
	}
	if len(got) != 2 || !got["X25519"] || !got["P-256"] {
		t.Fatalf("Supported = %+v, want X25519 and P-256", enumeration.Supported)
	}
	if enumeration.Connections != 3 {
		t.Fatalf("Connections = %d, want 3 (two curves and the refusal)", enumeration.Connections)
	}
}

func TestSelectTLS12CurveReportsCurveAndSuite(t *testing.T) {
	address := tls12Server(t, tls.CurveP384)

	result := SelectTLS12Curve(context.Background(), Options{Address: address, Timeout: 3 * time.Second}, []uint16{GroupP256, GroupP384})
	if result.Status != StatusSupported || result.SelectedGroup != GroupP384 || result.SelectedGroupName != "P-384" {
		t.Fatalf("result = %+v, want P-384", result)
	}
	if !strings.HasPrefix(result.Name, "TLS_ECDHE_") {
		t.Fatalf("suite = %q, want an ECDHE suite", result.Name)
	}

	none := SelectTLS12Curve(context.Background(), Options{Address: address, Timeout: 3 * time.Second}, []uint16{GroupP256})
	if none.Status != StatusAlert || !isNoCommonGroupAlert(none.AlertDescription) {
		t.Fatalf("result = %+v, want a no-common-curve alert", none)
	}
}

func TestSelectTLS12CurveRejectsEmptyOffer(t *testing.T) {
	if result := SelectTLS12Curve(context.Background(), Options{Address: "127.0.0.1:1"}, nil); result.ErrorCode != ErrorCodeBuildClientHelloFailed {
		t.Fatalf("result = %+v, want build_client_hello_failed", result)
	}
}

// A server that selects a curve the client did not offer cannot be trusted.
func TestEnumerateTLS12CurvesDistrustsUnofferedCurve(t *testing.T) {
	address := serverKeyExchangeFixture(t, GroupP521)

	enumeration, err := EnumerateTLS12Curves(context.Background(), Options{Address: address, Timeout: time.Second}, []uint16{GroupX25519, GroupP256})
	if err != nil {
		t.Fatalf("EnumerateTLS12Curves() error = %v", err)
	}
	if enumeration.Complete || len(enumeration.Supported) != 0 || len(enumeration.Unresolved) != 2 {
		t.Fatalf("enumeration = %+v, want nothing classified", enumeration)
	}
}

func TestEnumerateTLS12CurvesReadsKeyExchangeAcrossRecords(t *testing.T) {
	address := serverKeyExchangeFixture(t, GroupP256)

	result := SelectTLS12Curve(context.Background(), Options{Address: address, Timeout: time.Second}, []uint16{GroupX25519, GroupP256})
	if result.Status != StatusSupported || result.SelectedGroup != GroupP256 {
		t.Fatalf("result = %+v, want P-256 read from a flight split over several records", result)
	}
}

func TestSelectTLS12CurveReportsMissingKeyExchange(t *testing.T) {
	address := serverFlightFixture(t, tls.VersionTLS12, false, 3, GroupP256)
	result := SelectTLS12Curve(context.Background(), Options{Address: address, Timeout: time.Second}, []uint16{GroupP256})
	if result.Status != StatusInconclusive || result.ErrorCode != ErrorCodeServerKeyExchangeNotFound {
		t.Fatalf("result = %+v, want server_key_exchange_not_found", result)
	}

	address = serverFlightFixture(t, tls.VersionTLS12, true, 1, GroupP256)
	result = SelectTLS12Curve(context.Background(), Options{Address: address, Timeout: time.Second}, []uint16{GroupP256})
	if result.Status != StatusInconclusive || result.ErrorCode != ErrorCodeServerKeyExchangeMalformed {
		t.Fatalf("result = %+v, want server_key_exchange_malformed for a non-named curve", result)
	}
}

func TestSelectTLS12CurveRejectsLowerVersionAnswer(t *testing.T) {
	address := serverFlightFixture(t, tls.VersionTLS11, true, 3, GroupP256)
	result := SelectTLS12Curve(context.Background(), Options{Address: address, Timeout: time.Second}, []uint16{GroupP256})
	if result.Status != StatusRejected || result.ErrorCode != ErrorCodeVersionMismatch {
		t.Fatalf("result = %+v, want a version mismatch", result)
	}
}

// serverKeyExchangeFixture answers every ClientHello with a TLS 1.2 flight
// whose ServerKeyExchange names curve, split over several records.
func serverKeyExchangeFixture(t *testing.T, curve uint16) string {
	return serverFlightFixture(t, tls.VersionTLS12, true, 3, curve)
}

// serverFlightFixture answers every ClientHello with ServerHello, a fake
// Certificate and, when withKeyExchange is set, a ServerKeyExchange of the
// given curve type followed by ServerHelloDone. The bytes are written one
// handshake message per TLS record and the Certificate is split in two.
func serverFlightFixture(t *testing.T, version uint16, withKeyExchange bool, curveType byte, curve uint16) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	suite := uint16(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	var hello []byte
	hello = appendUint16(hello, version)
	hello = append(hello, make([]byte, 32)...)
	hello = appendOpaque8(hello, nil)
	hello = appendUint16(hello, suite)
	hello = append(hello, 0)
	hello = appendOpaque16(hello, nil)

	message := func(kind byte, body []byte) []byte {
		out := append([]byte{kind}, appendUint24(nil, len(body))...)
		return append(out, body...)
	}
	record := func(payload []byte) []byte {
		out := append([]byte{22, 3, 3}, appendUint16(nil, uint16(len(payload)))...)
		return append(out, payload...)
	}

	certificate := message(11, make([]byte, 3000))
	var flight []byte
	flight = append(flight, record(message(handshakeServerHello, hello))...)
	flight = append(flight, record(certificate[:1500])...)
	flight = append(flight, record(certificate[1500:])...)
	if withKeyExchange {
		exchange := append([]byte{curveType}, appendUint16(nil, curve)...)
		exchange = append(exchange, make([]byte, 40)...)
		flight = append(flight, record(message(handshakeServerKeyExchange, exchange))...)
	}
	flight = append(flight, record(message(handshakeServerHelloDone, nil))...)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = readTLSRecord(conn)
				_, _ = conn.Write(flight)
				time.Sleep(50 * time.Millisecond)
			}()
		}
	}()
	return listener.Addr().String()
}
