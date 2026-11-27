package tlsprobe

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ECDHECurve describes an elliptic curve a TLS 1.2 server can use for ECDHE.
type ECDHECurve struct {
	ID   uint16
	Name string
	// Bits is the size of the curve in bits.
	Bits int
}

// WeakECDHECurveBits is the size below which a curve is reported as weak:
// the curves under 224 bits give less than 112 bits of security.
const WeakECDHECurveBits = 224

// Weak reports whether the curve is smaller than WeakECDHECurveBits.
func (c ECDHECurve) Weak() bool { return c.Bits < WeakECDHECurveBits }

// ecdheCurves is the catalog of the IANA "TLS Supported Groups" elliptic
// curves (RFC 8422), strongest modern choices first so that a server that
// follows the client order reports them first. Names that crypto/tls and the
// TLS 1.3 group catalog already use keep that spelling.
var ecdheCurves = []ECDHECurve{
	{GroupX25519, "X25519", 255},
	{GroupP256, "P-256", 256},
	{GroupP384, "P-384", 384},
	{GroupP521, "P-521", 521},
	{GroupX448, "X448", 448},
	{26, "brainpoolP256r1", 256},
	{27, "brainpoolP384r1", 384},
	{28, "brainpoolP512r1", 512},
	{22, "secp256k1", 256},
	{20, "secp224k1", 224},
	{21, "secp224r1", 224},
	{18, "secp192k1", 192},
	{19, "secp192r1", 192},
	{15, "secp160k1", 160},
	{16, "secp160r1", 160},
	{17, "secp160r2", 160},
	{13, "sect571k1", 571},
	{14, "sect571r1", 571},
	{11, "sect409k1", 409},
	{12, "sect409r1", 409},
	{9, "sect283k1", 283},
	{10, "sect283r1", 283},
	{8, "sect239k1", 239},
	{6, "sect233k1", 233},
	{7, "sect233r1", 233},
	{4, "sect193r1", 193},
	{5, "sect193r2", 193},
	{1, "sect163k1", 163},
	{2, "sect163r1", 163},
	{3, "sect163r2", 163},
}

var ecdheCurveByID = func() map[uint16]ECDHECurve {
	curves := make(map[uint16]ECDHECurve, len(ecdheCurves))
	for _, curve := range ecdheCurves {
		curves[curve.ID] = curve
	}
	return curves
}()

// ECDHECurves returns the curve catalog in the order the enumeration offers
// it. The returned slice is a copy.
func ECDHECurves() []ECDHECurve {
	return append([]ECDHECurve(nil), ecdheCurves...)
}

// ECDHECurveIDs returns the IDs of ECDHECurves.
func ECDHECurveIDs() []uint16 {
	ids := make([]uint16, len(ecdheCurves))
	for i, curve := range ecdheCurves {
		ids[i] = curve.ID
	}
	return ids
}

// LookupECDHECurve returns the catalog entry for a curve ID.
func LookupECDHECurve(id uint16) (ECDHECurve, bool) {
	curve, ok := ecdheCurveByID[id]
	return curve, ok
}

const (
	// ErrorCodeServerKeyExchangeNotFound means the server answered with a
	// ServerHello but ended its flight without a ServerKeyExchange.
	ErrorCodeServerKeyExchangeNotFound ErrorCode = "server_key_exchange_not_found"
	// ErrorCodeServerKeyExchangeMalformed means the ServerKeyExchange did not
	// carry a named curve.
	ErrorCodeServerKeyExchangeMalformed ErrorCode = "server_key_exchange_malformed"

	handshakeServerHello       = 2
	handshakeServerKeyExchange = 12
	handshakeServerHelloDone   = 14

	// maxCurveProbeBytes bounds the handshake data read while looking for the
	// ServerKeyExchange behind a certificate chain.
	maxCurveProbeBytes = 128 * 1024
)

// ecdheCipherSuites returns the TLS 1.2 ECDHE suites of the legacy catalog,
// RSA and ECDSA alike, so that a server selects one for whichever certificate
// it holds.
func ecdheCipherSuites() []uint16 {
	var ids []uint16
	for _, suite := range legacyCipherSuites {
		if strings.HasPrefix(suite.Name, "TLS_ECDHE_") && suite.MinVersion <= tls.VersionTLS12 {
			ids = append(ids, suite.ID)
		}
	}
	return ids
}

// EnumerateTLS12Curves finds which of curves a server uses for TLS 1.2 ECDHE.
//
// Each ClientHello offers every TLS 1.2 ECDHE cipher suite and the remaining
// curves in supported_groups. The server picks a suite and a curve, and
// announces the curve in its ServerKeyExchange (RFC 8422 section 5.4), which
// the probe reads and then drops the connection: no key exchange is
// completed. The curve is recorded, removed from the offer, and the probe
// repeats until the server refuses with a handshake_failure alert, so a
// server with k curves costs k+1 connections.
//
// Only what the server does for the certificate it selects is observed: a
// server with an RSA and an ECDSA certificate may use different curves for
// each. Unanswered ClientHellos, unexpected alerts and a curve that was not
// offered end the enumeration with the remaining curves in Unresolved, as in
// EnumerateTLS13Groups.
func EnumerateTLS12Curves(ctx context.Context, opts Options, curves []uint16) (GroupEnumeration, error) {
	return enumerateGroupSelections(ctx, opts, curves, groupSelector{
		selected: StatusSupported,
		pick:     selectTLS12Curve,
		lookup: func(id uint16) KeyExchangeGroup {
			if curve, ok := ecdheCurveByID[id]; ok {
				return KeyExchangeGroup{ID: curve.ID, Name: curve.Name}
			}
			return KeyExchangeGroup{ID: id, Name: fmt.Sprintf("0x%04x", id)}
		},
	})
}

// SelectTLS12Curve sends one TLS 1.2 ClientHello that offers every ECDHE
// cipher suite and the given curves, in order, and reports the curve the
// server announces in its ServerKeyExchange. On StatusSupported,
// Result.SelectedGroup is the curve and Result.CipherSuite the suite the
// server chose; an alert means the server shares no curve with the offer.
func SelectTLS12Curve(ctx context.Context, opts Options, curves []uint16) Result {
	return selectTLS12Curve(ctx, opts, curves)
}

func selectTLS12Curve(ctx context.Context, opts Options, curves []uint16) Result {
	result := Result{
		Status:        StatusInconclusive,
		EvidenceLevel: EvidenceClientHelloOnly,
	}
	if len(curves) == 0 {
		return withError(result, ErrorCodeBuildClientHelloFailed, "no curve to offer")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	suites := ecdheCipherSuites()
	clientHello, err := buildLegacyClientHelloWithGroups(opts, tls.VersionTLS12, suites, curves)
	if err != nil {
		return withError(result, ErrorCodeBuildClientHelloFailed, err.Error())
	}

	dialContext := opts.DialContext
	if dialContext == nil {
		dialer := net.Dialer{Timeout: timeout}
		dialContext = dialer.DialContext
	}
	conn, err := dialContext(ctx, "tcp", opts.Address)
	if err != nil {
		result.Status = statusForNetworkError(err)
		return withError(result, ErrorCodeConnectFailed, stableNetworkError(err))
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return withError(result, ErrorCodeDeadlineFailed, err.Error())
	}
	stopOnContextDone := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stopOnContextDone()

	if _, err := conn.Write(clientHello); err != nil {
		result.Status = statusForNetworkError(err)
		return withError(result, ErrorCodeWriteFailed, stableNetworkError(err))
	}

	return readServerKeyExchange(conn, result, suites)
}

// readServerKeyExchange reads the server's first flight until the
// ServerKeyExchange, reassembling handshake messages that span records.
func readServerKeyExchange(conn net.Conn, result Result, offered []uint16) Result {
	var handshake []byte
	sawServerHello := false

	for records := 0; records < 32; records++ {
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			result.Status = statusForNetworkError(err)
			return withError(result, ErrorCodeReadFailed, stableNetworkError(err))
		}
		length := int(binary.BigEndian.Uint16(header[3:5]))
		if length == 0 || length > 18432 {
			result.Status = StatusInconclusive
			return withError(result, ErrorCodeInvalidRecordLength, fmt.Sprintf("invalid TLS record length %d", length))
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			result.Status = statusForNetworkError(err)
			return withError(result, ErrorCodeReadFailed, stableNetworkError(err))
		}

		switch header[0] {
		case 20:
			continue
		case 21:
			result.Status = StatusAlert
			result.Alert = describeAlert(payload)
			result.AlertLevel, result.AlertDescription = alertCodes(payload)
			return result
		case 22:
		default:
			result.Status = StatusInconclusive
			return withError(result, ErrorCodeUnexpectedRecordType, fmt.Sprintf("unexpected TLS record type %d", header[0]))
		}

		handshake = append(handshake, payload...)
		if len(handshake) > maxCurveProbeBytes {
			result.Status = StatusInconclusive
			return withError(result, ErrorCodeIncompleteHandshake, "server flight is too large")
		}

		for len(handshake) >= 4 {
			kind := handshake[0]
			size := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if len(handshake) < 4+size {
				break
			}
			body := handshake[4 : 4+size]
			handshake = handshake[4+size:]

			switch kind {
			case handshakeServerHello:
				checked, ok := checkLegacyServerHello(body, result, offered)
				if !ok {
					return checked
				}
				result = checked
				sawServerHello = true
			case handshakeServerKeyExchange:
				if !sawServerHello {
					continue
				}
				if len(body) < 3 || body[0] != 3 {
					result.Status = StatusInconclusive
					return withError(result, ErrorCodeServerKeyExchangeMalformed, "ServerKeyExchange does not name a curve")
				}
				result.SelectedGroup = binary.BigEndian.Uint16(body[1:3])
				result.SelectedGroupName = keyShareGroupName(result.SelectedGroup)
				if curve, ok := ecdheCurveByID[result.SelectedGroup]; ok {
					result.SelectedGroupName = curve.Name
				}
				result.Status = StatusSupported
				return result
			case handshakeServerHelloDone:
				result.Status = StatusInconclusive
				return withError(result, ErrorCodeServerKeyExchangeNotFound, "the server flight ended without a ServerKeyExchange")
			}
		}
	}

	result.Status = StatusInconclusive
	return withError(result, ErrorCodeNoServerHelloOrAlert, "server did not send a ServerKeyExchange or alert")
}

// checkLegacyServerHello validates a TLS 1.2 ServerHello against the offered
// suites and records the selected one. It returns ok=false with the final
// result when the server did not answer on TLS 1.2 with an offered suite.
func checkLegacyServerHello(body []byte, result Result, offered []uint16) (Result, bool) {
	if len(body) < 38 {
		result.Status = StatusInconclusive
		return withError(result, ErrorCodeServerHelloTooShort, "ServerHello is too short"), false
	}
	offset := 35 + int(body[34])
	if offset+3 > len(body) {
		result.Status = StatusInconclusive
		return withError(result, ErrorCodeServerHelloTruncated, "ServerHello session ID is truncated"), false
	}

	if version := binary.BigEndian.Uint16(body[0:2]); version != tls.VersionTLS12 {
		result.Status = StatusRejected
		return withError(result, ErrorCodeVersionMismatch, fmt.Sprintf(
			"server answered on %s instead of TLS 1.2", legacyVersionName(version))), false
	}
	suite := binary.BigEndian.Uint16(body[offset : offset+2])
	if !containsGroup(offered, suite) {
		result.Status = StatusRejected
		return withError(result, ErrorCodeRejectedCipher, fmt.Sprintf("server selected %s", CipherSuiteName(suite))), false
	}
	result.CipherSuite = suite
	result.Name = CipherSuiteName(suite)
	return result, true
}
