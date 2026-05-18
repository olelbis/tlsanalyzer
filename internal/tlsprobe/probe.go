package tlsprobe

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Status describes the outcome of a raw TLS 1.3 cipher probe.
type Status string

const (
	// StatusSupported means the server selected the offered TLS 1.3 cipher suite.
	StatusSupported Status = "supported"
	// StatusRejected means the server replied with ServerHello but selected another cipher suite.
	StatusRejected Status = "rejected"
	// StatusHelloRetryRequest means the server sent HelloRetryRequest and the probe could not complete a retry.
	StatusHelloRetryRequest Status = "hello-retry-request"
	// StatusAlert means the server rejected the probe with a TLS alert.
	StatusAlert Status = "alert"
	// StatusTimeout means the TCP connection, write or read timed out.
	StatusTimeout Status = "timeout"
	// StatusClosed means the peer closed the connection before a supported/rejected decision.
	StatusClosed Status = "closed"
	// StatusInconclusive means the probe could not classify the response deterministically.
	StatusInconclusive Status = "inconclusive"
)

// Options configures raw TLS 1.3 ClientHello probing.
//
// Address is required and must be a host:port TCP address. ServerName is used
// for SNI when set. Timeout applies to connect, write and read operations.
// ALPN values are advertised as-is after empty values are ignored.
type Options struct {
	Address    string
	ServerName string
	Timeout    time.Duration
	ALPN       []string
}

// Result contains evidence from one raw TLS 1.3 cipher probe.
//
// The probe stops after enough handshake evidence is observed to classify the
// offered cipher suite. It does not complete a full TLS handshake.
type Result struct {
	CipherSuite uint16
	Name        string
	Status      Status
	Alert       string
	Error       string
}

var helloRetryRequestRandom = []byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
	0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
	0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

const (
	extensionCookie              uint16 = 44
	extensionKeyShare            uint16 = 51
	extensionServerName          uint16 = 0
	extensionSupportedGroups     uint16 = 10
	extensionSignatureAlgorithms uint16 = 13
	extensionALPN                uint16 = 16
	extensionSupportedVersions   uint16 = 43
	extensionPSKModes            uint16 = 45

	groupX25519 uint16 = 0x001d
	groupP256   uint16 = 0x0017
)

type clientHelloSpec struct {
	opts          Options
	cipherSuite   uint16
	sessionID     []byte
	keyShareGroup uint16
	cookie        []byte
}

type helloRetryRequest struct {
	selectedGroup uint16
	cookie        []byte
}

type readResult struct {
	result Result
	hrr    *helloRetryRequest
}

// ProbeTLS13CipherSuites probes each TLS 1.3 cipher suite independently.
//
// Results are returned in the same order as cipherSuites. Configuration errors
// stop probing and are returned as errors; network and protocol outcomes are
// represented in each Result.
func ProbeTLS13CipherSuites(ctx context.Context, opts Options, cipherSuites []uint16) ([]Result, error) {
	if err := ValidateOptions(opts); err != nil {
		return nil, err
	}
	if len(cipherSuites) == 0 {
		return nil, nil
	}

	results := make([]Result, 0, len(cipherSuites))
	for _, cipherSuite := range cipherSuites {
		result, err := ProbeTLS13CipherSuite(ctx, opts, cipherSuite)
		if err != nil {
			return results, err
		}
		results = append(results, result)
	}
	return results, nil
}

// ProbeTLS13CipherSuite sends a minimal TLS 1.3 ClientHello offering one cipher suite.
//
// This function is intentionally a probe, not a TLS implementation. It parses
// ServerHello, HelloRetryRequest, alerts, connection close and timeout outcomes
// and then returns the observed classification.
func ProbeTLS13CipherSuite(ctx context.Context, opts Options, cipherSuite uint16) (Result, error) {
	result := Result{
		CipherSuite: cipherSuite,
		Name:        tls.CipherSuiteName(cipherSuite),
		Status:      StatusInconclusive,
	}

	if err := ValidateOptions(opts); err != nil {
		return result, err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	sessionID := make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		result.Error = err.Error()
		return result, nil
	}

	clientHello, err := buildTLS13ClientHello(clientHelloSpec{
		opts:          opts,
		cipherSuite:   cipherSuite,
		sessionID:     sessionID,
		keyShareGroup: groupX25519,
	})
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", opts.Address)
	if err != nil {
		result.Status = statusForNetworkError(err)
		result.Error = stableNetworkError(err)
		return result, nil
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		result.Error = err.Error()
		return result, nil
	}

	if _, err := conn.Write(clientHello); err != nil {
		result.Status = statusForNetworkError(err)
		result.Error = stableNetworkError(err)
		return result, nil
	}

	read, err := readProbeRecord(conn, result)
	if err != nil || read.hrr == nil {
		return read.result, err
	}

	retryHello, retryErr := buildRetryClientHello(opts, cipherSuite, sessionID, read.hrr)
	if retryErr != nil {
		read.result.Status = StatusHelloRetryRequest
		read.result.Error = retryErr.Error()
		return read.result, nil
	}
	if _, err := conn.Write(retryHello); err != nil {
		read.result.Status = statusForNetworkError(err)
		read.result.Error = stableNetworkError(err)
		return read.result, nil
	}

	return readProbeResult(conn, read.result)
}

// SupportedTLS13CipherSuites returns the TLS 1.3 cipher suites understood by the probe.
func SupportedTLS13CipherSuites() []uint16 {
	return []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}
}

// ValidateOptions checks probe configuration without opening a network connection.
func ValidateOptions(opts Options) error {
	if opts.Address == "" {
		return errors.New("tlsprobe: address is required")
	}
	for _, protocol := range opts.ALPN {
		if len(protocol) > 255 {
			return fmt.Errorf("tlsprobe: ALPN protocol %q is longer than 255 bytes", protocol)
		}
	}
	return nil
}

func buildRetryClientHello(opts Options, cipherSuite uint16, sessionID []byte, hrr *helloRetryRequest) ([]byte, error) {
	if hrr.selectedGroup == 0 {
		return nil, errors.New("HelloRetryRequest did not include a selected group")
	}
	if !isSupportedKeyShareGroup(hrr.selectedGroup) {
		return nil, fmt.Errorf("HelloRetryRequest selected unsupported group 0x%04x", hrr.selectedGroup)
	}

	return buildTLS13ClientHello(clientHelloSpec{
		opts:          opts,
		cipherSuite:   cipherSuite,
		sessionID:     sessionID,
		keyShareGroup: hrr.selectedGroup,
		cookie:        hrr.cookie,
	})
}

func buildTLS13ClientHello(spec clientHelloSpec) ([]byte, error) {
	publicKey, err := generateKeyShare(spec.keyShareGroup)
	if err != nil {
		return nil, err
	}

	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, err
	}
	if len(spec.sessionID) > 32 {
		return nil, errors.New("session ID is too long")
	}

	var body []byte
	body = appendUint16(body, 0x0303)
	body = append(body, randomBytes...)
	body = appendOpaque8(body, spec.sessionID)
	body = appendUint16(body, 2)
	body = appendUint16(body, spec.cipherSuite)
	body = append(body, 1, 0)

	extensions := buildClientHelloExtensions(spec, publicKey)
	body = appendOpaque16(body, extensions)

	handshake := []byte{1}
	handshake = appendUint24(handshake, len(body))
	handshake = append(handshake, body...)

	record := []byte{22, 0x03, 0x01}
	record = appendUint16(record, uint16(len(handshake)))
	record = append(record, handshake...)
	return record, nil
}

func generateKeyShare(group uint16) ([]byte, error) {
	var curve ecdh.Curve
	switch group {
	case groupX25519:
		curve = ecdh.X25519()
	case groupP256:
		curve = ecdh.P256()
	default:
		return nil, fmt.Errorf("unsupported key share group 0x%04x", group)
	}
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return privateKey.PublicKey().Bytes(), nil
}

func buildClientHelloExtensions(spec clientHelloSpec, keyShare []byte) []byte {
	var extensions []byte
	if spec.opts.ServerName != "" {
		var serverName []byte
		serverName = append(serverName, 0)
		serverName = appendOpaque16(serverName, []byte(spec.opts.ServerName))
		extensions = appendExtension(extensions, extensionServerName, appendOpaque16(nil, serverName))
	}

	var supportedGroups []byte
	supportedGroups = appendUint16(supportedGroups, groupX25519)
	supportedGroups = appendUint16(supportedGroups, groupP256)
	extensions = appendExtension(extensions, extensionSupportedGroups, appendOpaque16(nil, supportedGroups))

	var signatureAlgorithms []byte
	for _, algorithm := range []uint16{0x0403, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501} {
		signatureAlgorithms = appendUint16(signatureAlgorithms, algorithm)
	}
	extensions = appendExtension(extensions, extensionSignatureAlgorithms, appendOpaque16(nil, signatureAlgorithms))

	extensions = appendExtension(extensions, extensionSupportedVersions, []byte{2, 0x03, 0x04})

	var keyShareEntry []byte
	keyShareEntry = appendUint16(keyShareEntry, spec.keyShareGroup)
	keyShareEntry = appendOpaque16(keyShareEntry, keyShare)
	extensions = appendExtension(extensions, extensionKeyShare, appendOpaque16(nil, keyShareEntry))

	extensions = appendExtension(extensions, extensionPSKModes, []byte{1, 1})

	if len(spec.cookie) > 0 {
		extensions = appendExtension(extensions, extensionCookie, spec.cookie)
	}

	if len(spec.opts.ALPN) > 0 {
		var protocols []byte
		for _, protocol := range spec.opts.ALPN {
			if len(protocol) == 0 || len(protocol) > 255 {
				continue
			}
			protocols = appendOpaque8(protocols, []byte(protocol))
		}
		if len(protocols) > 0 {
			extensions = appendExtension(extensions, extensionALPN, appendOpaque16(nil, protocols))
		}
	}

	return extensions
}

func readProbeResult(conn net.Conn, result Result) (Result, error) {
	read, err := readProbeRecord(conn, result)
	return read.result, err
}

func readProbeRecord(conn net.Conn, result Result) (readResult, error) {
	for i := 0; i < 8; i++ {
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			result.Status = statusForNetworkError(err)
			result.Error = stableNetworkError(err)
			return readResult{result: result}, nil
		}

		recordLength := int(binary.BigEndian.Uint16(header[3:5]))
		if recordLength == 0 || recordLength > 18432 {
			result.Status = StatusInconclusive
			result.Error = fmt.Sprintf("invalid TLS record length %d", recordLength)
			return readResult{result: result}, nil
		}

		payload := make([]byte, recordLength)
		if _, err := io.ReadFull(conn, payload); err != nil {
			result.Status = statusForNetworkError(err)
			result.Error = stableNetworkError(err)
			return readResult{result: result}, nil
		}

		switch header[0] {
		case 20:
			continue
		case 21:
			result.Status = StatusAlert
			result.Alert = describeAlert(payload)
			return readResult{result: result}, nil
		case 22:
			return parseHandshakePayload(payload, result), nil
		default:
			result.Status = StatusInconclusive
			result.Error = fmt.Sprintf("unexpected TLS record type %d", header[0])
			return readResult{result: result}, nil
		}
	}

	result.Status = StatusInconclusive
	result.Error = "server did not send a ServerHello or alert"
	return readResult{result: result}, nil
}

func parseHandshakePayload(payload []byte, result Result) readResult {
	for len(payload) >= 4 {
		handshakeType := payload[0]
		handshakeLength := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
		if handshakeLength > len(payload)-4 {
			result.Status = StatusInconclusive
			result.Error = "incomplete handshake message"
			return readResult{result: result}
		}
		body := payload[4 : 4+handshakeLength]
		payload = payload[4+handshakeLength:]

		if handshakeType != 2 {
			continue
		}
		return parseServerHello(body, result)
	}

	result.Status = StatusInconclusive
	result.Error = "ServerHello not found"
	return readResult{result: result}
}

func parseServerHello(body []byte, result Result) readResult {
	if len(body) < 38 {
		result.Status = StatusInconclusive
		result.Error = "ServerHello is too short"
		return readResult{result: result}
	}

	if bytes.Equal(body[2:34], helloRetryRequestRandom) {
		result.Status = StatusHelloRetryRequest
		hrr, err := parseHelloRetryRequest(body)
		if err != nil {
			result.Error = err.Error()
		}
		return readResult{result: result, hrr: hrr}
	}

	offset := 34
	sessionIDLength := int(body[offset])
	offset++
	if offset+sessionIDLength+3 > len(body) {
		result.Status = StatusInconclusive
		result.Error = "ServerHello session ID is truncated"
		return readResult{result: result}
	}
	offset += sessionIDLength

	selectedCipher := binary.BigEndian.Uint16(body[offset : offset+2])
	if selectedCipher == result.CipherSuite {
		result.Status = StatusSupported
		return readResult{result: result}
	}

	result.Status = StatusRejected
	result.Error = fmt.Sprintf("server selected %s", tls.CipherSuiteName(selectedCipher))
	return readResult{result: result}
}

func parseHelloRetryRequest(body []byte) (*helloRetryRequest, error) {
	offset := 34
	sessionIDLength := int(body[offset])
	offset++
	if offset+sessionIDLength+3 > len(body) {
		return nil, errors.New("HelloRetryRequest session ID is truncated")
	}
	offset += sessionIDLength + 3
	if offset+2 > len(body) {
		return nil, errors.New("HelloRetryRequest extensions are missing")
	}
	extensionsLength := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if offset+extensionsLength > len(body) {
		return nil, errors.New("HelloRetryRequest extensions are truncated")
	}

	hrr := &helloRetryRequest{}
	extensions := body[offset : offset+extensionsLength]
	for len(extensions) > 0 {
		if len(extensions) < 4 {
			return hrr, errors.New("HelloRetryRequest extension header is truncated")
		}
		extensionType := binary.BigEndian.Uint16(extensions[0:2])
		extensionLength := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if extensionLength > len(extensions) {
			return hrr, errors.New("HelloRetryRequest extension data is truncated")
		}
		extensionData := extensions[:extensionLength]
		extensions = extensions[extensionLength:]

		switch extensionType {
		case extensionKeyShare:
			if len(extensionData) != 2 {
				return hrr, errors.New("HelloRetryRequest key_share extension is malformed")
			}
			hrr.selectedGroup = binary.BigEndian.Uint16(extensionData)
		case extensionCookie:
			hrr.cookie = append([]byte(nil), extensionData...)
		}
	}

	if hrr.selectedGroup == 0 {
		return hrr, errors.New("HelloRetryRequest selected group is missing")
	}
	return hrr, nil
}

func isSupportedKeyShareGroup(group uint16) bool {
	return group == groupX25519 || group == groupP256
}

func statusForNetworkError(err error) Status {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return StatusClosed
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StatusTimeout
	}
	return StatusInconclusive
}

func stableNetworkError(err error) string {
	if err == nil {
		return ""
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return "connection closed"
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "connection reset by peer") ||
		strings.Contains(message, "use of closed network connection") {
		return "connection closed"
	}
	return err.Error()
}

func describeAlert(payload []byte) string {
	if len(payload) < 2 {
		return "malformed alert"
	}
	return fmt.Sprintf("%s/%s", alertLevelName(payload[0]), alertDescriptionName(payload[1]))
}

func alertLevelName(level byte) string {
	switch level {
	case 1:
		return "warning"
	case 2:
		return "fatal"
	default:
		return fmt.Sprintf("level-%d", level)
	}
}

func alertDescriptionName(description byte) string {
	switch description {
	case 0:
		return "close_notify"
	case 10:
		return "unexpected_message"
	case 20:
		return "bad_record_mac"
	case 22:
		return "record_overflow"
	case 40:
		return "handshake_failure"
	case 42:
		return "bad_certificate"
	case 43:
		return "unsupported_certificate"
	case 44:
		return "certificate_revoked"
	case 45:
		return "certificate_expired"
	case 46:
		return "certificate_unknown"
	case 47:
		return "illegal_parameter"
	case 48:
		return "unknown_ca"
	case 49:
		return "access_denied"
	case 50:
		return "decode_error"
	case 51:
		return "decrypt_error"
	case 70:
		return "protocol_version"
	case 71:
		return "insufficient_security"
	case 80:
		return "internal_error"
	case 86:
		return "inappropriate_fallback"
	case 90:
		return "user_canceled"
	case 109:
		return "missing_extension"
	case 110:
		return "unsupported_extension"
	case 112:
		return "unrecognized_name"
	case 115:
		return "unknown_psk_identity"
	case 116:
		return "certificate_required"
	case 120:
		return "no_application_protocol"
	default:
		return fmt.Sprintf("alert-%d", description)
	}
}

func appendExtension(dst []byte, extensionType uint16, data []byte) []byte {
	dst = appendUint16(dst, extensionType)
	return appendOpaque16(dst, data)
}

func appendOpaque8(dst []byte, data []byte) []byte {
	dst = append(dst, byte(len(data)))
	return append(dst, data...)
}

func appendOpaque16(dst []byte, data []byte) []byte {
	dst = appendUint16(dst, uint16(len(data)))
	return append(dst, data...)
}

func appendUint16(dst []byte, value uint16) []byte {
	return append(dst, byte(value>>8), byte(value))
}

func appendUint24(dst []byte, value int) []byte {
	return append(dst, byte(value>>16), byte(value>>8), byte(value))
}
