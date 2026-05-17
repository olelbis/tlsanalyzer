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
	"time"
)

type Status string

const (
	StatusSupported         Status = "supported"
	StatusRejected          Status = "rejected"
	StatusHelloRetryRequest Status = "hello-retry-request"
	StatusAlert             Status = "alert"
	StatusTimeout           Status = "timeout"
	StatusClosed            Status = "closed"
	StatusInconclusive      Status = "inconclusive"
)

type Options struct {
	Address    string
	ServerName string
	Timeout    time.Duration
	ALPN       []string
}

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

func ProbeTLS13CipherSuites(ctx context.Context, opts Options, cipherSuites []uint16) ([]Result, error) {
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

func ProbeTLS13CipherSuite(ctx context.Context, opts Options, cipherSuite uint16) (Result, error) {
	result := Result{
		CipherSuite: cipherSuite,
		Name:        tls.CipherSuiteName(cipherSuite),
		Status:      StatusInconclusive,
	}

	if opts.Address == "" {
		return result, errors.New("tlsprobe: address is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	clientHello, err := buildTLS13ClientHello(opts, cipherSuite)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", opts.Address)
	if err != nil {
		result.Status = statusForNetworkError(err)
		result.Error = err.Error()
		return result, nil
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		result.Error = err.Error()
		return result, nil
	}

	if _, err := conn.Write(clientHello); err != nil {
		result.Status = statusForNetworkError(err)
		result.Error = err.Error()
		return result, nil
	}

	return readProbeResult(conn, result)
}

func buildTLS13ClientHello(opts Options, cipherSuite uint16) ([]byte, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, err
	}
	sessionID := make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		return nil, err
	}

	var body []byte
	body = appendUint16(body, 0x0303)
	body = append(body, randomBytes...)
	body = appendOpaque8(body, sessionID)
	body = appendUint16(body, 2)
	body = appendUint16(body, cipherSuite)
	body = append(body, 1, 0)

	extensions := buildClientHelloExtensions(opts, privateKey.PublicKey().Bytes())
	body = appendOpaque16(body, extensions)

	handshake := []byte{1}
	handshake = appendUint24(handshake, len(body))
	handshake = append(handshake, body...)

	record := []byte{22, 0x03, 0x01}
	record = appendUint16(record, uint16(len(handshake)))
	record = append(record, handshake...)
	return record, nil
}

func buildClientHelloExtensions(opts Options, keyShare []byte) []byte {
	var extensions []byte
	if opts.ServerName != "" {
		var serverName []byte
		serverName = append(serverName, 0)
		serverName = appendOpaque16(serverName, []byte(opts.ServerName))
		extensions = appendExtension(extensions, 0, appendOpaque16(nil, serverName))
	}

	var supportedGroups []byte
	supportedGroups = appendUint16(supportedGroups, 0x001d)
	supportedGroups = appendUint16(supportedGroups, 0x0017)
	extensions = appendExtension(extensions, 10, appendOpaque16(nil, supportedGroups))

	var signatureAlgorithms []byte
	for _, algorithm := range []uint16{0x0403, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501} {
		signatureAlgorithms = appendUint16(signatureAlgorithms, algorithm)
	}
	extensions = appendExtension(extensions, 13, appendOpaque16(nil, signatureAlgorithms))

	extensions = appendExtension(extensions, 43, []byte{2, 0x03, 0x04})

	var keyShareEntry []byte
	keyShareEntry = appendUint16(keyShareEntry, 0x001d)
	keyShareEntry = appendOpaque16(keyShareEntry, keyShare)
	extensions = appendExtension(extensions, 51, appendOpaque16(nil, keyShareEntry))

	extensions = appendExtension(extensions, 45, []byte{1, 1})

	if len(opts.ALPN) > 0 {
		var protocols []byte
		for _, protocol := range opts.ALPN {
			if len(protocol) == 0 || len(protocol) > 255 {
				continue
			}
			protocols = appendOpaque8(protocols, []byte(protocol))
		}
		if len(protocols) > 0 {
			extensions = appendExtension(extensions, 16, appendOpaque16(nil, protocols))
		}
	}

	return extensions
}

func readProbeResult(conn net.Conn, result Result) (Result, error) {
	for i := 0; i < 8; i++ {
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			result.Status = statusForNetworkError(err)
			result.Error = err.Error()
			return result, nil
		}

		recordLength := int(binary.BigEndian.Uint16(header[3:5]))
		if recordLength == 0 || recordLength > 18432 {
			result.Status = StatusInconclusive
			result.Error = fmt.Sprintf("invalid TLS record length %d", recordLength)
			return result, nil
		}

		payload := make([]byte, recordLength)
		if _, err := io.ReadFull(conn, payload); err != nil {
			result.Status = statusForNetworkError(err)
			result.Error = err.Error()
			return result, nil
		}

		switch header[0] {
		case 20:
			continue
		case 21:
			result.Status = StatusAlert
			result.Alert = describeAlert(payload)
			return result, nil
		case 22:
			return parseHandshakePayload(payload, result), nil
		default:
			result.Status = StatusInconclusive
			result.Error = fmt.Sprintf("unexpected TLS record type %d", header[0])
			return result, nil
		}
	}

	result.Status = StatusInconclusive
	result.Error = "server did not send a ServerHello or alert"
	return result, nil
}

func parseHandshakePayload(payload []byte, result Result) Result {
	for len(payload) >= 4 {
		handshakeType := payload[0]
		handshakeLength := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
		if handshakeLength > len(payload)-4 {
			result.Status = StatusInconclusive
			result.Error = "incomplete handshake message"
			return result
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
	return result
}

func parseServerHello(body []byte, result Result) Result {
	if len(body) < 38 {
		result.Status = StatusInconclusive
		result.Error = "ServerHello is too short"
		return result
	}

	if bytes.Equal(body[2:34], helloRetryRequestRandom) {
		result.Status = StatusHelloRetryRequest
		return result
	}

	offset := 34
	sessionIDLength := int(body[offset])
	offset++
	if offset+sessionIDLength+3 > len(body) {
		result.Status = StatusInconclusive
		result.Error = "ServerHello session ID is truncated"
		return result
	}
	offset += sessionIDLength

	selectedCipher := binary.BigEndian.Uint16(body[offset : offset+2])
	if selectedCipher == result.CipherSuite {
		result.Status = StatusSupported
		return result
	}

	result.Status = StatusRejected
	result.Error = fmt.Sprintf("server selected %s", tls.CipherSuiteName(selectedCipher))
	return result
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
