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
	"strconv"
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

// EvidenceLevel describes how much TLS evidence a probe collected.
type EvidenceLevel string

const (
	// EvidenceClientHelloOnly means the probe stopped after ClientHello response evidence.
	EvidenceClientHelloOnly EvidenceLevel = "clienthello-only"
)

// ErrorCode is a stable machine-readable diagnostic code for Result.Error.
type ErrorCode string

const (
	ErrorCodeBuildClientHelloFailed ErrorCode = "build_client_hello_failed"
	ErrorCodeConnectFailed          ErrorCode = "connect_failed"
	ErrorCodeDeadlineFailed         ErrorCode = "deadline_failed"
	ErrorCodeWriteFailed            ErrorCode = "write_failed"
	ErrorCodeReadFailed             ErrorCode = "read_failed"
	ErrorCodeInvalidRecordLength    ErrorCode = "invalid_record_length"
	ErrorCodeUnexpectedRecordType   ErrorCode = "unexpected_record_type"
	ErrorCodeNoServerHelloOrAlert   ErrorCode = "no_server_hello_or_alert"
	ErrorCodeIncompleteHandshake    ErrorCode = "incomplete_handshake"
	ErrorCodeServerHelloNotFound    ErrorCode = "server_hello_not_found"
	ErrorCodeServerHelloTooShort    ErrorCode = "server_hello_too_short"
	ErrorCodeServerHelloTruncated   ErrorCode = "server_hello_truncated"
	ErrorCodeCompressionMissing     ErrorCode = "server_hello_compression_missing"
	ErrorCodeRejectedCipher         ErrorCode = "rejected_cipher"
	ErrorCodeMalformedHRR           ErrorCode = "malformed_hello_retry_request"
	ErrorCodeUnsupportedHRRGroup    ErrorCode = "unsupported_hello_retry_request_group"
)

// Options configures raw TLS 1.3 ClientHello probing.
//
// Address is required and must be a host:port TCP address. ServerName is used
// for SNI when set. Timeout applies to connect, write and read operations.
// ALPN values are advertised as-is after empty values are ignored. KeyShareGroups
// controls the supported groups advertised by the probe; when empty, a
// conservative default set is used. DialContext can override TCP connection
// creation for tests, proxies or embedded callers; when nil, net.Dialer is used.
type Options struct {
	Address        string
	ServerName     string
	Timeout        time.Duration
	ALPN           []string
	KeyShareGroups []uint16
	DialContext    func(ctx context.Context, network, address string) (net.Conn, error)
}

// Result contains evidence from one raw TLS 1.3 cipher probe.
//
// The probe stops after enough handshake evidence is observed to classify the
// offered cipher suite. It does not complete a full TLS handshake.
type Result struct {
	CipherSuite              uint16
	Name                     string
	Status                   Status
	EvidenceLevel            EvidenceLevel
	CompletedHandshake       bool
	Alert                    string
	AlertLevel               uint8
	AlertDescription         uint8
	SelectedGroup            uint16
	SelectedGroupName        string
	HelloRetryRequest        bool
	HelloRetryRequestRetried bool
	ErrorCode                ErrorCode
	Error                    string
}

// Summary counts raw probe outcomes for a result set.
type Summary struct {
	Total              int
	Supported          int
	Rejected           int
	Alerts             int
	Timeouts           int
	Closed             int
	HelloRetryRequests int
	Inconclusive       int
}

// ConfigError describes an invalid probe option.
type ConfigError struct {
	Field   string
	Message string
	Err     error
}

func (e *ConfigError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("tlsprobe: invalid %s: %s: %v", e.Field, e.Message, e.Err)
	}
	return fmt.Sprintf("tlsprobe: invalid %s: %s", e.Field, e.Message)
}

func (e *ConfigError) Unwrap() error {
	return e.Err
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

	// GroupP256 is the TLS supported group ID for secp256r1.
	GroupP256 uint16 = 0x0017
	// GroupP384 is the TLS supported group ID for secp384r1.
	GroupP384 uint16 = 0x0018
	// GroupP521 is the TLS supported group ID for secp521r1.
	GroupP521 uint16 = 0x0019
	// GroupX25519 is the TLS supported group ID for X25519.
	GroupX25519 uint16 = 0x001d

	groupP256   = GroupP256
	groupP384   = GroupP384
	groupP521   = GroupP521
	groupX25519 = GroupX25519
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
		CipherSuite:        cipherSuite,
		Name:               CipherSuiteName(cipherSuite),
		Status:             StatusInconclusive,
		EvidenceLevel:      EvidenceClientHelloOnly,
		ErrorCode:          "",
		CompletedHandshake: false,
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

	keyShareGroups := normalizedKeyShareGroups(opts)
	sessionID := make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		result = withError(result, ErrorCodeBuildClientHelloFailed, err.Error())
		return result, nil
	}

	clientHello, err := buildTLS13ClientHello(clientHelloSpec{
		opts:          opts,
		cipherSuite:   cipherSuite,
		sessionID:     sessionID,
		keyShareGroup: keyShareGroups[0],
	})
	if err != nil {
		result = withError(result, ErrorCodeBuildClientHelloFailed, err.Error())
		return result, nil
	}

	dialContext := opts.DialContext
	if dialContext == nil {
		dialer := net.Dialer{Timeout: timeout}
		dialContext = dialer.DialContext
	}
	conn, err := dialContext(ctx, "tcp", opts.Address)
	if err != nil {
		result.Status = statusForNetworkError(err)
		result = withError(result, ErrorCodeConnectFailed, stableNetworkError(err))
		return result, nil
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		result = withError(result, ErrorCodeDeadlineFailed, err.Error())
		return result, nil
	}

	if _, err := conn.Write(clientHello); err != nil {
		result.Status = statusForNetworkError(err)
		result = withError(result, ErrorCodeWriteFailed, stableNetworkError(err))
		return result, nil
	}

	read, err := readProbeRecord(conn, result)
	if err != nil || read.hrr == nil {
		return read.result, err
	}

	retryHello, retryErr := buildRetryClientHello(opts, cipherSuite, sessionID, read.hrr)
	if retryErr != nil {
		read.result.Status = StatusHelloRetryRequest
		read.result = withError(read.result, hrrErrorCode(retryErr), retryErr.Error())
		return read.result, nil
	}
	read.result.HelloRetryRequestRetried = true
	if _, err := conn.Write(retryHello); err != nil {
		read.result.Status = statusForNetworkError(err)
		read.result = withError(read.result, ErrorCodeWriteFailed, stableNetworkError(err))
		return read.result, nil
	}

	return readProbeResult(conn, read.result)
}

// CipherSuiteName returns the Go display name for a TLS cipher suite ID.
func CipherSuiteName(cipherSuite uint16) string {
	return tls.CipherSuiteName(cipherSuite)
}

// SupportedTLS13CipherSuites returns the TLS 1.3 cipher suites understood by the probe.
func SupportedTLS13CipherSuites() []uint16 {
	return []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}
}

// Summarize counts probe statuses without interpreting human-readable errors.
func Summarize(results []Result) Summary {
	summary := Summary{Total: len(results)}
	for _, result := range results {
		switch result.Status {
		case StatusSupported:
			summary.Supported++
		case StatusRejected:
			summary.Rejected++
		case StatusAlert:
			summary.Alerts++
		case StatusTimeout:
			summary.Timeouts++
		case StatusClosed:
			summary.Closed++
		case StatusHelloRetryRequest:
			summary.HelloRetryRequests++
		case StatusInconclusive:
			summary.Inconclusive++
		}
	}
	return summary
}

// SupportedKeyShareGroups returns the key share groups understood by the probe.
func SupportedKeyShareGroups() []uint16 {
	return append([]uint16(nil), defaultKeyShareGroups()...)
}

// ValidateOptions checks probe configuration without opening a network connection.
func ValidateOptions(opts Options) error {
	if opts.Address == "" {
		return configError("address", "is required", nil)
	}
	if opts.Address != strings.TrimSpace(opts.Address) {
		return configError("address", "must not contain leading or trailing whitespace", nil)
	}
	host, port, err := net.SplitHostPort(opts.Address)
	if err != nil {
		return configError("address", "must be a host:port TCP address", err)
	}
	if host == "" {
		return configError("address", "host is required", nil)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return configError("address", fmt.Sprintf("port %q must be a TCP port in range 1..65535", port), err)
	}
	if opts.Timeout < 0 {
		return configError("timeout", "must not be negative", nil)
	}
	for _, protocol := range opts.ALPN {
		if len(protocol) > 255 {
			return configError("alpn", fmt.Sprintf("protocol %q is longer than 255 bytes", protocol), nil)
		}
	}
	if opts.KeyShareGroups != nil && len(opts.KeyShareGroups) == 0 {
		return configError("key_share_groups", "must not be empty when set", nil)
	}
	for _, group := range opts.KeyShareGroups {
		if !isSupportedKeyShareGroup(group) {
			return configError("key_share_groups", fmt.Sprintf("unsupported group 0x%04x", group), nil)
		}
	}
	return nil
}

func configError(field, message string, err error) error {
	return &ConfigError{
		Field:   field,
		Message: message,
		Err:     err,
	}
}

func buildRetryClientHello(opts Options, cipherSuite uint16, sessionID []byte, hrr *helloRetryRequest) ([]byte, error) {
	if hrr.selectedGroup == 0 {
		return nil, errors.New("HelloRetryRequest did not include a selected group")
	}
	if !isAllowedKeyShareGroup(hrr.selectedGroup, normalizedKeyShareGroups(opts)) {
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
	case GroupX25519:
		curve = ecdh.X25519()
	case GroupP256:
		curve = ecdh.P256()
	case GroupP384:
		curve = ecdh.P384()
	case GroupP521:
		curve = ecdh.P521()
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
	for _, group := range normalizedKeyShareGroups(spec.opts) {
		supportedGroups = appendUint16(supportedGroups, group)
	}
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
	var handshakePayload []byte
	for i := 0; i < 8; i++ {
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			result.Status = statusForNetworkError(err)
			result = withError(result, ErrorCodeReadFailed, stableNetworkError(err))
			return readResult{result: result}, nil
		}

		recordLength := int(binary.BigEndian.Uint16(header[3:5]))
		if recordLength == 0 || recordLength > 18432 {
			result.Status = StatusInconclusive
			result = withError(result, ErrorCodeInvalidRecordLength, fmt.Sprintf("invalid TLS record length %d", recordLength))
			return readResult{result: result}, nil
		}

		payload := make([]byte, recordLength)
		if _, err := io.ReadFull(conn, payload); err != nil {
			result.Status = statusForNetworkError(err)
			result = withError(result, ErrorCodeReadFailed, stableNetworkError(err))
			return readResult{result: result}, nil
		}

		switch header[0] {
		case 20:
			continue
		case 21:
			result.Status = StatusAlert
			result.Alert = describeAlert(payload)
			result.AlertLevel, result.AlertDescription = alertCodes(payload)
			return readResult{result: result}, nil
		case 22:
			handshakePayload = append(handshakePayload, payload...)
			read, needMore := parseHandshakePayloadBuffered(handshakePayload, result)
			if needMore {
				continue
			}
			return read, nil
		default:
			result.Status = StatusInconclusive
			result = withError(result, ErrorCodeUnexpectedRecordType, fmt.Sprintf("unexpected TLS record type %d", header[0]))
			return readResult{result: result}, nil
		}
	}

	result.Status = StatusInconclusive
	result = withError(result, ErrorCodeNoServerHelloOrAlert, "server did not send a ServerHello or alert")
	return readResult{result: result}, nil
}

func parseHandshakePayload(payload []byte, result Result) readResult {
	read, _ := parseHandshakePayloadWithMode(payload, result, false)
	return read
}

func parseHandshakePayloadBuffered(payload []byte, result Result) (readResult, bool) {
	return parseHandshakePayloadWithMode(payload, result, true)
}

func parseHandshakePayloadWithMode(payload []byte, result Result, allowIncomplete bool) (readResult, bool) {
	for len(payload) >= 4 {
		handshakeType := payload[0]
		handshakeLength := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
		if handshakeLength > len(payload)-4 {
			if allowIncomplete {
				return readResult{result: result}, true
			}
			result.Status = StatusInconclusive
			result = withError(result, ErrorCodeIncompleteHandshake, "incomplete handshake message")
			return readResult{result: result}, false
		}
		body := payload[4 : 4+handshakeLength]
		payload = payload[4+handshakeLength:]

		if handshakeType != 2 {
			continue
		}
		return parseServerHello(body, result), false
	}

	if allowIncomplete {
		return readResult{result: result}, true
	}
	result.Status = StatusInconclusive
	result = withError(result, ErrorCodeServerHelloNotFound, "ServerHello not found")
	return readResult{result: result}, false
}

func parseServerHello(body []byte, result Result) readResult {
	if len(body) < 38 {
		result.Status = StatusInconclusive
		result = withError(result, ErrorCodeServerHelloTooShort, "ServerHello is too short")
		return readResult{result: result}
	}

	if bytes.Equal(body[2:34], helloRetryRequestRandom) {
		result.Status = StatusHelloRetryRequest
		result.HelloRetryRequest = true
		hrr, err := parseHelloRetryRequest(body)
		if err != nil {
			result = withError(result, ErrorCodeMalformedHRR, err.Error())
		}
		if hrr != nil {
			result.SelectedGroup = hrr.selectedGroup
			result.SelectedGroupName = keyShareGroupName(hrr.selectedGroup)
		}
		return readResult{result: result, hrr: hrr}
	}

	offset := 34
	sessionIDLength := int(body[offset])
	offset++
	if offset+sessionIDLength+3 > len(body) {
		result.Status = StatusInconclusive
		result = withError(result, ErrorCodeServerHelloTruncated, "ServerHello session ID is truncated")
		return readResult{result: result}
	}
	offset += sessionIDLength

	selectedCipher := binary.BigEndian.Uint16(body[offset : offset+2])
	offset += 2
	if offset >= len(body) {
		result.Status = StatusInconclusive
		result = withError(result, ErrorCodeCompressionMissing, "ServerHello compression method is missing")
		return readResult{result: result}
	}
	offset++
	if offset+2 <= len(body) {
		selectedGroup, err := parseServerHelloSelectedGroup(body[offset:])
		if err == nil && selectedGroup != 0 {
			result.SelectedGroup = selectedGroup
			result.SelectedGroupName = keyShareGroupName(selectedGroup)
		}
	}
	if selectedCipher == result.CipherSuite {
		result.Status = StatusSupported
		return readResult{result: result}
	}

	result.Status = StatusRejected
	result = withError(result, ErrorCodeRejectedCipher, fmt.Sprintf("server selected %s", CipherSuiteName(selectedCipher)))
	return readResult{result: result}
}

func withError(result Result, code ErrorCode, message string) Result {
	result.ErrorCode = code
	result.Error = message
	return result
}

func hrrErrorCode(err error) ErrorCode {
	if err == nil {
		return ""
	}
	if strings.Contains(err.Error(), "unsupported group") {
		return ErrorCodeUnsupportedHRRGroup
	}
	return ErrorCodeMalformedHRR
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
	switch group {
	case GroupX25519, GroupP256, GroupP384, GroupP521:
		return true
	default:
		return false
	}
}

func isAllowedKeyShareGroup(group uint16, groups []uint16) bool {
	for _, allowed := range groups {
		if group == allowed {
			return true
		}
	}
	return false
}

func defaultKeyShareGroups() []uint16 {
	return []uint16{GroupX25519, GroupP256, GroupP384, GroupP521}
}

func normalizedKeyShareGroups(opts Options) []uint16 {
	if len(opts.KeyShareGroups) == 0 {
		return defaultKeyShareGroups()
	}
	return append([]uint16(nil), opts.KeyShareGroups...)
}

func keyShareGroupName(group uint16) string {
	switch group {
	case GroupX25519:
		return "X25519"
	case GroupP256:
		return "P-256"
	case GroupP384:
		return "P-384"
	case GroupP521:
		return "P-521"
	case 0:
		return ""
	default:
		return fmt.Sprintf("0x%04x", group)
	}
}

func parseServerHelloSelectedGroup(data []byte) (uint16, error) {
	if len(data) < 2 {
		return 0, errors.New("ServerHello extensions are missing")
	}
	extensionsLength := int(binary.BigEndian.Uint16(data[0:2]))
	data = data[2:]
	if extensionsLength > len(data) {
		return 0, errors.New("ServerHello extensions are truncated")
	}
	extensions := data[:extensionsLength]
	for len(extensions) > 0 {
		if len(extensions) < 4 {
			return 0, errors.New("ServerHello extension header is truncated")
		}
		extensionType := binary.BigEndian.Uint16(extensions[0:2])
		extensionLength := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if extensionLength > len(extensions) {
			return 0, errors.New("ServerHello extension data is truncated")
		}
		extensionData := extensions[:extensionLength]
		extensions = extensions[extensionLength:]
		if extensionType != extensionKeyShare {
			continue
		}
		if len(extensionData) < 2 {
			return 0, errors.New("ServerHello key_share extension is malformed")
		}
		return binary.BigEndian.Uint16(extensionData[0:2]), nil
	}
	return 0, nil
}

func statusForNetworkError(err error) Status {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return StatusClosed
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StatusTimeout
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "connection reset by peer") ||
		strings.Contains(message, "use of closed network connection") {
		return StatusClosed
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

func alertCodes(payload []byte) (uint8, uint8) {
	if len(payload) < 2 {
		return 0, 0
	}
	return payload[0], payload[1]
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
