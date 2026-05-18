package tlsprobe

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbeTLS13CipherSuiteSupported(t *testing.T) {
	server := newTLS13TestServer(&tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	})
	defer server.Close()

	result, err := ProbeTLS13CipherSuite(context.Background(), Options{
		Address: server.Listener.Addr().String(),
		Timeout: time.Second,
	}, tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("ProbeTLS13CipherSuite() error = %v", err)
	}

	if result.Status != StatusSupported {
		t.Fatalf("Status = %q, want %q; alert %q error %q", result.Status, StatusSupported, result.Alert, result.Error)
	}
	if result.Name != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("Name = %q, want TLS_AES_128_GCM_SHA256", result.Name)
	}
}

func TestProbeTLS13CipherSuiteSendsSNI(t *testing.T) {
	const expectedServerName = "service.example.test"
	seenServerName := make(chan string, 1)
	server := newTLS13TestServer(&tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			seenServerName <- hello.ServerName
			return nil, nil
		},
	})
	defer server.Close()

	result, err := ProbeTLS13CipherSuite(context.Background(), Options{
		Address:    server.Listener.Addr().String(),
		ServerName: expectedServerName,
		Timeout:    time.Second,
	}, tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("ProbeTLS13CipherSuite() error = %v", err)
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

func TestProbeTLS13CipherSuiteReportsAlert(t *testing.T) {
	server := newTLS13TestServer(&tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	})
	defer server.Close()

	result, err := ProbeTLS13CipherSuite(context.Background(), Options{
		Address: server.Listener.Addr().String(),
		Timeout: time.Second,
	}, tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("ProbeTLS13CipherSuite() error = %v", err)
	}

	if result.Status != StatusAlert {
		t.Fatalf("Status = %q, want %q; alert %q error %q", result.Status, StatusAlert, result.Alert, result.Error)
	}
	if result.Alert == "" {
		t.Fatal("Alert should describe the TLS alert")
	}
}

func TestProbeTLS13CipherSuiteRetriesHelloRetryRequest(t *testing.T) {
	address, closeServer := newHelloRetryRequestFixtureServer(t, tls.TLS_AES_128_GCM_SHA256, groupP256)
	defer closeServer()

	result, err := ProbeTLS13CipherSuite(context.Background(), Options{
		Address: address,
		Timeout: time.Second,
	}, tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("ProbeTLS13CipherSuite() error = %v", err)
	}

	if result.Status != StatusSupported {
		t.Fatalf("Status = %q, want %q; alert %q error %q", result.Status, StatusSupported, result.Alert, result.Error)
	}
}

func TestProbeTLS13CipherSuiteKeepsHelloRetryRequestForUnsupportedGroup(t *testing.T) {
	const unsupportedGroup = 0x9999
	address, closeServer := newHelloRetryRequestOnlyFixtureServer(t, tls.TLS_AES_128_GCM_SHA256, unsupportedGroup)
	defer closeServer()

	result, err := ProbeTLS13CipherSuite(context.Background(), Options{
		Address: address,
		Timeout: time.Second,
	}, tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("ProbeTLS13CipherSuite() error = %v", err)
	}

	if result.Status != StatusHelloRetryRequest {
		t.Fatalf("Status = %q, want %q; alert %q error %q", result.Status, StatusHelloRetryRequest, result.Alert, result.Error)
	}
	if result.Error == "" {
		t.Fatal("Error should explain why the HelloRetryRequest was not retried")
	}
}

func TestProbeTLS13CipherSuiteReportsRejectedServerHello(t *testing.T) {
	address, closeServer := newServerHelloFixtureServer(t, tls.TLS_AES_256_GCM_SHA384)
	defer closeServer()

	result, err := ProbeTLS13CipherSuite(context.Background(), Options{
		Address: address,
		Timeout: time.Second,
	}, tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("ProbeTLS13CipherSuite() error = %v", err)
	}

	if result.Status != StatusRejected {
		t.Fatalf("Status = %q, want %q; alert %q error %q", result.Status, StatusRejected, result.Alert, result.Error)
	}
	if result.Error == "" {
		t.Fatal("Error should describe the selected cipher")
	}
}

func TestProbeTLS13CipherSuiteReportsClosedConnection(t *testing.T) {
	address, closeServer := newCloseOnlyFixtureServer(t)
	defer closeServer()

	result, err := ProbeTLS13CipherSuite(context.Background(), Options{
		Address: address,
		Timeout: time.Second,
	}, tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("ProbeTLS13CipherSuite() error = %v", err)
	}
	if result.Status != StatusClosed {
		t.Fatalf("Status = %q, want %q; error %q", result.Status, StatusClosed, result.Error)
	}
}

func TestProbeTLS13CipherSuiteReportsTimeout(t *testing.T) {
	address, closeServer := newIdleFixtureServer(t)
	defer closeServer()

	result, err := ProbeTLS13CipherSuite(context.Background(), Options{
		Address: address,
		Timeout: 20 * time.Millisecond,
	}, tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("ProbeTLS13CipherSuite() error = %v", err)
	}
	if result.Status != StatusTimeout {
		t.Fatalf("Status = %q, want %q; error %q", result.Status, StatusTimeout, result.Error)
	}
}

func TestProbeTLS13CipherSuitesReturnsOneResultPerCipher(t *testing.T) {
	server := newTLS13TestServer(&tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	})
	defer server.Close()

	results, err := ProbeTLS13CipherSuites(context.Background(), Options{
		Address: server.Listener.Addr().String(),
		Timeout: time.Second,
	}, []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384})
	if err != nil {
		t.Fatalf("ProbeTLS13CipherSuites() error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	for _, result := range results {
		if result.Status != StatusSupported {
			t.Fatalf("Status for %s = %q, want %q; alert %q error %q", result.Name, result.Status, StatusSupported, result.Alert, result.Error)
		}
	}
}

func TestProbeTLS13CipherSuitesReturnsConfigurationErrorBeforeDialing(t *testing.T) {
	results, err := ProbeTLS13CipherSuites(context.Background(), Options{}, []uint16{tls.TLS_AES_128_GCM_SHA256})
	if err == nil {
		t.Fatal("ProbeTLS13CipherSuites() error = nil, want address validation error")
	}
	if results != nil {
		t.Fatalf("results = %+v, want nil", results)
	}
}

func TestProbeTLS13CipherSuiteReturnsConfigurationErrorBeforeDialing(t *testing.T) {
	result, err := ProbeTLS13CipherSuite(context.Background(), Options{
		Address: "missing-port.example.test",
	}, tls.TLS_AES_128_GCM_SHA256)
	if err == nil {
		t.Fatal("ProbeTLS13CipherSuite() error = nil, want address validation error")
	}
	if result.Status != StatusInconclusive {
		t.Fatalf("Status = %q, want %q", result.Status, StatusInconclusive)
	}
}

func TestValidateOptionsRejectsInvalidAddress(t *testing.T) {
	tests := []struct {
		name string
		opts Options
	}{
		{
			name: "missing host",
			opts: Options{Address: ":443"},
		},
		{
			name: "missing port",
			opts: Options{Address: "example.com"},
		},
		{
			name: "non numeric port",
			opts: Options{Address: "example.com:https"},
		},
		{
			name: "port out of range",
			opts: Options{Address: "example.com:65536"},
		},
		{
			name: "leading whitespace",
			opts: Options{Address: " example.com:443"},
		},
		{
			name: "negative timeout",
			opts: Options{
				Address: "example.com:443",
				Timeout: -time.Second,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOptions(tt.opts)
			if err == nil {
				t.Fatal("ValidateOptions() error = nil, want validation error")
			}
			var configErr *ConfigError
			if !errors.As(err, &configErr) {
				t.Fatalf("ValidateOptions() error = %T, want *ConfigError", err)
			}
		})
	}
}

func TestValidateOptionsRejectsOverlongALPNProtocol(t *testing.T) {
	err := ValidateOptions(Options{
		Address: "127.0.0.1:443",
		ALPN:    []string{string(bytesOf(256, 'a'))},
	})
	if err == nil {
		t.Fatal("ValidateOptions() error = nil, want ALPN length error")
	}
}

func TestSupportedTLS13CipherSuitesReturnsIndependentCopy(t *testing.T) {
	first := SupportedTLS13CipherSuites()
	second := SupportedTLS13CipherSuites()
	if len(first) != 3 {
		t.Fatalf("len(SupportedTLS13CipherSuites()) = %d, want 3", len(first))
	}
	first[0] = 0
	if second[0] == 0 {
		t.Fatal("SupportedTLS13CipherSuites() returned shared mutable storage")
	}
}

func TestParseServerHelloFixtureSupported(t *testing.T) {
	sessionID := []byte("fixture-session")
	body := serverHelloBody(bytesOf(32, 0x42), sessionID, tls.TLS_AES_128_GCM_SHA256, nil)

	read := parseServerHello(body, Result{CipherSuite: tls.TLS_AES_128_GCM_SHA256})

	if read.result.Status != StatusSupported {
		t.Fatalf("Status = %q, want %q; error %q", read.result.Status, StatusSupported, read.result.Error)
	}
	if read.hrr != nil {
		t.Fatal("hrr should be nil for a normal ServerHello")
	}
}

func TestParseServerHelloFixtureRejected(t *testing.T) {
	body := serverHelloBody(bytesOf(32, 0x42), []byte("fixture-session"), tls.TLS_AES_256_GCM_SHA384, nil)

	read := parseServerHello(body, Result{CipherSuite: tls.TLS_AES_128_GCM_SHA256})

	if read.result.Status != StatusRejected {
		t.Fatalf("Status = %q, want %q; error %q", read.result.Status, StatusRejected, read.result.Error)
	}
	if read.result.Error == "" {
		t.Fatal("Error should describe the selected cipher")
	}
}

func TestParseServerHelloFixtureHelloRetryRequest(t *testing.T) {
	extensions := appendExtension(nil, extensionKeyShare, []byte{byte(groupP256 >> 8), byte(groupP256)})
	body := serverHelloBody(helloRetryRequestRandom, []byte("fixture-session"), tls.TLS_AES_128_GCM_SHA256, extensions)

	read := parseServerHello(body, Result{CipherSuite: tls.TLS_AES_128_GCM_SHA256})

	if read.result.Status != StatusHelloRetryRequest {
		t.Fatalf("Status = %q, want %q; error %q", read.result.Status, StatusHelloRetryRequest, read.result.Error)
	}
	if read.hrr == nil {
		t.Fatal("hrr = nil, want parsed HelloRetryRequest data")
	}
	if read.hrr.selectedGroup != groupP256 {
		t.Fatalf("selectedGroup = 0x%04x, want 0x%04x", read.hrr.selectedGroup, groupP256)
	}
}

func TestParseHandshakePayloadFixtureIncomplete(t *testing.T) {
	read := parseHandshakePayload([]byte{2, 0, 0, 8, 1, 2}, Result{})
	if read.result.Status != StatusInconclusive {
		t.Fatalf("Status = %q, want %q", read.result.Status, StatusInconclusive)
	}
	if read.result.Error != "incomplete handshake message" {
		t.Fatalf("Error = %q, want incomplete handshake message", read.result.Error)
	}
}

func TestReadProbeRecordFixtureUnexpectedRecordType(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		_, _ = server.Write([]byte{23, 3, 3, 0, 1, 0})
	}()

	read, err := readProbeRecord(client, Result{})
	if err != nil {
		t.Fatalf("readProbeRecord() error = %v", err)
	}
	if read.result.Status != StatusInconclusive {
		t.Fatalf("Status = %q, want %q", read.result.Status, StatusInconclusive)
	}
	if read.result.Error != "unexpected TLS record type 23" {
		t.Fatalf("Error = %q, want unexpected TLS record type 23", read.result.Error)
	}
	<-done
}

func TestParseHelloRetryRequestFixtureMalformedExtension(t *testing.T) {
	extensions := []byte{byte(extensionKeyShare >> 8), byte(extensionKeyShare), 0, 3, 0, byte(groupP256 >> 8), byte(groupP256)}
	body := serverHelloBody(helloRetryRequestRandom, []byte("fixture-session"), tls.TLS_AES_128_GCM_SHA256, extensions)

	hrr, err := parseHelloRetryRequest(body)
	if err == nil {
		t.Fatal("parseHelloRetryRequest() error = nil, want malformed extension error")
	}
	if hrr == nil {
		t.Fatal("parseHelloRetryRequest() hrr = nil, want partial result")
	}
}

func TestDescribeAlertFixture(t *testing.T) {
	if got := describeAlert([]byte{2, 40}); got != "fatal/handshake_failure" {
		t.Fatalf("describeAlert() = %q, want fatal/handshake_failure", got)
	}
}

func TestDescribeAlertFixtureMalformed(t *testing.T) {
	if got := describeAlert([]byte{2}); got != "malformed alert" {
		t.Fatalf("describeAlert() = %q, want malformed alert", got)
	}
}

func newTLS13TestServer(config *tls.Config) *httptest.Server {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	server := &httptest.Server{
		Listener: listener,
		TLS:      config,
		Config: &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}),
			ErrorLog: log.New(io.Discard, "", 0),
		},
	}
	server.StartTLS()
	return server
}

func serverHelloBody(randomBytes []byte, sessionID []byte, cipherSuite uint16, extensions []byte) []byte {
	var body []byte
	body = appendUint16(body, 0x0303)
	body = append(body, randomBytes...)
	body = appendOpaque8(body, sessionID)
	body = appendUint16(body, cipherSuite)
	body = append(body, 0)
	body = appendOpaque16(body, extensions)
	return body
}

func bytesOf(length int, value byte) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = value
	}
	return out
}

func newHelloRetryRequestFixtureServer(t *testing.T, cipherSuite uint16, selectedGroup uint16) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})

	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		if _, err := readTLSRecord(conn); err != nil {
			t.Errorf("read first ClientHello: %v", err)
			return
		}

		keyShareExtension := appendExtension(nil, extensionKeyShare, []byte{byte(selectedGroup >> 8), byte(selectedGroup)})
		hrr := serverHelloBody(helloRetryRequestRandom, nil, cipherSuite, keyShareExtension)
		if err := writeHandshakeRecord(conn, hrr); err != nil {
			t.Errorf("write HelloRetryRequest: %v", err)
			return
		}

		secondClientHello, err := readTLSRecord(conn)
		if err != nil {
			t.Errorf("read second ClientHello: %v", err)
			return
		}
		if !clientHelloIncludesKeyShareGroup(secondClientHello, selectedGroup) {
			t.Errorf("second ClientHello does not include requested key share group 0x%04x", selectedGroup)
			return
		}

		serverHello := serverHelloBody(bytesOf(32, 0x33), nil, cipherSuite, nil)
		if err := writeHandshakeRecord(conn, serverHello); err != nil {
			t.Errorf("write ServerHello: %v", err)
		}
	}()

	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
	}
}

func newHelloRetryRequestOnlyFixtureServer(t *testing.T, cipherSuite uint16, selectedGroup uint16) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})

	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		if _, err := readTLSRecord(conn); err != nil {
			t.Errorf("read ClientHello: %v", err)
			return
		}
		keyShareExtension := appendExtension(nil, extensionKeyShare, []byte{byte(selectedGroup >> 8), byte(selectedGroup)})
		hrr := serverHelloBody(helloRetryRequestRandom, nil, cipherSuite, keyShareExtension)
		if err := writeHandshakeRecord(conn, hrr); err != nil {
			t.Errorf("write HelloRetryRequest: %v", err)
		}
	}()

	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
	}
}

func newServerHelloFixtureServer(t *testing.T, cipherSuite uint16) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})

	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		if _, err := readTLSRecord(conn); err != nil {
			t.Errorf("read ClientHello: %v", err)
			return
		}
		serverHello := serverHelloBody(bytesOf(32, 0x44), nil, cipherSuite, nil)
		if err := writeHandshakeRecord(conn, serverHello); err != nil {
			t.Errorf("write ServerHello: %v", err)
		}
	}()

	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
	}
}

func newCloseOnlyFixtureServer(t *testing.T) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})

	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}()

	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
	}
}

func newIdleFixtureServer(t *testing.T) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})

	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = readTLSRecord(conn)
		time.Sleep(200 * time.Millisecond)
	}()

	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
	}
}

func readTLSRecord(conn net.Conn) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[3:5]))
	payload := make([]byte, length)
	_, err := io.ReadFull(conn, payload)
	return payload, err
}

func writeHandshakeRecord(conn net.Conn, body []byte) error {
	handshake := []byte{2}
	handshake = appendUint24(handshake, len(body))
	handshake = append(handshake, body...)

	record := []byte{22, 0x03, 0x03}
	record = appendUint16(record, uint16(len(handshake)))
	record = append(record, handshake...)
	_, err := conn.Write(record)
	return err
}

func clientHelloIncludesKeyShareGroup(recordPayload []byte, group uint16) bool {
	if len(recordPayload) < 4 || recordPayload[0] != 1 {
		return false
	}
	bodyLength := int(recordPayload[1])<<16 | int(recordPayload[2])<<8 | int(recordPayload[3])
	if bodyLength > len(recordPayload)-4 {
		return false
	}
	body := recordPayload[4 : 4+bodyLength]
	if len(body) < 38 {
		return false
	}

	offset := 34
	sessionIDLength := int(body[offset])
	offset++
	offset += sessionIDLength
	if offset+2 > len(body) {
		return false
	}
	cipherLength := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2 + cipherLength
	if offset >= len(body) {
		return false
	}
	compressionLength := int(body[offset])
	offset++
	offset += compressionLength
	if offset+2 > len(body) {
		return false
	}
	extensionsLength := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if offset+extensionsLength > len(body) {
		return false
	}

	extensions := body[offset : offset+extensionsLength]
	for len(extensions) >= 4 {
		extensionType := binary.BigEndian.Uint16(extensions[0:2])
		extensionLength := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if extensionLength > len(extensions) {
			return false
		}
		extensionData := extensions[:extensionLength]
		extensions = extensions[extensionLength:]
		if extensionType == extensionKeyShare {
			return keyShareExtensionIncludesGroup(extensionData, group)
		}
	}
	return false
}

func keyShareExtensionIncludesGroup(extensionData []byte, group uint16) bool {
	if len(extensionData) < 2 {
		return false
	}
	listLength := int(binary.BigEndian.Uint16(extensionData[:2]))
	extensionData = extensionData[2:]
	if listLength > len(extensionData) {
		return false
	}
	extensionData = extensionData[:listLength]
	for len(extensionData) >= 4 {
		currentGroup := binary.BigEndian.Uint16(extensionData[0:2])
		keyLength := int(binary.BigEndian.Uint16(extensionData[2:4]))
		extensionData = extensionData[4:]
		if keyLength > len(extensionData) {
			return false
		}
		if currentGroup == group {
			return true
		}
		extensionData = extensionData[keyLength:]
	}
	return false
}
