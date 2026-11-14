// Package starttls performs the plaintext part of a STARTTLS upgrade for the
// mail protocols tlsanalyzer can scan: SMTP, IMAP and POP3.
//
// Upgrade runs the protocol dialogue on an already open TCP connection and
// returns once the server has agreed to start TLS. The next bytes on the
// connection belong to the TLS handshake, so the caller can hand it to
// crypto/tls or to a raw ClientHello probe unchanged.
//
// Nothing here is a mail client: no authentication is attempted and no mail is
// sent. The dialogue stops at the server's agreement to start TLS.
package starttls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Protocol is an application protocol that can be upgraded with STARTTLS.
type Protocol string

const (
	SMTP Protocol = "smtp"
	IMAP Protocol = "imap"
	POP3 Protocol = "pop3"
)

// ehloName is announced in SMTP EHLO. It is syntactically a domain name and
// uses a TLD reserved by RFC 6761, so it cannot belong to anybody.
const ehloName = "tlsanalyzer.invalid"

const (
	maxLineBytes = 8192
	maxLines     = 200
)

// Protocols returns the supported protocols.
func Protocols() []Protocol {
	return []Protocol{SMTP, IMAP, POP3}
}

// Parse converts a user supplied name to a Protocol. The empty string is not a
// protocol: callers use it to mean "no STARTTLS".
func Parse(name string) (Protocol, error) {
	p := Protocol(strings.ToLower(strings.TrimSpace(name)))
	for _, known := range Protocols() {
		if p == known {
			return p, nil
		}
	}
	names := make([]string, 0, len(Protocols()))
	for _, known := range Protocols() {
		names = append(names, string(known))
	}
	return "", fmt.Errorf("unsupported STARTTLS protocol %q; use one of: %s", name, strings.Join(names, ", "))
}

// DefaultPort returns the port a protocol uses for STARTTLS when none is given:
// 25 for SMTP, 143 for IMAP and 110 for POP3. SMTP submission usually listens
// on 587, which has to be passed explicitly.
func DefaultPort(p Protocol) string {
	switch p {
	case SMTP:
		return "25"
	case IMAP:
		return "143"
	case POP3:
		return "110"
	}
	return ""
}

// Error describes a failed STARTTLS negotiation. It is never a TLS failure:
// the server did not get as far as a handshake.
type Error struct {
	Protocol Protocol
	Message  string
	Err      error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("starttls %s: %s: %v", e.Protocol, e.Message, e.Err)
	}
	return fmt.Sprintf("starttls %s: %s", e.Protocol, e.Message)
}

func (e *Error) Unwrap() error { return e.Err }

// IsError reports whether err is, or wraps, a STARTTLS negotiation failure.
func IsError(err error) bool {
	var target *Error
	return errors.As(err, &target)
}

// Upgrade runs the STARTTLS dialogue for p on conn. The whole dialogue has to
// finish within timeout. On success the connection is positioned right after
// the server's agreement, with no byte read past it.
func Upgrade(conn net.Conn, p Protocol, timeout time.Duration) error {
	if timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return &Error{Protocol: p, Message: "set deadline", Err: err}
		}
		defer func() { _ = conn.SetDeadline(time.Time{}) }()
	}
	switch p {
	case SMTP:
		return upgradeSMTP(conn)
	case IMAP:
		return upgradeIMAP(conn)
	case POP3:
		return upgradePOP3(conn)
	}
	return &Error{Protocol: p, Message: "unsupported protocol"}
}

// DialContext returns a dial function that connects with base (net.Dialer when
// nil) and upgrades every connection with STARTTLS before returning it.
func DialContext(p Protocol, timeout time.Duration, base func(ctx context.Context, network, address string) (net.Conn, error)) func(ctx context.Context, network, address string) (net.Conn, error) {
	if base == nil {
		dialer := net.Dialer{Timeout: timeout}
		base = dialer.DialContext
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := base(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if err := Upgrade(conn, p, timeout); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

// readLine reads one CRLF or LF terminated line one byte at a time. Reading
// byte by byte guarantees that nothing past the line, such as the first bytes
// of the TLS handshake, is consumed.
func readLine(conn net.Conn) (string, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := conn.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				return strings.TrimRight(string(line), "\r"), nil
			}
			line = append(line, buf[0])
			if len(line) > maxLineBytes {
				return "", errors.New("line too long")
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return strings.TrimRight(string(line), "\r"), nil
			}
			return "", err
		}
	}
}

func writeLine(conn net.Conn, line string) error {
	_, err := conn.Write([]byte(line + "\r\n"))
	return err
}

// smtpReply reads one possibly multi-line SMTP reply (RFC 5321 section 4.2).
// It returns the three digit code and every line of text.
func smtpReply(conn net.Conn) (int, []string, error) {
	var lines []string
	code := 0
	for i := 0; i < maxLines; i++ {
		line, err := readLine(conn)
		if err != nil {
			return 0, nil, err
		}
		if len(line) < 3 || !isDigits(line[:3]) {
			return 0, nil, fmt.Errorf("not an SMTP reply: %q", truncate(line))
		}
		n := int(line[0]-'0')*100 + int(line[1]-'0')*10 + int(line[2]-'0')
		if code != 0 && n != code {
			return 0, nil, fmt.Errorf("reply code changed from %d to %d inside one reply", code, n)
		}
		code = n
		text := ""
		if len(line) > 4 {
			text = line[4:]
		}
		lines = append(lines, text)
		if len(line) == 3 || line[3] == ' ' {
			return code, lines, nil
		}
		if line[3] != '-' {
			return 0, nil, fmt.Errorf("not an SMTP reply: %q", truncate(line))
		}
	}
	return 0, nil, errors.New("reply has too many lines")
}

func upgradeSMTP(conn net.Conn) error {
	fail := func(msg string, err error) error { return &Error{Protocol: SMTP, Message: msg, Err: err} }

	code, lines, err := smtpReply(conn)
	if err != nil {
		return fail("read greeting", err)
	}
	if code != 220 {
		return fail(fmt.Sprintf("greeting was %d %s, want 220", code, truncate(strings.Join(lines, " "))), nil)
	}

	if err := writeLine(conn, "EHLO "+ehloName); err != nil {
		return fail("send EHLO", err)
	}
	code, lines, err = smtpReply(conn)
	if err != nil {
		return fail("read EHLO reply", err)
	}
	if code != 250 {
		return fail(fmt.Sprintf("EHLO was refused with %d %s", code, truncate(strings.Join(lines, " "))), nil)
	}
	offered := false
	for _, line := range lines {
		if strings.EqualFold(strings.TrimSpace(line), "STARTTLS") {
			offered = true
		}
	}
	if !offered {
		return fail("the server does not offer STARTTLS", nil)
	}

	if err := writeLine(conn, "STARTTLS"); err != nil {
		return fail("send STARTTLS", err)
	}
	code, lines, err = smtpReply(conn)
	if err != nil {
		return fail("read STARTTLS reply", err)
	}
	if code != 220 {
		return fail(fmt.Sprintf("STARTTLS was refused with %d %s", code, truncate(strings.Join(lines, " "))), nil)
	}
	return nil
}

// imapTagged reads lines until the one that carries tag and returns the
// untagged lines before it and the tagged status line.
func imapTagged(conn net.Conn, tag string) ([]string, string, error) {
	var untagged []string
	for i := 0; i < maxLines; i++ {
		line, err := readLine(conn)
		if err != nil {
			return nil, "", err
		}
		if strings.HasPrefix(line, tag+" ") {
			return untagged, strings.TrimPrefix(line, tag+" "), nil
		}
		untagged = append(untagged, line)
	}
	return nil, "", errors.New("reply has too many lines")
}

func upgradeIMAP(conn net.Conn) error {
	fail := func(msg string, err error) error { return &Error{Protocol: IMAP, Message: msg, Err: err} }

	greeting, err := readLine(conn)
	if err != nil {
		return fail("read greeting", err)
	}
	upper := strings.ToUpper(greeting)
	if !strings.HasPrefix(upper, "* OK") {
		return fail(fmt.Sprintf("greeting was %q, want an untagged OK", truncate(greeting)), nil)
	}

	if err := writeLine(conn, "a001 CAPABILITY"); err != nil {
		return fail("send CAPABILITY", err)
	}
	untagged, status, err := imapTagged(conn, "a001")
	if err != nil {
		return fail("read CAPABILITY reply", err)
	}
	if !strings.HasPrefix(strings.ToUpper(status), "OK") {
		return fail(fmt.Sprintf("CAPABILITY failed: %s", truncate(status)), nil)
	}
	offered := false
	for _, line := range untagged {
		fields := strings.Fields(strings.ToUpper(line))
		if len(fields) >= 2 && fields[0] == "*" && fields[1] == "CAPABILITY" {
			for _, capability := range fields[2:] {
				if capability == "STARTTLS" {
					offered = true
				}
			}
		}
	}
	if !offered {
		return fail("the server does not offer STARTTLS", nil)
	}

	if err := writeLine(conn, "a002 STARTTLS"); err != nil {
		return fail("send STARTTLS", err)
	}
	_, status, err = imapTagged(conn, "a002")
	if err != nil {
		return fail("read STARTTLS reply", err)
	}
	if !strings.HasPrefix(strings.ToUpper(status), "OK") {
		return fail(fmt.Sprintf("STARTTLS was refused: %s", truncate(status)), nil)
	}
	return nil
}

func upgradePOP3(conn net.Conn) error {
	fail := func(msg string, err error) error { return &Error{Protocol: POP3, Message: msg, Err: err} }

	greeting, err := readLine(conn)
	if err != nil {
		return fail("read greeting", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		return fail(fmt.Sprintf("greeting was %q, want +OK", truncate(greeting)), nil)
	}
	if err := writeLine(conn, "STLS"); err != nil {
		return fail("send STLS", err)
	}
	reply, err := readLine(conn)
	if err != nil {
		return fail("read STLS reply", err)
	}
	if !strings.HasPrefix(reply, "+OK") {
		return fail(fmt.Sprintf("STLS was refused: %s", truncate(reply)), nil)
	}
	return nil
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func truncate(s string) string {
	const limit = 120
	if len(s) > limit {
		return s[:limit] + "..."
	}
	return s
}
