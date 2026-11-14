package starttls

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// script serves one connection with fn and returns the client side.
func script(t *testing.T, fn func(r *bufio.Reader, w net.Conn)) net.Conn {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		fn(bufio.NewReader(conn), conn)
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func send(w net.Conn, s string) { _, _ = w.Write([]byte(s)) }

func expectLine(t *testing.T, r *bufio.Reader, prefix string) {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Errorf("server read: %v", err)
		return
	}
	if !strings.HasPrefix(line, prefix) {
		t.Errorf("client sent %q, want prefix %q", line, prefix)
	}
}

// readMarker reads what follows the upgrade and checks that Upgrade consumed
// nothing of it.
func readMarker(t *testing.T, conn net.Conn, want string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if string(got) != want {
		t.Fatalf("bytes after the upgrade = %q, want %q", got, want)
	}
}

func TestUpgradeSMTP(t *testing.T) {
	client := script(t, func(r *bufio.Reader, w net.Conn) {
		send(w, "220-mail.example ESMTP\r\n220 ready\r\n")
		expectLine(t, r, "EHLO ")
		send(w, "250-mail.example\r\n250-SIZE 35882577\r\n250-starttls\r\n250 8BITMIME\r\n")
		expectLine(t, r, "STARTTLS")
		send(w, "220 2.0.0 Ready to start TLS\r\nTLSBYTES")
	})
	if err := Upgrade(client, SMTP, 2*time.Second); err != nil {
		t.Fatalf("Upgrade() = %v", err)
	}
	readMarker(t, client, "TLSBYTES")
}

func TestUpgradeSMTPFailures(t *testing.T) {
	tests := []struct {
		name   string
		server func(r *bufio.Reader, w net.Conn)
		want   string
	}{
		{"not offered", func(r *bufio.Reader, w net.Conn) {
			send(w, "220 ready\r\n")
			expectLine(t, r, "EHLO ")
			send(w, "250-mail\r\n250 SIZE 100\r\n")
		}, "does not offer STARTTLS"},
		{"refused greeting", func(r *bufio.Reader, w net.Conn) {
			send(w, "554 no service\r\n")
		}, "greeting was 554"},
		{"refused starttls", func(r *bufio.Reader, w net.Conn) {
			send(w, "220 ready\r\n")
			expectLine(t, r, "EHLO ")
			send(w, "250 STARTTLS\r\n")
			expectLine(t, r, "STARTTLS")
			send(w, "454 4.7.0 TLS not available\r\n")
		}, "refused with 454"},
		{"not smtp", func(r *bufio.Reader, w net.Conn) {
			send(w, "SSH-2.0-OpenSSH_9.0\r\n")
		}, "not an SMTP reply"},
		{"ehlo refused", func(r *bufio.Reader, w net.Conn) {
			send(w, "220 ready\r\n")
			expectLine(t, r, "EHLO ")
			send(w, "502 5.5.1 unknown command\r\n")
		}, "EHLO was refused with 502"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Upgrade(script(t, tt.server), SMTP, 2*time.Second)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Upgrade() = %v, want an error containing %q", err, tt.want)
			}
			if !IsError(err) {
				t.Fatalf("IsError(%v) = false", err)
			}
		})
	}
}

func TestUpgradeIMAP(t *testing.T) {
	client := script(t, func(r *bufio.Reader, w net.Conn) {
		send(w, "* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready.\r\n")
		expectLine(t, r, "a001 CAPABILITY")
		send(w, "* CAPABILITY IMAP4rev1 LITERAL+ STARTTLS LOGINDISABLED\r\na001 OK Pre-login capabilities listed\r\n")
		expectLine(t, r, "a002 STARTTLS")
		send(w, "a002 OK Begin TLS negotiation now.\r\nTLSBYTES")
	})
	if err := Upgrade(client, IMAP, 2*time.Second); err != nil {
		t.Fatalf("Upgrade() = %v", err)
	}
	readMarker(t, client, "TLSBYTES")
}

func TestUpgradeIMAPFailures(t *testing.T) {
	tests := []struct {
		name   string
		server func(r *bufio.Reader, w net.Conn)
		want   string
	}{
		{"not offered", func(r *bufio.Reader, w net.Conn) {
			send(w, "* OK ready\r\n")
			expectLine(t, r, "a001 CAPABILITY")
			send(w, "* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\na001 OK done\r\n")
		}, "does not offer STARTTLS"},
		{"bye", func(r *bufio.Reader, w net.Conn) {
			send(w, "* BYE go away\r\n")
		}, "want an untagged OK"},
		{"refused", func(r *bufio.Reader, w net.Conn) {
			send(w, "* OK ready\r\n")
			expectLine(t, r, "a001 CAPABILITY")
			send(w, "* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK done\r\n")
			expectLine(t, r, "a002 STARTTLS")
			send(w, "a002 NO TLS not available\r\n")
		}, "STARTTLS was refused"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Upgrade(script(t, tt.server), IMAP, 2*time.Second)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Upgrade() = %v, want an error containing %q", err, tt.want)
			}
		})
	}
}

func TestUpgradePOP3(t *testing.T) {
	client := script(t, func(r *bufio.Reader, w net.Conn) {
		send(w, "+OK POP3 ready\r\n")
		expectLine(t, r, "STLS")
		send(w, "+OK Begin TLS negotiation\r\nTLSBYTES")
	})
	if err := Upgrade(client, POP3, 2*time.Second); err != nil {
		t.Fatalf("Upgrade() = %v", err)
	}
	readMarker(t, client, "TLSBYTES")
}

func TestUpgradePOP3Refused(t *testing.T) {
	client := script(t, func(r *bufio.Reader, w net.Conn) {
		send(w, "+OK ready\r\n")
		expectLine(t, r, "STLS")
		send(w, "-ERR unknown command\r\n")
	})
	err := Upgrade(client, POP3, 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "STLS was refused") {
		t.Fatalf("Upgrade() = %v", err)
	}
}

func TestUpgradeTimesOutOnSilentServer(t *testing.T) {
	client := script(t, func(r *bufio.Reader, w net.Conn) {
		_, _ = r.ReadByte() // never answers, waits for the client
	})
	start := time.Now()
	err := Upgrade(client, SMTP, 200*time.Millisecond)
	if err == nil {
		t.Fatal("Upgrade() = nil, want a timeout")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("Upgrade() took %s, the timeout was not applied", time.Since(start))
	}
}

func TestUpgradeRejectsRunawayLine(t *testing.T) {
	client := script(t, func(r *bufio.Reader, w net.Conn) {
		send(w, strings.Repeat("A", maxLineBytes+10))
	})
	err := Upgrade(client, POP3, 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "line too long") {
		t.Fatalf("Upgrade() = %v, want a line-too-long error", err)
	}
}

func TestDialContextUpgradesAndClosesOnFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		for i := 0; ; i++ {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(i int, conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				send(conn, "+OK ready\r\n")
				_, _ = r.ReadString('\n')
				if i == 0 {
					send(conn, "+OK go\r\nTLSBYTES")
				} else {
					send(conn, "-ERR no\r\n")
				}
			}(i, conn)
		}
	}()

	dial := DialContext(POP3, 2*time.Second, nil)
	conn, err := dial(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("first dial = %v", err)
	}
	readMarker(t, conn, "TLSBYTES")
	_ = conn.Close()

	if conn, err = dial(context.Background(), "tcp", listener.Addr().String()); err == nil || !IsError(err) {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("second dial = %v, want a STARTTLS error", err)
	}
}

func TestParseAndDefaultPort(t *testing.T) {
	for name, port := range map[string]string{"smtp": "25", "IMAP": "143", " pop3 ": "110"} {
		p, err := Parse(name)
		if err != nil {
			t.Fatalf("Parse(%q) = %v", name, err)
		}
		if got := DefaultPort(p); got != port {
			t.Fatalf("DefaultPort(%s) = %q, want %q", p, got, port)
		}
	}
	if _, err := Parse("ftp"); err == nil || !strings.Contains(err.Error(), "smtp, imap, pop3") {
		t.Fatalf("Parse(ftp) = %v, want an error listing the protocols", err)
	}
	if _, err := Parse(""); err == nil {
		t.Fatal("Parse(\"\") should fail: empty means no STARTTLS and is handled by the caller")
	}
}
