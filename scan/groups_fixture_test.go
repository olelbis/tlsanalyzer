package scan

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/olelbis/tlsanalyzer/tlsprobe"
)

// groupFixtureServer imitates a TLS 1.3 server whose choice among the offered
// groups the test controls. A ClientHello that offers one group only is
// passed on to backend, a real crypto/tls server, so handshakes complete; any
// other ClientHello is answered with a HelloRetryRequest naming the group the
// fixture picks: the first offered group that is in preference, or the first
// offered group when followClient is set.
func groupFixtureServer(t *testing.T, backend string, preference []uint16, followClient bool) (host, port string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = listener.Close()
		wg.Wait()
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				record, offered, ok := readClientHelloGroups(conn)
				if !ok {
					return
				}
				if len(offered) == 1 {
					proxyToBackend(conn, backend, record)
					return
				}
				chosen, found := pickGroup(offered, preference, followClient)
				if !found {
					_, _ = conn.Write([]byte{21, 3, 3, 0, 2, 2, 40})
					return
				}
				_, _ = conn.Write(helloRetryRequestRecord(chosen))
			}()
		}
	}()

	host, port, err = net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split address: %v", err)
	}
	return host, port
}

func pickGroup(offered, preference []uint16, followClient bool) (uint16, bool) {
	if followClient {
		for _, group := range offered {
			if containsGroupID(preference, group) {
				return group, true
			}
		}
		return 0, false
	}
	for _, group := range preference {
		if containsGroupID(offered, group) {
			return group, true
		}
	}
	return 0, false
}

func proxyToBackend(client net.Conn, backend string, firstRecord []byte) {
	upstream, err := net.Dial("tcp", backend)
	if err != nil {
		return
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := upstream.Write(firstRecord); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

// readClientHelloGroups reads the first TLS record and returns it together
// with the groups of the supported_groups extension, in order.
func readClientHelloGroups(conn net.Conn) (record []byte, groups []uint16, ok bool) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, nil, false
	}
	body := make([]byte, binary.BigEndian.Uint16(header[3:5]))
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, nil, false
	}
	record = append(header, body...)

	p := body
	skip := func(n int) bool {
		if len(p) < n {
			return false
		}
		p = p[n:]
		return true
	}
	vec8 := func() bool { return len(p) >= 1 && skip(1+int(p[0])) }
	vec16 := func() bool { return len(p) >= 2 && skip(2+int(binary.BigEndian.Uint16(p))) }
	// handshake header, legacy version, random, session id, suites, compression.
	if !skip(4+2+32) || !vec8() || !vec16() || !vec8() || len(p) < 2 {
		return nil, nil, false
	}
	extensions := p[2:]
	for len(extensions) >= 4 {
		kind := binary.BigEndian.Uint16(extensions)
		size := int(binary.BigEndian.Uint16(extensions[2:]))
		if len(extensions) < 4+size {
			return nil, nil, false
		}
		data := extensions[4 : 4+size]
		if kind == 0x000a && len(data) >= 2 {
			for list := data[2:]; len(list) >= 2; list = list[2:] {
				groups = append(groups, binary.BigEndian.Uint16(list))
			}
		}
		extensions = extensions[4+size:]
	}
	return record, groups, true
}

func helloRetryRequestRecord(group uint16) []byte {
	helloRetryRequestRandom := []byte{
		0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
		0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
	}
	var extensions []byte
	extensions = append(extensions, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)
	extensions = append(extensions, 0x00, 0x33, 0x00, 0x02, byte(group>>8), byte(group))

	body := []byte{0x03, 0x03}
	body = append(body, helloRetryRequestRandom...)
	body = append(body, 0)
	body = append(body, byte(tls.TLS_AES_128_GCM_SHA256>>8), byte(tls.TLS_AES_128_GCM_SHA256&0xff), 0)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)

	handshake := []byte{2, 0, byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := []byte{22, 3, 3, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}

func TestProbeKeyExchangeGroupsFixtureServerPreferences(t *testing.T) {
	backend, backendHost, backendPort := newLocalTLSServerWithConfig(t, &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	})
	defer backend.Close()
	backendAddress := net.JoinHostPort(backendHost, backendPort)

	const hybrid, x25519, p256 = 0x11ec, 0x001d, 0x0017
	tests := []struct {
		name         string
		preference   []uint16
		followClient bool
		want         string
	}{
		{"server prefers the hybrid", []uint16{hybrid, x25519, p256}, false, PreferencePostQuantum},
		{"server prefers a classical group", []uint16{x25519, hybrid, p256}, false, PreferenceClassical},
		{"server follows the client order", []uint16{hybrid, x25519, p256}, true, PreferenceClient},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port := groupFixtureServer(t, backendAddress, tt.preference, tt.followClient)
			result := ProbeKeyExchangeGroups(Options{Host: host, Port: port, Timeout: 3 * time.Second}, "")
			if result.Preference != tt.want {
				t.Fatalf("Preference = %q, want %q (groups %v, warnings %v)", result.Preference, tt.want, KeyExchangeGroupNames(result.Groups), result.Warnings)
			}
			for _, group := range result.Groups {
				if group.ID == hybrid && group.Evidence != GroupEvidenceHandshake {
					t.Errorf("hybrid evidence = %q, want %q", group.Evidence, GroupEvidenceHandshake)
				}
			}
		})
	}
}

func TestProbeKeyExchangeGroupsPreferenceInconclusiveWhenProbesGoUnanswered(t *testing.T) {
	var result GroupProbeResult
	result.Groups = []KeyExchangeGroupResult{
		{ID: 0x11ec, Name: "X25519MLKEM768", PostQuantum: true, Evidence: GroupEvidenceHandshake},
		{ID: 0x001d, Name: "X25519", Evidence: GroupEvidenceHRR},
	}
	// Nothing listens here, so both preference probes fail to connect.
	result.probePreference(tlsprobe.Options{Address: "127.0.0.1:1", Timeout: 200 * time.Millisecond})
	if result.Preference != PreferenceInconclusive {
		t.Fatalf("Preference = %q, want %q", result.Preference, PreferenceInconclusive)
	}
	if !strings.Contains(strings.Join(result.Warnings, " "), "preference is unknown") {
		t.Fatalf("Warnings = %v, want the unanswered probes reported", result.Warnings)
	}
}
