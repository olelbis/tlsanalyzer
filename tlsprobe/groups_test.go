package tlsprobe

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func groupIDs(enumeration GroupEnumeration) map[uint16]bool {
	ids := make(map[uint16]bool)
	for _, group := range enumeration.Supported {
		ids[group.ID] = true
	}
	return ids
}

func TestKeyExchangeGroupCatalogIsConsistent(t *testing.T) {
	seenID := make(map[uint16]bool)
	seenName := make(map[string]bool)
	postQuantum := 0
	for _, group := range KeyExchangeGroups() {
		if seenID[group.ID] {
			t.Errorf("duplicate group ID 0x%04x", group.ID)
		}
		if seenName[group.Name] {
			t.Errorf("duplicate group name %q", group.Name)
		}
		seenID[group.ID], seenName[group.Name] = true, true
		if group.Name == "" {
			t.Errorf("group 0x%04x has no name", group.ID)
		}
		if got := keyShareGroupName(group.ID); got != group.Name {
			t.Errorf("keyShareGroupName(0x%04x) = %q, want %q", group.ID, got, group.Name)
		}
		if group.PostQuantum {
			postQuantum++
		}
	}
	// The probe already reports its four key share groups under these names.
	for id, want := range map[uint16]string{GroupX25519: "X25519", GroupP256: "P-256", GroupP384: "P-384", GroupP521: "P-521"} {
		if got, _ := catalogGroupName(id); got != want {
			t.Errorf("catalog name of 0x%04x = %q, want %q", id, got, want)
		}
	}
	for id, want := range map[uint16]bool{GroupX25519MLKEM768: true, GroupSecP256r1MLKEM768: true, GroupMLKEM768: true, GroupX25519: false, GroupFFDHE2048: false, 0x7777: false} {
		if got := IsPostQuantumGroup(id); got != want {
			t.Errorf("IsPostQuantumGroup(0x%04x) = %t, want %t", id, got, want)
		}
	}
	if postQuantum == 0 {
		t.Fatal("the catalog has no post-quantum group")
	}
	if got := keyShareGroupName(0x7777); got != "0x7777" {
		t.Errorf("keyShareGroupName(unknown) = %q, want hex", got)
	}
	if len(KeyExchangeGroupIDs()) != len(KeyExchangeGroups()) {
		t.Error("KeyExchangeGroupIDs and KeyExchangeGroups disagree")
	}
}

func TestKeyExchangeGroupsReturnsIndependentCopy(t *testing.T) {
	groups := KeyExchangeGroups()
	groups[0].Name = "changed"
	if KeyExchangeGroups()[0].Name == "changed" {
		t.Fatal("KeyExchangeGroups returned the catalog itself")
	}
}

func TestBuildTLS13ClientHelloWithEmptyKeyShareOffersGroupsAndAllSuites(t *testing.T) {
	record, err := buildTLS13ClientHello(clientHelloSpec{
		opts:          Options{ServerName: "example.test"},
		cipherSuites:  []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256},
		sessionID:     make([]byte, 32),
		groups:        []uint16{GroupX25519MLKEM768, GroupX25519},
		emptyKeyShare: true,
	})
	if err != nil {
		t.Fatalf("buildTLS13ClientHello() error = %v", err)
	}

	offset := 5 + 4 + 2 + 32
	offset += 1 + int(record[offset])
	if got := binary.BigEndian.Uint16(record[offset : offset+2]); got != 6 {
		t.Fatalf("cipher_suites length = %d, want three suites", got)
	}
	offset += 2 + 6 + 2 // suites, then compression methods
	extensionsLength := int(binary.BigEndian.Uint16(record[offset : offset+2]))
	extensions := record[offset+2 : offset+2+extensionsLength]

	found := make(map[uint16][]byte)
	for len(extensions) >= 4 {
		length := int(binary.BigEndian.Uint16(extensions[2:4]))
		found[binary.BigEndian.Uint16(extensions[0:2])] = extensions[4 : 4+length]
		extensions = extensions[4+length:]
	}
	if keyShare, ok := found[extensionKeyShare]; !ok || len(keyShare) != 2 || keyShare[0] != 0 || keyShare[1] != 0 {
		t.Fatalf("key_share extension = % x, want an empty client_shares list (00 00)", keyShare)
	}
	groups := found[extensionSupportedGroups]
	if len(groups) != 2+4 || binary.BigEndian.Uint16(groups[2:4]) != GroupX25519MLKEM768 || binary.BigEndian.Uint16(groups[4:6]) != GroupX25519 {
		t.Fatalf("supported_groups = % x, want the two offered groups in order", groups)
	}
}

func TestEnumerateTLS13GroupsAgainstCryptoTLS(t *testing.T) {
	address := confTLS13Server(t, confCert(t, "rsa"), []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256})

	enumeration, err := EnumerateTLS13Groups(context.Background(), Options{Address: address, ServerName: "localhost", Timeout: 3 * time.Second}, KeyExchangeGroupIDs())
	if err != nil {
		t.Fatalf("EnumerateTLS13Groups() error = %v", err)
	}

	want := map[uint16]bool{GroupX25519MLKEM768: true, GroupX25519: true, GroupP256: true}
	got := groupIDs(enumeration)
	if len(got) != len(want) {
		t.Fatalf("Supported = %+v, want exactly X25519MLKEM768, X25519 and P-256", enumeration.Supported)
	}
	for id := range want {
		if !got[id] {
			t.Errorf("group 0x%04x not found in %+v", id, enumeration.Supported)
		}
	}
	if !enumeration.Complete || len(enumeration.Unresolved) != 0 {
		t.Fatalf("Complete = %t Unresolved = %v, want a complete enumeration", enumeration.Complete, enumeration.Unresolved)
	}
	// Three groups and the refusal: the cost does not depend on the catalog size.
	if enumeration.Connections != 4 {
		t.Fatalf("Connections = %d, want 4", enumeration.Connections)
	}
	for _, group := range enumeration.Supported {
		if group.ID == GroupX25519MLKEM768 && !group.PostQuantum {
			t.Error("X25519MLKEM768 is not marked post-quantum")
		}
	}
}

func TestEnumerateTLS13GroupsServerWithoutCommonGroup(t *testing.T) {
	address := confTLS13Server(t, confCert(t, "rsa"), []tls.CurveID{tls.CurveP521})

	enumeration, err := EnumerateTLS13Groups(context.Background(), Options{Address: address, Timeout: 3 * time.Second}, []uint16{GroupX25519, GroupP256})
	if err != nil {
		t.Fatalf("EnumerateTLS13Groups() error = %v", err)
	}
	if !enumeration.Complete || len(enumeration.Supported) != 0 || enumeration.Connections != 1 {
		t.Fatalf("enumeration = %+v, want one connection and an alert-ended, complete, empty result", enumeration)
	}
	if enumeration.Last.Status != StatusAlert {
		t.Fatalf("Last.Status = %q, want %q", enumeration.Last.Status, StatusAlert)
	}
}

func TestEnumerateTLS13GroupsIgnoresDuplicates(t *testing.T) {
	address := confTLS13Server(t, confCert(t, "rsa"), []tls.CurveID{tls.X25519})
	enumeration, err := EnumerateTLS13Groups(context.Background(), Options{Address: address, Timeout: 3 * time.Second}, []uint16{GroupX25519, GroupX25519, GroupP256})
	if err != nil {
		t.Fatalf("EnumerateTLS13Groups() error = %v", err)
	}
	if len(enumeration.Supported) != 1 || enumeration.Supported[0].ID != GroupX25519 || enumeration.Connections != 2 {
		t.Fatalf("enumeration = %+v, want X25519 once in two connections", enumeration)
	}
}

func TestEnumerateTLS13GroupsAcceptsClosedConnectionAsRefusal(t *testing.T) {
	shortenLegacyRetryPause(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = readTLSRecord(conn)
			conn.Close()
		}
	}()

	enumeration, err := EnumerateTLS13Groups(context.Background(), Options{Address: listener.Addr().String(), Timeout: time.Second}, []uint16{GroupX25519, GroupP256})
	if err != nil {
		t.Fatalf("EnumerateTLS13Groups() error = %v", err)
	}
	if !enumeration.Complete || len(enumeration.Supported) != 0 || enumeration.Last.Status != StatusClosed || enumeration.Connections != 1+legacyEnumerationRetries {
		t.Fatalf("enumeration = %+v, want a complete empty result after %d closed connections", enumeration, 1+legacyEnumerationRetries)
	}
}

func TestEnumerateTLS13GroupsGivesUpOnSilentServer(t *testing.T) {
	shortenLegacyRetryPause(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	// The connections are held open and never answered; the accept goroutine
	// and the cleanup share the list.
	var (
		mu   sync.Mutex
		held []net.Conn
	)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()
	defer func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range held {
			conn.Close()
		}
	}()

	groups := []uint16{GroupX25519, GroupP256, GroupP384}
	enumeration, err := EnumerateTLS13Groups(context.Background(), Options{Address: listener.Addr().String(), Timeout: 100 * time.Millisecond}, groups)
	if err != nil {
		t.Fatalf("EnumerateTLS13Groups() error = %v", err)
	}
	if enumeration.Complete || len(enumeration.Unresolved) != len(groups) || enumeration.Last.Status != StatusTimeout {
		t.Fatalf("enumeration = %+v, want an unresolved result after timeouts", enumeration)
	}
}

// helloRetryRequestFixtureServer answers every ClientHello with a
// HelloRetryRequest that names group.
func helloRetryRequestFixtureServer(t *testing.T, group uint16) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	var body []byte
	body = appendUint16(body, 0x0303)
	body = append(body, helloRetryRequestRandom...)
	body = appendOpaque8(body, nil)
	body = appendUint16(body, tls.TLS_AES_128_GCM_SHA256)
	body = append(body, 0)
	var extensions []byte
	extensions = appendExtension(extensions, extensionSupportedVersions, []byte{0x03, 0x04})
	extensions = appendExtension(extensions, extensionKeyShare, appendUint16(nil, group))
	body = appendOpaque16(body, extensions)
	handshake := append([]byte{2}, appendUint24(nil, len(body))...)
	handshake = append(handshake, body...)
	record := append([]byte{22, 0x03, 0x03}, appendUint16(nil, uint16(len(handshake)))...)
	record = append(record, handshake...)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = readTLSRecord(conn)
				_, _ = conn.Write(record)
			}()
		}
	}()
	return listener.Addr().String()
}

func TestEnumerateTLS13GroupsDistrustsUnofferedGroup(t *testing.T) {
	address := helloRetryRequestFixtureServer(t, GroupP521)

	enumeration, err := EnumerateTLS13Groups(context.Background(), Options{Address: address, Timeout: time.Second}, []uint16{GroupX25519, GroupP256})
	if err != nil {
		t.Fatalf("EnumerateTLS13Groups() error = %v", err)
	}
	if enumeration.Complete || len(enumeration.Supported) != 0 || len(enumeration.Unresolved) != 2 {
		t.Fatalf("enumeration = %+v, want it to stop unresolved on a group that was not offered", enumeration)
	}
}

func TestEnumerateTLS13GroupsReportsSelectionFromFixture(t *testing.T) {
	address := helloRetryRequestFixtureServer(t, GroupP256)
	enumeration, err := EnumerateTLS13Groups(context.Background(), Options{Address: address, Timeout: time.Second}, []uint16{GroupX25519, GroupP256})
	if err != nil {
		t.Fatalf("EnumerateTLS13Groups() error = %v", err)
	}
	// The fixture keeps answering P-256, which is no longer offered on the
	// second round: that is a violation, not a second group.
	if len(enumeration.Supported) != 1 || enumeration.Supported[0].ID != GroupP256 || enumeration.Complete {
		t.Fatalf("enumeration = %+v, want P-256 found and the rest unresolved", enumeration)
	}
}

func TestEnumerateTLS13GroupsRejectsInvalidInputAndStopsWithContext(t *testing.T) {
	_, err := EnumerateTLS13Groups(context.Background(), Options{}, []uint16{GroupX25519})
	var configErr *ConfigError
	if !errors.As(err, &configErr) || configErr.Field != "address" {
		t.Fatalf("error = %v, want ConfigError for field address", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	enumeration, err := EnumerateTLS13Groups(ctx, Options{Address: "127.0.0.1:1"}, []uint16{GroupX25519, GroupP256})
	if !errors.Is(err, context.Canceled) || len(enumeration.Unresolved) != 2 || enumeration.Connections != 0 {
		t.Fatalf("enumeration = %+v error = %v, want context.Canceled before any connection", enumeration, err)
	}
}

func TestSelectTLS13GroupReportsServerChoice(t *testing.T) {
	address := helloRetryRequestFixtureServer(t, GroupP256)
	result := SelectTLS13Group(context.Background(), Options{Address: address, Timeout: time.Second}, []uint16{GroupX25519, GroupP256})
	if result.Status != StatusHelloRetryRequest || result.SelectedGroup != GroupP256 {
		t.Fatalf("result = %+v, want a HelloRetryRequest selecting P-256", result)
	}
}
