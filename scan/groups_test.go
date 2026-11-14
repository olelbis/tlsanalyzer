package scan

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"
)

func TestProbeKeyExchangeGroupsFindsPostQuantumHybrid(t *testing.T) {
	server, host, port := newLocalTLSServerWithConfig(t, &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
	})
	defer server.Close()

	result := ProbeKeyExchangeGroups(Options{Host: host, Port: port, Timeout: 3 * time.Second}, "X25519MLKEM768")

	got := strings.Join(KeyExchangeGroupNames(result.Groups), ",")
	for _, want := range []string{"X25519MLKEM768", "X25519", "P-256"} {
		if !strings.Contains(got, want) {
			t.Errorf("groups = %q, want it to contain %s", got, want)
		}
	}
	if len(result.Groups) != 3 || result.Incomplete {
		t.Fatalf("Groups = %v Incomplete = %t, want exactly three groups and a complete result", got, result.Incomplete)
	}
	if !result.HasPostQuantum() {
		t.Fatal("HasPostQuantum() = false for an endpoint that accepts X25519MLKEM768")
	}
	if result.Connections != 4 {
		t.Fatalf("Connections = %d, want 4 (three groups and the refusal)", result.Connections)
	}
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "ClientHello-only") {
		t.Fatalf("Warnings = %v, want one warning that the evidence is ClientHello-only", result.Warnings)
	}
	if rendered := FormatKeyExchangeGroups(result.Groups); !strings.Contains(rendered, "X25519MLKEM768 (post-quantum)") || strings.Contains(rendered, "P-256 (post-quantum)") {
		t.Fatalf("FormatKeyExchangeGroups() = %q, want only the hybrid marked post-quantum", rendered)
	}
}

func TestProbeKeyExchangeGroupsClassicalOnlyHasNoPostQuantum(t *testing.T) {
	server, host, port := newLocalTLSServerWithConfig(t, &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	})
	defer server.Close()

	result := ProbeKeyExchangeGroups(Options{Host: host, Port: port, Timeout: 3 * time.Second}, "X25519")
	if result.HasPostQuantum() || len(result.Groups) != 1 || result.Incomplete {
		t.Fatalf("result = %+v, want only X25519 and a complete result", result)
	}
}

// The version handshake is ground truth: if it negotiated a group the
// enumeration did not find, the enumeration cannot be trusted.
func TestProbeKeyExchangeGroupsContradictedByVersionHandshakeIsIncomplete(t *testing.T) {
	server, host, port := newLocalTLSServerWithConfig(t, &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	})
	defer server.Close()

	result := ProbeKeyExchangeGroups(Options{Host: host, Port: port, Timeout: 3 * time.Second}, "CurveP384")
	if !result.Incomplete {
		t.Fatal("Incomplete = false although the negotiated group is missing from the enumeration")
	}
	if !strings.Contains(strings.Join(result.Warnings, " "), "negotiated CurveP384 but the group enumeration did not find it") {
		t.Fatalf("Warnings = %v, want the contradiction explained", result.Warnings)
	}
}

func TestProbeKeyExchangeGroupsOnUnreachableEndpointIsIncomplete(t *testing.T) {
	result := ProbeKeyExchangeGroups(Options{Host: "127.0.0.1", Port: "1", Timeout: 200 * time.Millisecond}, "")
	if !result.Incomplete || len(result.Groups) != 0 {
		t.Fatalf("result = %+v, want an incomplete, empty result", result)
	}
	if !strings.Contains(strings.Join(result.Warnings, " "), "could not finish") {
		t.Fatalf("Warnings = %v, want the unfinished enumeration reported", result.Warnings)
	}
}

func TestGroupIDForCryptoTLSName(t *testing.T) {
	tests := map[string]uint16{
		"X25519":         0x001d,
		"CurveP256":      0x0017,
		"X25519MLKEM768": 0x11ec,
	}
	for name, want := range tests {
		got, ok := groupIDForCryptoTLSName(name)
		if !ok || got != want {
			t.Errorf("groupIDForCryptoTLSName(%q) = 0x%04x, %t, want 0x%04x", name, got, ok, want)
		}
	}
	for _, name := range []string{"", "NotAGroup"} {
		if _, ok := groupIDForCryptoTLSName(name); ok {
			t.Errorf("groupIDForCryptoTLSName(%q) matched", name)
		}
	}
}
