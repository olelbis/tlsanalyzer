package utils

import (
	"crypto/tls"
	"strings"
	"testing"
)

func TestCipherSuiteIDsForVersionOrdersByPreference(t *testing.T) {
	names := make(map[uint16]string, len(AllCipherSuites))
	for _, cs := range AllCipherSuites {
		names[cs.ID] = cs.Name
	}

	ids := CipherSuiteIDsForVersion(tls.VersionTLS12)
	if len(ids) == 0 {
		t.Fatal("no cipher suites returned for TLS 1.2")
	}

	seen := make(map[uint16]bool, len(ids))
	previousRank := -1
	for _, id := range ids {
		name, ok := names[id]
		if !ok {
			t.Fatalf("suite %#04x is not part of AllCipherSuites", id)
		}
		if seen[id] {
			t.Fatalf("suite %s listed twice", name)
		}
		seen[id] = true
		if !IsCipherSuiteCompatibleWith(tls.VersionTLS12, id) {
			t.Fatalf("suite %s cannot be negotiated with TLS 1.2", name)
		}
		rank := cipherPreferenceRank(name)
		if rank < previousRank {
			t.Fatalf("suite %s (rank %d) is listed after a less preferable suite (rank %d)", name, rank, previousRank)
		}
		previousRank = rank
	}

	if first := names[ids[0]]; !strings.HasPrefix(first, "TLS_ECDHE_") || strings.Contains(first, "_CBC_") {
		t.Errorf("first suite = %s, want a forward-secret AEAD suite", first)
	}
	if last := names[ids[len(ids)-1]]; !strings.Contains(last, "3DES") {
		t.Errorf("last suite = %s, want a 3DES suite", last)
	}
}

func TestCipherSuiteIDsForVersionTLS13(t *testing.T) {
	ids := CipherSuiteIDsForVersion(tls.VersionTLS13)
	if len(ids) != 3 {
		t.Fatalf("TLS 1.3 suites = %d, want 3", len(ids))
	}
	for _, id := range ids {
		if !IsCipherSuiteCompatibleWith(tls.VersionTLS13, id) {
			t.Fatalf("suite %#04x is not a TLS 1.3 suite", id)
		}
	}
}
