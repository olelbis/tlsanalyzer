package policy

import (
	"crypto/tls"
	"strings"
	"testing"
)

func TestMinimumScanVersion(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		requested uint16
		want      uint16
	}{
		{name: "no policy", config: Config{}, requested: tls.VersionTLS12, want: tls.VersionTLS12},
		{name: "forbidden below minimum extends the scan", config: Config{ForbiddenTLSVersions: []uint16{tls.VersionTLS10, tls.VersionTLS11}}, requested: tls.VersionTLS12, want: tls.VersionTLS10},
		{name: "forbidden at or above minimum keeps it", config: Config{ForbiddenTLSVersions: []uint16{tls.VersionTLS11}}, requested: tls.VersionTLS10, want: tls.VersionTLS10},
		{name: "required below minimum extends the scan", config: Config{RequiredTLSVersions: []uint16{tls.VersionTLS12}}, requested: tls.VersionTLS13, want: tls.VersionTLS12},
		{name: "explicit legacy-tls extends to TLS 1.0", config: Config{FailOn: []string{CheckLegacyTLS}}, requested: tls.VersionTLS13, want: tls.VersionTLS10},
		{name: "other fail-on checks do not extend", config: Config{FailOn: []string{CheckWeakCipher}}, requested: tls.VersionTLS12, want: tls.VersionTLS12},
		{name: "modern policy keeps --min-version authoritative", config: Config{Name: NameModern}, requested: tls.VersionTLS12, want: tls.VersionTLS12},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MinimumScanVersion(tt.config, tt.requested); got != tt.want {
				t.Fatalf("MinimumScanVersion() = %#04x, want %#04x", got, tt.want)
			}
		})
	}
}

func TestScanRangeNotes(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		requested uint16
		wantNote  string // substring; empty means no note expected
	}{
		{name: "no policy", config: Config{}, requested: tls.VersionTLS12},
		{name: "modern with default minimum", config: Config{Name: NameModern}, requested: tls.VersionTLS10},
		{name: "modern with raised minimum", config: Config{Name: NameModern}, requested: tls.VersionTLS12, wantNote: "from TLS 1.2 upwards"},
		{name: "modern covered by forbidden TLS 1.0", config: Config{Name: NameModern, ForbiddenTLSVersions: []uint16{tls.VersionTLS10}}, requested: tls.VersionTLS12},
		{name: "modern partially covered", config: Config{Name: NameModern, ForbiddenTLSVersions: []uint16{tls.VersionTLS11}}, requested: tls.VersionTLS12, wantNote: "from TLS 1.1 upwards"},
		{name: "explicit legacy-tls is fully scanned", config: Config{FailOn: []string{CheckLegacyTLS}}, requested: tls.VersionTLS13},
		{name: "unrelated check", config: Config{FailOn: []string{CheckWeakCipher}}, requested: tls.VersionTLS13},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notes := ScanRangeNotes(tt.config, tt.requested)
			if tt.wantNote == "" {
				if len(notes) != 0 {
					t.Fatalf("notes = %v, want none", notes)
				}
				return
			}
			if len(notes) != 1 || !strings.Contains(notes[0], tt.wantNote) || !strings.Contains(notes[0], CheckLegacyTLS) {
				t.Fatalf("notes = %v, want one %s note containing %q", notes, CheckLegacyTLS, tt.wantNote)
			}
		})
	}
}
