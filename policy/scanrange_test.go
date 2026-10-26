package policy

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/olelbis/tlsanalyzer/scan"
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

func TestEvaluateNotesIndeterminateGatedVersions(t *testing.T) {
	results := []scan.TLSScanResult{
		{Version: "TLS 1.0", VersionID: tls.VersionTLS10, Status: scan.ScanStatusTimeout},
		{Version: "TLS 1.1", VersionID: tls.VersionTLS11, Status: scan.ScanStatusNetworkError},
		{Version: "TLS 1.2", VersionID: tls.VersionTLS12, Status: scan.ScanStatusTimeout},
		{Version: "TLS 1.3", VersionID: tls.VersionTLS13, Supported: true, Status: scan.ScanStatusSupported},
	}

	t.Run("forbid-tls and legacy-tls", func(t *testing.T) {
		got := Evaluate(results, Config{
			ForbiddenTLSVersions: []uint16{tls.VersionTLS10},
			FailOn:               []string{CheckLegacyTLS},
		}, time.Now())
		if !got.Passed {
			t.Fatalf("notes must be informational, failures = %+v", got.Failures)
		}
		// TLS 1.0 (forbidden and legacy) and TLS 1.1 (legacy) are gated; TLS 1.2 is not.
		if len(got.Notes) != 2 || !strings.Contains(got.Notes[0], "TLS 1.0") || !strings.Contains(got.Notes[1], "TLS 1.1") {
			t.Fatalf("notes = %v, want notes for TLS 1.0 and TLS 1.1 only", got.Notes)
		}
	})

	t.Run("unrelated gate", func(t *testing.T) {
		got := Evaluate(results, Config{FailOn: []string{CheckWeakCipher}}, time.Now())
		if len(got.Notes) != 0 {
			t.Fatalf("notes = %v, want none", got.Notes)
		}
	})

	t.Run("definitive unsupported is not indeterminate", func(t *testing.T) {
		got := Evaluate([]scan.TLSScanResult{
			{Version: "TLS 1.0", VersionID: tls.VersionTLS10, Status: scan.ScanStatusUnsupported},
		}, Config{ForbiddenTLSVersions: []uint16{tls.VersionTLS10}}, time.Now())
		if len(got.Notes) != 0 {
			t.Fatalf("notes = %v, want none", got.Notes)
		}
	})
}
