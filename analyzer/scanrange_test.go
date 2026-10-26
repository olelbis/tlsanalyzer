package analyzer

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/olelbis/tlsanalyzer/policy"
	"github.com/olelbis/tlsanalyzer/scan"
)

// legacyRangeServer starts a TLS server that accepts TLS 1.0 through 1.3.
func legacyRangeServer(t *testing.T) (host, port string) {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS13}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)

	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split server address: %v", err)
	}
	return host, port
}

func supportedVersionsOf(results []scan.TLSScanResult) map[string]bool {
	out := make(map[string]bool)
	for _, r := range results {
		if r.Supported {
			out[r.Version] = true
		}
	}
	return out
}

func scanRangeOptions(host, port string, min uint16, cfg policy.Config) Options {
	return Options{
		Host:         host,
		Port:         port,
		Timeout:      3 * time.Second,
		MinVersion:   min,
		SkipVerify:   true,
		PolicyConfig: cfg,
	}
}

func hasFailure(res policy.Result, check string) bool {
	for _, f := range res.Failures {
		if f.Check == check {
			return true
		}
	}
	return false
}

func TestExplicitGatesExtendScanBelowMinVersion(t *testing.T) {
	host, port := legacyRangeServer(t)

	// Baseline: without a policy the scan honours --min-version.
	base, err := Run(scanRangeOptions(host, port, tls.VersionTLS12, policy.Config{}), Hooks{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	for _, r := range base.Results {
		if r.VersionID < tls.VersionTLS12 {
			t.Fatalf("scan without policy covered %s, want only TLS 1.2 and newer", r.Version)
		}
	}

	t.Run("forbid-tls below minimum", func(t *testing.T) {
		res, err := Run(scanRangeOptions(host, port, tls.VersionTLS12, policy.Config{
			ForbiddenTLSVersions: []uint16{tls.VersionTLS10},
		}), Hooks{})
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if !supportedVersionsOf(res.Results)["TLS 1.0"] {
			t.Skip("this Go version cannot serve/negotiate TLS 1.0")
		}
		if !hasFailure(res.Policy, policy.CheckForbiddenTLS) {
			t.Fatalf("policy failures = %+v, want %s", res.Policy.Failures, policy.CheckForbiddenTLS)
		}
	})

	t.Run("fail-on legacy-tls extends to TLS 1.0", func(t *testing.T) {
		res, err := Run(scanRangeOptions(host, port, tls.VersionTLS13, policy.Config{
			FailOn: []string{policy.CheckLegacyTLS},
		}), Hooks{})
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if !supportedVersionsOf(res.Results)["TLS 1.0"] {
			t.Skip("this Go version cannot serve/negotiate TLS 1.0")
		}
		if !hasFailure(res.Policy, policy.CheckLegacyTLS) {
			t.Fatalf("policy failures = %+v, want %s", res.Policy.Failures, policy.CheckLegacyTLS)
		}
	})

	t.Run("require-tls below minimum is evaluated", func(t *testing.T) {
		res, err := Run(scanRangeOptions(host, port, tls.VersionTLS13, policy.Config{
			RequiredTLSVersions: []uint16{tls.VersionTLS12},
		}), Hooks{})
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if !supportedVersionsOf(res.Results)["TLS 1.2"] {
			t.Fatalf("TLS 1.2 was not scanned or not supported: %+v", res.Results)
		}
		if hasFailure(res.Policy, policy.CheckRequiredTLS) {
			t.Fatalf("policy failures = %+v, want no required-tls failure", res.Policy.Failures)
		}
	})
}

func TestModernPolicyWithRaisedMinVersionReportsNote(t *testing.T) {
	host, port := legacyRangeServer(t)

	res, err := Run(scanRangeOptions(host, port, tls.VersionTLS12, policy.Config{Name: policy.NameModern}), Hooks{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	for _, r := range res.Results {
		if r.VersionID < tls.VersionTLS12 {
			t.Fatalf("modern policy must not extend the scan, got %s", r.Version)
		}
	}
	if len(res.Policy.Notes) != 1 || !strings.Contains(res.Policy.Notes[0], "TLS 1.2 upwards") {
		t.Fatalf("notes = %v, want one legacy-tls range note", res.Policy.Notes)
	}
}

func TestMergeNegotiatedCipher(t *testing.T) {
	tests := []struct {
		name       string
		suites     []string
		negotiated string
		want       []string
		wantMissed bool
	}{
		{name: "already present", suites: []string{"B", "A"}, negotiated: "A", want: []string{"B", "A"}},
		{name: "missing is added", suites: []string{"B"}, negotiated: "A", want: []string{"A", "B"}, wantMissed: true},
		{name: "empty probe", suites: nil, negotiated: "A", want: []string{"A"}, wantMissed: true},
		{name: "nothing negotiated", suites: []string{"B"}, negotiated: "", want: []string{"B"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, missed := mergeNegotiatedCipher(append([]string(nil), tt.suites...), tt.negotiated)
			if missed != tt.wantMissed {
				t.Fatalf("missed = %t, want %t", missed, tt.wantMissed)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("suites = %v, want %v", got, tt.want)
			}
		})
	}
}
