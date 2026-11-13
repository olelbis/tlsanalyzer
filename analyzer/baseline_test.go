package analyzer

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/olelbis/tlsanalyzer/baseline"
	"github.com/olelbis/tlsanalyzer/output"
	"github.com/olelbis/tlsanalyzer/policy"
)

// recordBaseline scans an endpoint with cipher probing and returns the report
// a user would have saved with --json.
func recordBaseline(t *testing.T, host, port string) *baseline.Report {
	t.Helper()
	opts := scanRangeOptions(host, port, tls.VersionTLS12, policy.Config{})
	opts.ForceCiphers = true
	result, err := Run(opts, Hooks{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	report := output.NewJSONReport(host, port, "", "test", time.Now(), result.Results)
	return &report
}

func TestRunWithBaselineFailsOnSuiteThatGotWorse(t *testing.T) {
	cleanHost, cleanPort := cipherServer(t, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256})
	base := recordBaseline(t, cleanHost, cleanPort)

	// The same endpoint after a misconfiguration: RC4 was enabled.
	host, port := cipherServer(t, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_RC4_128_SHA})
	opts := scanRangeOptions(host, port, tls.VersionTLS12, policy.Config{})
	opts.Baseline = base
	result, err := Run(opts, Hooks{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !result.Policy.Enabled || result.Policy.Passed {
		t.Fatalf("Policy = %+v, want an enabled, failed policy", result.Policy)
	}
	found := false
	for _, failure := range result.Policy.Failures {
		if failure.Check == policy.CheckBaseline && strings.Contains(failure.Message, "TLS_RSA_WITH_RC4_128_SHA") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Failures = %+v, want a baseline failure naming TLS_RSA_WITH_RC4_128_SHA", result.Policy.Failures)
	}
}

func TestRunWithBaselineProbesCipherSuitesWithoutForceCiphers(t *testing.T) {
	host, port := cipherServer(t, []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	})
	base := recordBaseline(t, host, port)

	opts := scanRangeOptions(host, port, tls.VersionTLS12, policy.Config{})
	opts.Baseline = base
	result, err := Run(opts, Hooks{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// With only the negotiated suite known, the second suite would be
	// reported as removed.
	if !result.Policy.Passed {
		t.Fatalf("Failures = %+v, want none against the baseline of the same endpoint", result.Policy.Failures)
	}
	for _, note := range result.Policy.Notes {
		if strings.Contains(note, "no longer offers") {
			t.Fatalf("note %q: the run did not probe the suites the baseline lists", note)
		}
	}
}

func TestRunWithoutBaselineLeavesPolicyDisabled(t *testing.T) {
	host, port := cipherServer(t, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256})
	result, err := Run(scanRangeOptions(host, port, tls.VersionTLS12, policy.Config{}), Hooks{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Policy.Enabled {
		t.Fatalf("Policy = %+v, want disabled without gates or baseline", result.Policy)
	}
}
