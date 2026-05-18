package analyzer

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/olelbis/tlsanalyzer/policy"
	"github.com/olelbis/tlsanalyzer/scan"
)

func TestRunFailed(t *testing.T) {
	tests := []struct {
		name    string
		results []scan.TLSScanResult
		want    bool
	}{
		{name: "empty", want: true},
		{name: "all execution errors", results: []scan.TLSScanResult{{Status: scan.ScanStatusNetworkError}, {Status: scan.ScanStatusTimeout}}, want: true},
		{name: "unsupported is evidence", results: []scan.TLSScanResult{{Status: scan.ScanStatusUnsupported}}, want: false},
		{name: "supported is evidence", results: []scan.TLSScanResult{{Status: scan.ScanStatusSupported}}, want: false},
		{name: "mixed execution error and evidence", results: []scan.TLSScanResult{{Status: scan.ScanStatusTimeout}, {Status: scan.ScanStatusSupported}}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RunFailed(tt.results); got != tt.want {
				t.Fatalf("RunFailed() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestRunEvaluatesPolicyWithInjectedClock(t *testing.T) {
	result, err := Run(Options{
		Host:       "127.0.0.1",
		Port:       "1",
		Timeout:    time.Second,
		MinVersion: tls.VersionTLS13,
		PolicyConfig: policy.Config{
			Name:   policy.NameModern,
			FailOn: []string{policy.CheckRequiredTLS},
		},
	}, Hooks{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(result.Results))
	}
	if !result.Policy.Enabled {
		t.Fatal("policy should be enabled")
	}
}
