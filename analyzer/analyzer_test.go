package analyzer

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/olelbis/tlsanalyzer/policy"
	"github.com/olelbis/tlsanalyzer/scan"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions("example.com")
	if opts.Host != "example.com" {
		t.Fatalf("Host = %q", opts.Host)
	}
	if opts.Port != DefaultPort || opts.Timeout != DefaultTimeout || opts.MinVersion != DefaultMinVersion {
		t.Fatalf("defaults = port %q timeout %s min %x", opts.Port, opts.Timeout, opts.MinVersion)
	}
}

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

func TestRunWrapsSupportedHookError(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()

	host, port, err := netSplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split address: %v", err)
	}

	sentinel := errors.New("stop")
	_, err = Run(Options{
		Host:       host,
		Port:       port,
		Timeout:    time.Second,
		MinVersion: tls.VersionTLS12,
		SkipVerify: true,
	}, Hooks{
		Supported: func(scan.TLSScanResult, string) error {
			return sentinel
		},
	})
	if err == nil {
		t.Fatal("Run() error = nil")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("Run() error does not wrap sentinel: %v", err)
	}
	var hookErr *HookError
	if !errors.As(err, &hookErr) {
		t.Fatalf("Run() error type = %T, want *HookError", err)
	}
	if hookErr.Stage != HookStageSupported || hookErr.Version != "TLS 1.2" {
		t.Fatalf("hook error = %+v", hookErr)
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

func netSplitHostPort(address string) (string, string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", err
	}
	return host, port, nil
}
