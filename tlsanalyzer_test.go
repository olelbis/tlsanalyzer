package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olelbis/tlsanalyzer/build"
	"github.com/olelbis/tlsanalyzer/policy"
	"github.com/olelbis/tlsanalyzer/scan"
)

func TestValidateHost(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{name: "domain", host: "example.com"},
		{name: "ipv6", host: "::1"},
		{name: "empty", host: "", wantErr: true},
		{name: "contains whitespace", host: "example .com", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHost(tt.host)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateHost(%q) error = %v, wantErr %v", tt.host, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePort(t *testing.T) {
	tests := []struct {
		name    string
		port    string
		wantErr bool
	}{
		{name: "https", port: "443"},
		{name: "lowest", port: "1"},
		{name: "highest", port: "65535"},
		{name: "empty", port: "", wantErr: true},
		{name: "zero", port: "0", wantErr: true},
		{name: "too high", port: "65536", wantErr: true},
		{name: "not numeric", port: "https", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePort(tt.port)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validatePort(%q) error = %v, wantErr %v", tt.port, err, tt.wantErr)
			}
		})
	}
}

func TestValidateFlagCombination(t *testing.T) {
	tests := []struct {
		name       string
		outputJSON bool
		certChain  bool
		outputFile string
		wantErr    bool
	}{
		{name: "plain scan"},
		{name: "json without cert", outputJSON: true},
		{name: "cert without json", certChain: true},
		{name: "json cert with output", outputJSON: true, certChain: true, outputFile: "chain.pem"},
		{name: "json cert without output", outputJSON: true, certChain: true, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFlagCombination(tt.outputJSON, tt.certChain, tt.outputFile)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateFlagCombination() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRunMissingHostReturnsErrorWithoutExit(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"--no-clear"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("run() exit code = %d, want 1", code)
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Error: --host is required") {
		t.Fatalf("stderr does not contain missing host error:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "Usage of tlsanalyzer:") {
		t.Fatalf("stderr does not contain usage:\n%s", stderr.String())
	}
}

func TestRunRejectsJSONCertWithoutOutputBeforeScan(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"--host", "example.com", "--json", "--cert"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("run() exit code = %d, want 1", code)
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "--json with --cert requires --output") {
		t.Fatalf("stderr does not contain flag combination error:\n%s", stderr.String())
	}
}

func TestRunVersionDoesNotRequireHost(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"--version"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run() exit code = %d, want 0", code)
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if !strings.Contains(stdout.String(), "tlsanalyzer "+build.Version) {
		t.Fatalf("stdout does not contain version:\n%s", stdout.String())
	}
}

func TestRunRejectsUnknownPolicyBeforeScan(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"--host", "example.com", "--json", "--policy", "strict"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("run() exit code = %d, want 1", code)
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), `unknown policy "strict"`) {
		t.Fatalf("stderr does not contain unknown policy error:\n%s", stderr.String())
	}
}

func TestRunRejectsInvalidSNI(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"--host", "example.com", "--sni", "bad name", "--json"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("run() exit code = %d, want 1", code)
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "invalid --sni") {
		t.Fatalf("stderr does not contain invalid sni error:\n%s", stderr.String())
	}
}

func TestParseCLIArgsUsesIndependentFlagSets(t *testing.T) {
	var stderr bytes.Buffer

	first, err := parseCLIArgs([]string{"--host", "example.com", "--port", "8443"}, &stderr)
	if err != nil {
		t.Fatalf("first parseCLIArgs() error = %v", err)
	}
	second, err := parseCLIArgs([]string{"--host", "example.org"}, &stderr)
	if err != nil {
		t.Fatalf("second parseCLIArgs() error = %v", err)
	}

	if first.port != "8443" {
		t.Fatalf("first port = %q, want 8443", first.port)
	}
	if second.port != "443" {
		t.Fatalf("second port = %q, want default 443", second.port)
	}
}

func TestParseCLIArgsPolicyFlags(t *testing.T) {
	var stderr bytes.Buffer

	cfg, err := parseCLIArgs([]string{
		"--host", "example.com",
		"--sni", "service.example.com",
		"--policy", "modern",
		"--fail-on", "legacy-tls,weak-cipher",
		"--require-tls", "1.3",
		"--forbid-tls", "1.0,1.1",
		"--require-alpn", "h2",
		"--forbid-alpn", "http/1.1",
		"--min-cert-key-bits", "2048",
		"--min-cert-days", "30",
	}, &stderr)
	if err != nil {
		t.Fatalf("parseCLIArgs() error = %v", err)
	}
	if cfg.policy != "modern" {
		t.Fatalf("policy = %q, want modern", cfg.policy)
	}
	if cfg.failOn != "legacy-tls,weak-cipher" {
		t.Fatalf("failOn = %q, want legacy-tls,weak-cipher", cfg.failOn)
	}
	if cfg.sni != "service.example.com" {
		t.Fatalf("sni = %q, want service.example.com", cfg.sni)
	}
	if cfg.requireTLS != "1.3" || cfg.forbidTLS != "1.0,1.1" {
		t.Fatalf("TLS policy flags = require %q forbid %q", cfg.requireTLS, cfg.forbidTLS)
	}
	if cfg.requireALPN != "h2" || cfg.forbidALPN != "http/1.1" {
		t.Fatalf("ALPN policy flags = require %q forbid %q", cfg.requireALPN, cfg.forbidALPN)
	}
	if cfg.minCertKeyBits != 2048 || cfg.minCertDays != 30 {
		t.Fatalf("certificate policy flags = key %d days %d", cfg.minCertKeyBits, cfg.minCertDays)
	}
	policyConfig, err := buildPolicyConfig(cfg)
	if err != nil {
		t.Fatalf("buildPolicyConfig() error = %v", err)
	}
	if len(policyConfig.RequiredTLSVersions) != 1 || policyConfig.RequiredTLSVersions[0] != tls.VersionTLS13 {
		t.Fatalf("RequiredTLSVersions = %+v, want TLS 1.3", policyConfig.RequiredTLSVersions)
	}
	if len(policyConfig.ForbiddenTLSVersions) != 2 {
		t.Fatalf("ForbiddenTLSVersions = %+v, want TLS 1.0 and TLS 1.1", policyConfig.ForbiddenTLSVersions)
	}
}

func TestParseCLIArgsLoadsJSONConfigWithTargetProfileAndOverrides(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "tlsanalyzer.json")
	config := `{
  "target": "example",
  "profile": "ci",
  "json": true,
  "no_clear": true,
  "targets": {
    "example": {
      "host": "config.example.com",
      "port": "8443",
      "sni": "service.example.com"
    }
  },
  "profiles": {
    "ci": {
      "policy": "modern",
      "require_tls": "1.3",
      "forbid_tls": "1.0,1.1",
      "min_cert_days": 30
    }
  }
}`
	if err := os.WriteFile(configPath, []byte(config), 0640); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stderr bytes.Buffer
	cfg, err := parseCLIArgs([]string{
		"--config", configPath,
		"--host", "override.example.com",
		"--min-cert-days", "45",
	}, &stderr)
	if err != nil {
		t.Fatalf("parseCLIArgs() error = %v", err)
	}

	if cfg.host != "override.example.com" {
		t.Fatalf("host = %q, want CLI override", cfg.host)
	}
	if cfg.port != "8443" || cfg.sni != "service.example.com" {
		t.Fatalf("target values = port %q sni %q", cfg.port, cfg.sni)
	}
	if !cfg.outputJSON || !cfg.noClear {
		t.Fatalf("json/noClear = %v/%v, want true/true", cfg.outputJSON, cfg.noClear)
	}
	if cfg.policy != "modern" || cfg.requireTLS != "1.3" || cfg.forbidTLS != "1.0,1.1" {
		t.Fatalf("profile values = policy %q require %q forbid %q", cfg.policy, cfg.requireTLS, cfg.forbidTLS)
	}
	if cfg.minCertDays != 45 {
		t.Fatalf("minCertDays = %d, want CLI override 45", cfg.minCertDays)
	}
}

func TestRunRejectsUnknownConfigField(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "tlsanalyzer.json")
	if err := os.WriteFile(configPath, []byte(`{"unknown": true}`), 0640); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"--config", configPath}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("run() exit code = %d, want 1", code)
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "unknown field") {
		t.Fatalf("stderr does not contain unknown field error:\n%s", stderr.String())
	}
}

func TestExecuteScanRunReturnsStructuredResults(t *testing.T) {
	server, host, port := newMainLocalTLSServer(t, tls.VersionTLS12, tls.VersionTLS12)
	defer server.Close()

	var started []string
	supportedHookCalled := false
	result, err := executeScanRun(scanRunOptions{
		Host:       host,
		Port:       port,
		Timeout:    time.Second,
		MinVersion: tls.VersionTLS12,
		SkipVerify: true,
	}, scanRunHooks{
		VersionStart: func(versionName string, _ uint16, _ bool) {
			started = append(started, versionName)
		},
		Supported: func(result scan.TLSScanResult, negotiatedCipher string) error {
			supportedHookCalled = true
			if result.Certificate == nil {
				t.Fatal("supported hook result should include certificate")
			}
			if negotiatedCipher == "" {
				t.Fatal("negotiatedCipher should be passed to supported hook")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("executeScanRun() error = %v", err)
	}
	if len(started) != 2 || started[0] != "TLS 1.2" || started[1] != "TLS 1.3" {
		t.Fatalf("started versions = %v, want TLS 1.2 and TLS 1.3", started)
	}
	if !supportedHookCalled {
		t.Fatal("supported hook was not called")
	}
	if len(result.Results) != 2 {
		t.Fatalf("Results = %d, want 2", len(result.Results))
	}
	if !result.Results[0].Supported {
		t.Fatalf("first result should be supported: %+v", result.Results[0])
	}
	if result.Policy.Enabled {
		t.Fatal("policy should be disabled when no policy config is set")
	}
}

func TestBuildPolicyConfigRejectsInvalidTLSVersion(t *testing.T) {
	_, err := buildPolicyConfig(cliConfig{requireTLS: "1.4"})
	if err == nil {
		t.Fatal("buildPolicyConfig() error = nil, want invalid TLS version error")
	}
}

func TestParseCLIArgsProductPolishFlags(t *testing.T) {
	var stderr bytes.Buffer

	cfg, err := parseCLIArgs([]string{"--host", "example.com", "--compact", "--version"}, &stderr)
	if err != nil {
		t.Fatalf("parseCLIArgs() error = %v", err)
	}
	if !cfg.compact {
		t.Fatal("compact = false, want true")
	}
	if !cfg.showVersion {
		t.Fatal("showVersion = false, want true")
	}
}

func TestPolicyModernRequiresCipherProbe(t *testing.T) {
	cfg := policy.Config{Name: policy.NameModern}
	if !policy.RequiresCipherProbe(cfg) {
		t.Fatal("modern policy should require cipher probing")
	}
}

func newMainLocalTLSServer(t *testing.T, minVersion, maxVersion uint16) (*httptest.Server, string, string) {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{
		MinVersion: minVersion,
		MaxVersion: maxVersion,
	}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()

	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		server.Close()
		t.Fatalf("split server address: %v", err)
	}
	return server, host, port
}
