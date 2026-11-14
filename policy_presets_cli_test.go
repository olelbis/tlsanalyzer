package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"strings"
	"testing"
)

func TestRunRejectsMozillaPresetConflictBeforeScan(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--host", "example.com", "--policy", "mozilla-modern", "--require-tls", "1.2", "--json"}, &stdout, &stderr)
	if code != exitCodeInputRuntimeFailure {
		t.Fatalf("run() exit code = %d, want %d", code, exitCodeInputRuntimeFailure)
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "policy mozilla-modern forbids TLS 1.2") {
		t.Fatalf("stderr does not name the preset conflict:\n%s", stderr.String())
	}
}

func TestRunMozillaModernScansLegacyVersionsAndJudgesTheCertificate(t *testing.T) {
	host, port := newGroupTLSServer(t, tls.X25519)

	var stdout, stderr bytes.Buffer
	code := run([]string{"--host", host, "--port", port, "--policy", "mozilla-modern", "--json", "--no-clear"}, &stdout, &stderr)
	if code != exitCodePolicyFailure {
		t.Fatalf("run() exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitCodePolicyFailure, stdout.String(), stderr.String())
	}
	var report struct {
		Results []struct {
			Version string `json:"version"`
		} `json:"results"`
		Policy struct {
			Name     string `json:"name"`
			Passed   bool   `json:"passed"`
			Failures []struct {
				Check string `json:"check"`
			} `json:"failures"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
	}
	if len(report.Results) != 4 {
		t.Fatalf("results = %d, want TLS 1.0 to 1.3 so that the forbidden versions are scanned", len(report.Results))
	}
	if report.Policy.Name != "mozilla-modern" || report.Policy.Passed {
		t.Fatalf("policy = %+v, want a failed mozilla-modern policy", report.Policy)
	}
	checks := make(map[string]bool)
	for _, failure := range report.Policy.Failures {
		checks[failure.Check] = true
	}
	// The test server only speaks TLS 1.3, so the version gates pass; its
	// self-signed RSA certificate does not meet the certificate checks.
	for _, check := range []string{"cert-key", "cert-lifespan"} {
		if !checks[check] {
			t.Fatalf("missing %q failure: %+v", check, report.Policy.Failures)
		}
	}
	for _, check := range []string{"forbidden-tls", "required-tls"} {
		if checks[check] {
			t.Fatalf("unexpected %q failure on a TLS 1.3-only server: %+v", check, report.Policy.Failures)
		}
	}
}
