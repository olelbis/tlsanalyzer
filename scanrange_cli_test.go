package main

import (
	"bytes"
	"crypto/tls"
	"strings"
	"testing"
)

func TestRunExplicitGateBelowMinVersionExtendsScan(t *testing.T) {
	server, host, port := newMainLocalTLSServer(t, tls.VersionTLS12, tls.VersionTLS13)
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--host", host,
		"--port", port,
		"--min-version", "1.2",
		"--forbid-tls", "1.0",
		"--skip-verify",
		"--no-clear",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run() exit code = %d, want 0 (server does not offer TLS 1.0)\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "Scanning down to TLS 1.0") {
		t.Fatalf("stdout does not announce the extended scan range:\n%s", stdout.String())
	}
}

func TestRunWithoutPolicyDoesNotExtendScan(t *testing.T) {
	server, host, port := newMainLocalTLSServer(t, tls.VersionTLS12, tls.VersionTLS13)
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--host", host,
		"--port", port,
		"--min-version", "1.2",
		"--skip-verify",
		"--no-clear",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run() exit code = %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "Scanning down to") {
		t.Fatalf("scan range was extended without a policy:\n%s", stdout.String())
	}
}
