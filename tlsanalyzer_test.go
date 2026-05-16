package main

import (
	"bytes"
	"strings"
	"testing"
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
