package main

import "testing"

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
