package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newGroupTLSServer(t *testing.T, curves ...tls.CurveID) (host, port string) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: curves}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split server address: %v", err)
	}
	return host, port
}

func TestRunEnumGroupsPrintsAndReportsGroups(t *testing.T) {
	host, port := newGroupTLSServer(t, tls.X25519MLKEM768, tls.X25519)

	var stdout, stderr bytes.Buffer
	code := run([]string{"--host", host, "--port", port, "--min-version", "1.3", "--skip-verify", "--enum-groups", "--no-clear"}, &stdout, &stderr)
	if code != exitCodeOK {
		t.Fatalf("run() exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitCodeOK, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "Accepted Key Exchange Groups: X25519MLKEM768 (post-quantum)") {
		t.Fatalf("stdout does not list the accepted groups:\n%s", stdout.String())
	}

	stdout.Reset()
	code = run([]string{"--host", host, "--port", port, "--min-version", "1.3", "--skip-verify", "--enum-groups", "--json", "--no-clear"}, &stdout, &stderr)
	if code != exitCodeOK {
		t.Fatalf("run() --json exit code = %d\n%s", code, stdout.String())
	}
	var report struct {
		Results []struct {
			Version string `json:"version"`
			Groups  []struct {
				Name        string `json:"name"`
				ID          int    `json:"id"`
				PostQuantum bool   `json:"post_quantum"`
			} `json:"key_exchange_groups"`
			Incomplete bool `json:"key_exchange_groups_incomplete"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
	}
	if len(report.Results) != 1 || report.Results[0].Incomplete {
		t.Fatalf("results = %+v, want one complete TLS 1.3 result", report.Results)
	}
	hybrid := false
	for _, group := range report.Results[0].Groups {
		if group.Name == "X25519MLKEM768" && group.ID == 0x11ec && group.PostQuantum {
			hybrid = true
		}
	}
	if !hybrid {
		t.Fatalf("groups = %+v, want X25519MLKEM768 (id 4588, post_quantum)", report.Results[0].Groups)
	}
}

func TestRunWithoutEnumGroupsOmitsGroups(t *testing.T) {
	host, port := newGroupTLSServer(t, tls.X25519MLKEM768, tls.X25519)
	var stdout, stderr bytes.Buffer
	code := run([]string{"--host", host, "--port", port, "--min-version", "1.3", "--skip-verify", "--json", "--no-clear"}, &stdout, &stderr)
	if code != exitCodeOK {
		t.Fatalf("run() exit code = %d\n%s", code, stdout.String())
	}
	if strings.Contains(stdout.String(), "key_exchange_groups") {
		t.Fatalf("JSON has key_exchange_groups without --enum-groups:\n%s", stdout.String())
	}
}

func TestRunRequirePQUsesPolicyExitCode(t *testing.T) {
	tests := []struct {
		name     string
		curves   []tls.CurveID
		wantCode int
	}{
		{"hybrid endpoint", []tls.CurveID{tls.X25519MLKEM768, tls.X25519}, exitCodeOK},
		{"classical endpoint", []tls.CurveID{tls.X25519, tls.CurveP256}, exitCodePolicyFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port := newGroupTLSServer(t, tt.curves...)
			var stdout, stderr bytes.Buffer
			code := run([]string{"--host", host, "--port", port, "--min-version", "1.3", "--skip-verify", "--require-pq", "--no-clear"}, &stdout, &stderr)
			if code != tt.wantCode {
				t.Fatalf("run() exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, stdout.String(), stderr.String())
			}
			if tt.wantCode == exitCodePolicyFailure && !strings.Contains(stdout.String(), "[require-pq] TLS 1.3 accepts no post-quantum key exchange group") {
				t.Fatalf("stdout does not name the failed check:\n%s", stdout.String())
			}
		})
	}
}
