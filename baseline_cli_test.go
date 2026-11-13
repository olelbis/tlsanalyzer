package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recordBaselineFile scans a local endpoint the way a user records a baseline
// and returns the path of the saved report.
func recordBaselineFile(t *testing.T, host, port string, extraArgs ...string) string {
	t.Helper()
	args := append([]string{
		"--host", host, "--port", port,
		"--min-version", "1.2", "--skip-verify", "--force-ciphers",
		"--json", "--no-clear",
	}, extraArgs...)
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != exitCodeOK {
		t.Fatalf("recording the baseline exited %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, stdout.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func compareToBaseline(t *testing.T, host, port, baselinePath string, extraArgs ...string) (int, string, string) {
	t.Helper()
	args := append([]string{
		"--host", host, "--port", port,
		"--min-version", "1.2", "--skip-verify",
		"--baseline", baselinePath, "--no-clear",
	}, extraArgs...)
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// editBaseline rewrites a recorded report so that it describes an endpoint
// that was better than the one being scanned.
func editBaseline(t *testing.T, path string, edit func(report map[string]interface{})) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]interface{}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	edit(report)
	data, err = json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRunBaselinePassesOnUnchangedEndpoint(t *testing.T) {
	server, host, port := newMainLocalTLSServer(t, tls.VersionTLS12, tls.VersionTLS13)
	defer server.Close()
	baselinePath := recordBaselineFile(t, host, port)

	code, stdout, stderr := compareToBaseline(t, host, port, baselinePath)
	if code != exitCodeOK {
		t.Fatalf("run() exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitCodeOK, stdout, stderr)
	}
	if !strings.Contains(stdout, "Policy custom: passed") {
		t.Fatalf("stdout does not report the baseline gate as passed:\n%s", stdout)
	}
}

func TestRunBaselineRegressionUsesPolicyExitCode(t *testing.T) {
	server, host, port := newMainLocalTLSServer(t, tls.VersionTLS12, tls.VersionTLS12)
	defer server.Close()
	baselinePath := recordBaselineFile(t, host, port)

	// The baseline claims TLS 1.3 worked; the endpoint only speaks TLS 1.2.
	editBaseline(t, baselinePath, func(report map[string]interface{}) {
		for _, r := range report["results"].([]interface{}) {
			result := r.(map[string]interface{})
			if result["version"] == "TLS 1.3" {
				result["status"] = "supported"
				result["supported"] = true
			}
		}
	})

	code, stdout, stderr := compareToBaseline(t, host, port, baselinePath)
	if code != exitCodePolicyFailure {
		t.Fatalf("run() exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitCodePolicyFailure, stdout, stderr)
	}
	if !strings.Contains(stdout, "[baseline] TLS 1.3 is no longer supported") {
		t.Fatalf("stdout does not name the regression:\n%s", stdout)
	}
}

func TestRunBaselineRegressionIsInTheJSONPolicy(t *testing.T) {
	server, host, port := newMainLocalTLSServer(t, tls.VersionTLS12, tls.VersionTLS12)
	defer server.Close()
	baselinePath := recordBaselineFile(t, host, port)
	editBaseline(t, baselinePath, func(report map[string]interface{}) {
		for _, r := range report["results"].([]interface{}) {
			result := r.(map[string]interface{})
			if result["version"] == "TLS 1.3" {
				result["status"] = "supported"
				result["supported"] = true
			}
		}
	})

	code, stdout, _ := compareToBaseline(t, host, port, baselinePath, "--json")
	if code != exitCodePolicyFailure {
		t.Fatalf("run() exit code = %d, want %d\n%s", code, exitCodePolicyFailure, stdout)
	}
	var report struct {
		Policy struct {
			Enabled  bool `json:"enabled"`
			Passed   bool `json:"passed"`
			Failures []struct {
				Check   string `json:"check"`
				Version string `json:"version"`
			} `json:"failures"`
		} `json:"policy"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if !report.Policy.Enabled || report.Policy.Passed || len(report.Policy.Failures) != 1 ||
		report.Policy.Failures[0].Check != "baseline" || report.Policy.Failures[0].Version != "TLS 1.3" {
		t.Fatalf("policy = %+v, want one failed baseline check for TLS 1.3", report.Policy)
	}
}

func TestRunBaselineInputErrorsUseRuntimeExitCode(t *testing.T) {
	server, host, port := newMainLocalTLSServer(t, tls.VersionTLS12, tls.VersionTLS13)
	defer server.Close()
	baselinePath := recordBaselineFile(t, host, port)

	notAReport := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(notAReport, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		path     string
		port     string
		wantText string
	}{
		{"missing file", baselinePath + ".missing", port, "load baseline"},
		{"not a report", notAReport, port, "not a tlsanalyzer JSON report"},
		{"report of another target", baselinePath, "9", "holds no report for " + host + ":9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := compareToBaseline(t, host, tt.port, tt.path)
			if code != exitCodeInputRuntimeFailure {
				t.Fatalf("run() exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitCodeInputRuntimeFailure, stdout, stderr)
			}
			if !strings.Contains(stderr, tt.wantText) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr, tt.wantText)
			}
			if strings.Contains(stdout, "Starting TLS analysis") {
				t.Fatalf("the scan started although the baseline is unusable:\n%s", stdout)
			}
		})
	}
}

func TestRunBaselineFromConfigFile(t *testing.T) {
	server, host, port := newMainLocalTLSServer(t, tls.VersionTLS12, tls.VersionTLS12)
	defer server.Close()
	baselinePath := recordBaselineFile(t, host, port)
	editBaseline(t, baselinePath, func(report map[string]interface{}) {
		for _, r := range report["results"].([]interface{}) {
			result := r.(map[string]interface{})
			if result["version"] == "TLS 1.3" {
				result["status"] = "supported"
				result["supported"] = true
			}
		}
	})
	configPath := filepath.Join(t.TempDir(), "config.json")
	config, _ := json.Marshal(map[string]string{"baseline": baselinePath})
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"--config", configPath, "--host", host, "--port", port, "--min-version", "1.2", "--skip-verify", "--no-clear"}, &stdout, &stderr)
	if code != exitCodePolicyFailure {
		t.Fatalf("run() exit code = %d, want %d (baseline read from the config file)\nstdout:\n%s\nstderr:\n%s", code, exitCodePolicyFailure, stdout.String(), stderr.String())
	}
}

func writeTargets(t *testing.T, targets ...map[string]string) string {
	t.Helper()
	data, err := json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "targets.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunBatchBaseline(t *testing.T) {
	first, firstHost, firstPort := newMainLocalTLSServer(t, tls.VersionTLS12, tls.VersionTLS12)
	defer first.Close()
	second, secondHost, secondPort := newMainLocalTLSServer(t, tls.VersionTLS12, tls.VersionTLS12)
	defer second.Close()

	batchArgs := func(targets string, extra ...string) []string {
		return append([]string{
			"--targets-file", targets, "--min-version", "1.2", "--skip-verify",
			"--force-ciphers", "--no-clear",
		}, extra...)
	}

	recorded := writeTargets(t, map[string]string{"host": firstHost, "port": firstPort})
	var recordOut, recordErr bytes.Buffer
	if code := run(batchArgs(recorded, "--json"), &recordOut, &recordErr); code != exitCodeOK {
		t.Fatalf("recording the batch baseline exited %d\nstdout:\n%s\nstderr:\n%s", code, recordOut.String(), recordErr.String())
	}
	baselinePath := filepath.Join(t.TempDir(), "batch-baseline.json")
	if err := os.WriteFile(baselinePath, recordOut.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("target in the baseline passes, a new target is only noted", func(t *testing.T) {
		both := writeTargets(t,
			map[string]string{"host": firstHost, "port": firstPort},
			map[string]string{"host": secondHost, "port": secondPort},
		)
		var stdout, stderr bytes.Buffer
		code := run(batchArgs(both, "--baseline", baselinePath, "--json"), &stdout, &stderr)
		if code != exitCodeOK {
			t.Fatalf("run() exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitCodeOK, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "so it was not compared") {
			t.Fatalf("the target missing from the baseline is not reported:\n%s", stdout.String())
		}
	})

	t.Run("regression fails the batch with exit 3", func(t *testing.T) {
		editBaseline(t, baselinePath, func(report map[string]interface{}) {
			for _, target := range report["targets"].([]interface{}) {
				inner := target.(map[string]interface{})["report"].(map[string]interface{})
				for _, r := range inner["results"].([]interface{}) {
					result := r.(map[string]interface{})
					if result["version"] == "TLS 1.3" {
						result["status"] = "supported"
						result["supported"] = true
					}
				}
			}
		})
		var stdout, stderr bytes.Buffer
		code := run(batchArgs(recorded, "--baseline", baselinePath), &stdout, &stderr)
		if code != exitCodePolicyFailure {
			t.Fatalf("run() exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitCodePolicyFailure, stdout.String(), stderr.String())
		}
	})

	t.Run("unusable baseline is a runtime error", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run(batchArgs(recorded, "--baseline", baselinePath+".missing"), &stdout, &stderr)
		if code != exitCodeInputRuntimeFailure {
			t.Fatalf("run() exit code = %d, want %d\nstderr:\n%s", code, exitCodeInputRuntimeFailure, stderr.String())
		}
	})
}
