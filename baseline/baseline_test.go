package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const singleReport = `{
  "host": "Example.com", "port": "443", "schema_version": "1.1", "scanner_version": "v0.32.0",
  "generated_at": "2026-11-13T10:00:00Z", "unknown_future_field": true,
  "results": [{"version": "TLS 1.2", "version_id": 771, "supported": true, "status": "supported", "cipher_discovery": "probed"}]
}`

func TestParseSingleReportAndLookup(t *testing.T) {
	set, err := Parse([]byte(singleReport))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if set.Batch {
		t.Fatal("single report parsed as batch")
	}
	report, ok := set.Lookup("example.com", "443", "")
	if !ok || len(report.Results) != 1 {
		t.Fatalf("Lookup() = %+v, %v, want the report (host compared case-insensitively)", report, ok)
	}
	if _, ok := set.Lookup("example.com", "8443", ""); ok {
		t.Fatal("Lookup() matched a different port")
	}
	if _, ok := set.Lookup("other.example", "443", ""); ok {
		t.Fatal("Lookup() matched a different host")
	}
	// The report was recorded without SNI; it is the only one for the target.
	if _, ok := set.Lookup("example.com", "443", "www.example.com"); !ok {
		t.Fatal("Lookup() should fall back to the single report of the host and port")
	}
}

func TestParseBatchReportMatchesBySNI(t *testing.T) {
	batch := `{
  "schema_version": "1.1", "scanner_version": "v0.32.0", "generated_at": "2026-11-13T10:00:00Z",
  "batch": {"target_count": 3},
  "targets": [
    {"host": "a.example", "port": "443", "server_name": "one.example", "report": {"host": "a.example", "port": "443", "server_name": "one.example", "schema_version": "1.1", "results": [{"version": "TLS 1.3", "version_id": 772, "status": "supported"}]}},
    {"host": "a.example", "port": "443", "server_name": "two.example", "report": {"host": "a.example", "port": "443", "server_name": "two.example", "schema_version": "1.1", "results": [{"version": "TLS 1.2", "version_id": 771, "status": "supported"}]}},
    {"host": "b.example", "port": "443", "exit_code": 1, "error": "boom"}
  ]
}`
	set, err := Parse([]byte(batch))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !set.Batch {
		t.Fatal("batch report parsed as single")
	}
	report, ok := set.Lookup("a.example", "443", "two.example")
	if !ok || report.Results[0].Version != "TLS 1.2" {
		t.Fatalf("Lookup(two.example) = %+v, %v, want the TLS 1.2 report", report, ok)
	}
	if _, ok := set.Lookup("a.example", "443", ""); ok {
		t.Fatal("Lookup() must not guess between two reports for the same host and port")
	}
	if _, ok := set.Lookup("b.example", "443", ""); ok {
		t.Fatal("Lookup() returned a target that has no report (it failed)")
	}
	if got := strings.Join(set.Targets(), ","); got != "a.example:443,a.example:443" {
		t.Fatalf("Targets() = %q", got)
	}
}

func TestParseRejectsFilesThatAreNotUsableBaselines(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{"empty", "  \n", "empty"},
		{"not json", "tlsanalyzer", "not a tlsanalyzer JSON report"},
		{"other json", `{"hello": "world"}`, "not a tlsanalyzer JSON report"},
		{"future schema", `{"schema_version": "2.0", "results": []}`, `unsupported schema_version "2.0"`},
		{"old schema", `{"schema_version": "0.9", "results": []}`, `unsupported schema_version "0.9"`},
		{"batch without reports", `{"schema_version": "1.1", "targets": [{"host": "a", "port": "443"}]}`, "no target reports"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.data))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse() error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestLoadReadsFileAndNamesItInErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte(singleReport), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	_, err := Load(path + ".missing")
	if err == nil || !strings.Contains(err.Error(), "baseline.json.missing") {
		t.Fatalf("Load() error = %v, want it to name the missing file", err)
	}
}
