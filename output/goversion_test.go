package output

import (
	"encoding/json"
	"runtime"
	"testing"
	"time"
)

func TestBuildJSONReportRecordsGoToolchainVersion(t *testing.T) {
	data, err := BuildJSONReport("example.com", "443", "", "v0.0.0", time.Unix(0, 0), nil)
	if err != nil {
		t.Fatalf("BuildJSONReport() error = %v", err)
	}
	var report struct {
		GoVersion string `json:"go_version"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if report.GoVersion != runtime.Version() {
		t.Fatalf("go_version = %q, want %q", report.GoVersion, runtime.Version())
	}
}
