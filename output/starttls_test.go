package output

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/olelbis/tlsanalyzer/scan"
)

func TestJSONReportStartTLS(t *testing.T) {
	at := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)

	plain, err := BuildJSONReport("example.com", "443", "", "vtest", at, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), `"starttls"`) {
		t.Fatalf("a plain TLS report has a starttls field:\n%s", plain)
	}

	report := NewJSONReport("mail.example.com", "25", "", "vtest", at, nil)
	report.StartTLS = "smtp"
	data, err := MarshalJSONReport(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded JSONReport
	if err := json.Unmarshal(data, &decoded); err != nil || decoded.StartTLS != "smtp" {
		t.Fatalf("decoded = %+v, %v, want starttls smtp\n%s", decoded, err, data)
	}
}

func TestBatchReportCarriesStartTLS(t *testing.T) {
	at := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	data, err := BuildJSONBatchReport("vtest", at, []TargetReport{
		{Host: "mail.example.com", Port: "25", StartTLS: "smtp", Results: []scan.TLSScanResult{}},
		{Host: "example.com", Port: "443", Results: []scan.TLSScanResult{}},
	}, BatchRunMetadata{TargetCount: 2})
	if err != nil {
		t.Fatal(err)
	}
	var batch struct {
		Targets []struct {
			Report JSONReport `json:"report"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(data, &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.Targets) != 2 || batch.Targets[0].Report.StartTLS != "smtp" || batch.Targets[1].Report.StartTLS != "" {
		t.Fatalf("targets = %+v, want starttls only on the mail target", batch.Targets)
	}
}
