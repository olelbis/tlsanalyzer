package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/olelbis/tlsanalyzer/policy"
	"github.com/olelbis/tlsanalyzer/scan"
)

// TargetReport contains the scan evidence and policy outcome for one batch target.
type TargetReport struct {
	Host           string
	Port           string
	ServerName     string
	ScannerVersion string
	Attempts       int
	Results        []scan.TLSScanResult
	Policy         *policy.Result
	Error          string
	ExitCode       int
}

// BatchRunMetadata describes the operational settings used by a batch run.
type BatchRunMetadata struct {
	TargetCount  int    `json:"target_count"`
	Concurrency  int    `json:"concurrency"`
	Retries      int    `json:"retries"`
	RetryBackoff string `json:"retry_backoff"`
}

// JSONBatchReport is the aggregate JSON document emitted for batch scans.
type JSONBatchReport struct {
	SchemaVersion  string            `json:"schema_version"`
	ScannerVersion string            `json:"scanner_version"`
	GeneratedAt    string            `json:"generated_at"`
	Batch          BatchRunMetadata  `json:"batch"`
	Targets        []JSONBatchTarget `json:"targets"`
}

// JSONBatchTarget contains batch metadata and the embedded single-target JSON report.
type JSONBatchTarget struct {
	Host       string          `json:"host"`
	Port       string          `json:"port"`
	ServerName string          `json:"server_name,omitempty"`
	Attempts   int             `json:"attempts"`
	ExitCode   int             `json:"exit_code"`
	Error      string          `json:"error,omitempty"`
	Report     json.RawMessage `json:"report"`
}

// BuildJSONBatchReport builds a dependency-free aggregate JSON report for batch scans.
func BuildJSONBatchReport(scannerVersion string, generatedAt time.Time, reports []TargetReport, metadata BatchRunMetadata) ([]byte, error) {
	batch := JSONBatchReport{
		SchemaVersion:  JSONSchemaVersion,
		ScannerVersion: scannerVersion,
		GeneratedAt:    generatedAt.UTC().Format(time.RFC3339),
		Batch:          metadata,
		Targets:        make([]JSONBatchTarget, 0, len(reports)),
	}
	for _, report := range reports {
		data, err := BuildJSONReport(report.Host, report.Port, report.ServerName, report.ScannerVersion, generatedAt, report.Results, report.Policy)
		if err != nil {
			return nil, err
		}
		batch.Targets = append(batch.Targets, JSONBatchTarget{
			Host:       report.Host,
			Port:       report.Port,
			ServerName: report.ServerName,
			Attempts:   report.Attempts,
			ExitCode:   report.ExitCode,
			Error:      report.Error,
			Report:     json.RawMessage(data),
		})
	}
	return json.MarshalIndent(batch, "", "  ")
}

// PrintBatchSummary writes a compact human-readable summary for batch scans.
func PrintBatchSummary(w io.Writer, reports []TargetReport) {
	fmt.Fprintln(w, "\nBatch Summary:")
	for _, report := range reports {
		status := "passed"
		if report.Error != "" {
			status = "error"
		} else if report.Policy != nil && report.Policy.Enabled && !report.Policy.Passed {
			status = "policy-failed"
		}
		target := targetLabel(report.Host, report.Port, report.ServerName)
		fmt.Fprintf(w, "  %-14s %s attempts=%d supported=%s cert=%s ciphers=%s\n", status, target, report.Attempts, summarizeSupportedTLSVersions(report.Results), summarizeCertificateValidation(report.Results), summarizeCipherFindings(report.Results))
	}
}

// WriteSARIFBatchReportToFile writes one SARIF report for all batch targets.
func WriteSARIFBatchReportToFile(reports []TargetReport, outputPath string) error {
	data, err := BuildSARIFBatchReport(reports)
	if err != nil {
		return err
	}
	if !strings.HasSuffix(outputPath, ".sarif") {
		outputPath += ".sarif"
	}
	return os.WriteFile(outputPath, data, 0640)
}

// WriteJUnitBatchReportToFile writes one JUnit XML report for all batch targets.
func WriteJUnitBatchReportToFile(reports []TargetReport, outputPath string) error {
	data, err := BuildJUnitBatchReport(reports)
	if err != nil {
		return err
	}
	if !strings.HasSuffix(outputPath, ".xml") {
		outputPath += ".xml"
	}
	return os.WriteFile(outputPath, data, 0640)
}
