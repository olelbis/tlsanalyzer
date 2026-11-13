// Package baseline compares a TLS scan with a previously recorded JSON report.
//
// A baseline is an ordinary report written by `tlsanalyzer --json`, either a
// single-target report or a batch report. Compare reports what got worse
// since the baseline was recorded as policy failures, and everything else
// that changed (improvements, differences that cannot be judged) as notes.
package baseline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/olelbis/tlsanalyzer/output"
)

// Report is the decoded form of a single-target JSON report.
type Report = output.JSONReport

// Set is a loaded baseline file: one single-target report or the targets of a
// batch report.
type Set struct {
	// Batch reports whether the file was a batch report.
	Batch   bool
	reports []entry
}

type entry struct {
	host       string
	port       string
	serverName string
	report     *Report
}

// Load reads a baseline file written by `tlsanalyzer --json`.
//
// Unknown fields are ignored so that a baseline recorded by a newer 1.x
// scanner stays usable. A report with a different schema major version is
// refused because its fields may not mean what they mean now.
func Load(path string) (*Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load baseline %q: %w", path, err)
	}
	set, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("load baseline %q: %w", path, err)
	}
	return set, nil
}

// Parse decodes baseline JSON. See Load.
func Parse(data []byte) (*Set, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("the file is empty")
	}
	var probe struct {
		SchemaVersion string          `json:"schema_version"`
		Targets       json.RawMessage `json:"targets"`
		Results       json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("not a tlsanalyzer JSON report: %w", err)
	}
	if probe.SchemaVersion == "" || (probe.Targets == nil && probe.Results == nil) {
		return nil, fmt.Errorf("not a tlsanalyzer JSON report (no schema_version and results)")
	}
	if major := schemaMajor(probe.SchemaVersion); major != schemaMajor(output.JSONSchemaVersion) {
		return nil, fmt.Errorf("unsupported schema_version %q; this scanner reads schema %s.x reports", probe.SchemaVersion, schemaMajor(output.JSONSchemaVersion))
	}

	if probe.Targets != nil {
		var batch output.JSONBatchReport
		if err := json.Unmarshal(data, &batch); err != nil {
			return nil, fmt.Errorf("decode batch report: %w", err)
		}
		set := &Set{Batch: true}
		for i, target := range batch.Targets {
			if len(target.Report) == 0 {
				continue
			}
			var report Report
			if err := json.Unmarshal(target.Report, &report); err != nil {
				return nil, fmt.Errorf("decode batch target %d (%s:%s): %w", i+1, target.Host, target.Port, err)
			}
			set.reports = append(set.reports, entry{host: target.Host, port: target.Port, serverName: target.ServerName, report: &report})
		}
		if len(set.reports) == 0 {
			return nil, fmt.Errorf("the batch report holds no target reports")
		}
		return set, nil
	}

	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("decode report: %w", err)
	}
	return &Set{reports: []entry{{host: report.Host, port: report.Port, serverName: report.ServerName, report: &report}}}, nil
}

// Lookup returns the baseline report recorded for a target. The host is
// compared case-insensitively. A report recorded with the same SNI wins; a
// report recorded without SNI or with a different one is used only when it is
// the single report for that host and port.
func (s *Set) Lookup(host, port, serverName string) (*Report, bool) {
	var sameHostPort []entry
	for _, e := range s.reports {
		if !strings.EqualFold(e.host, host) || e.port != port {
			continue
		}
		if e.serverName == serverName {
			return e.report, true
		}
		sameHostPort = append(sameHostPort, e)
	}
	if len(sameHostPort) == 1 {
		return sameHostPort[0].report, true
	}
	return nil, false
}

// Targets lists the host:port pairs the baseline holds, for error messages.
func (s *Set) Targets() []string {
	targets := make([]string, 0, len(s.reports))
	for _, e := range s.reports {
		targets = append(targets, e.host+":"+e.port)
	}
	return targets
}

func schemaMajor(version string) string {
	major, _, _ := strings.Cut(version, ".")
	return major
}
