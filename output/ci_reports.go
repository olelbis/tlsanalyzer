package output

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/olelbis/tlsanalyzer/policy"
	"github.com/olelbis/tlsanalyzer/scan"
)

const sarifVersion = "2.1.0"

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	ShortDescription sarifText         `json:"shortDescription"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       sarifRuleProperty `json:"properties,omitempty"`
}

type sarifRuleProperty struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	Snippet sarifText `json:"snippet,omitempty"`
}

type junitTestSuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Errors   int              `xml:"errors,attr"`
	Suites   []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Time      string          `xml:"time,attr"`
	TestCases []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	ClassName string        `xml:"classname,attr"`
	Name      string        `xml:"name,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Error     *junitFailure `xml:"error,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

// WriteSARIFReportToFile writes SARIF v2.1.0 output for policy findings.
func WriteSARIFReportToFile(host, port, serverName, scannerVersion string, results []scan.TLSScanResult, outputPath string, policyResult *policy.Result) error {
	report, err := BuildSARIFReport(host, port, serverName, scannerVersion, results, policyResult)
	if err != nil {
		return err
	}
	if !strings.HasSuffix(outputPath, ".sarif") {
		outputPath += ".sarif"
	}
	return os.WriteFile(outputPath, report, 0640)
}

// BuildSARIFReport builds a SARIF v2.1.0 report from enabled policy failures.
func BuildSARIFReport(host, port, serverName, scannerVersion string, results []scan.TLSScanResult, policyResult *policy.Result) ([]byte, error) {
	failures := policyFailures(policyResult)
	log := sarifLog{
		Version: sarifVersion,
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "tlsanalyzer",
				InformationURI: "https://github.com/olelbis/tlsanalyzer",
				Version:        scannerVersion,
				Rules:          sarifRulesForFailures(failures),
			}},
			Results: sarifResultsForFailures(host, port, serverName, results, failures),
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}

// WriteJUnitReportToFile writes a JUnit XML report for scan status and policy failures.
func WriteJUnitReportToFile(host, port, serverName, scannerVersion string, results []scan.TLSScanResult, outputPath string, policyResult *policy.Result) error {
	report, err := BuildJUnitReport(host, port, serverName, scannerVersion, results, policyResult)
	if err != nil {
		return err
	}
	if !strings.HasSuffix(outputPath, ".xml") {
		outputPath += ".xml"
	}
	return os.WriteFile(outputPath, report, 0640)
}

// BuildJUnitReport builds a JUnit XML report for CI systems.
func BuildJUnitReport(host, port, serverName, scannerVersion string, results []scan.TLSScanResult, policyResult *policy.Result) ([]byte, error) {
	suite := junitTestSuite{
		Name: fmt.Sprintf("tlsanalyzer %s", targetLabel(host, port, serverName)),
		Time: junitSeconds(totalDurationMillis(results)),
	}

	for _, result := range results {
		testCase := junitTestCase{
			ClassName: "tlsanalyzer.tls",
			Name:      result.Version,
			Time:      junitSeconds(result.DurationMillis),
		}
		if isScanExecutionError(result.Status) {
			testCase.Error = &junitFailure{
				Message: valueOrDefault(result.ErrorMessage, result.Status),
				Type:    result.Status,
				Text:    fmt.Sprintf("%s scan ended with %s", result.Version, result.Status),
			}
			suite.Errors++
		}
		suite.TestCases = append(suite.TestCases, testCase)
	}

	if policyResult != nil && policyResult.Enabled {
		if policyResult.Passed {
			suite.TestCases = append(suite.TestCases, junitTestCase{
				ClassName: "tlsanalyzer.policy",
				Name:      "policy." + displayPolicyName(policyResult),
				Time:      "0",
			})
		}
		for _, failure := range policyResult.Failures {
			testCase := junitTestCase{
				ClassName: "tlsanalyzer.policy",
				Name:      "policy." + failure.Check + versionSuffix(failure.Version),
				Time:      "0",
				Failure: &junitFailure{
					Message: failure.Message,
					Type:    failure.Check,
					Text:    failure.Message,
				},
			}
			suite.Failures++
			suite.TestCases = append(suite.TestCases, testCase)
		}
	}

	if len(suite.TestCases) == 0 {
		suite.TestCases = append(suite.TestCases, junitTestCase{
			ClassName: "tlsanalyzer.scan",
			Name:      "scan.completed",
			Time:      "0",
		})
	}

	suite.Tests = len(suite.TestCases)
	suites := junitTestSuites{
		Tests:    suite.Tests,
		Failures: suite.Failures,
		Errors:   suite.Errors,
		Suites:   []junitTestSuite{suite},
	}

	data, err := xml.MarshalIndent(suites, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), data...), nil
}

func policyFailures(result *policy.Result) []policy.Failure {
	if result == nil || !result.Enabled {
		return nil
	}
	return result.Failures
}

func sarifRulesForFailures(failures []policy.Failure) []sarifRule {
	seen := make(map[string]bool)
	rules := make([]sarifRule, 0)
	for _, failure := range failures {
		if seen[failure.Check] {
			continue
		}
		seen[failure.Check] = true
		rules = append(rules, sarifRule{
			ID:               failure.Check,
			Name:             failure.Check,
			ShortDescription: sarifText{Text: "tlsanalyzer policy check " + failure.Check},
			HelpURI:          "https://github.com/olelbis/tlsanalyzer/blob/main/docs/user-manual.md#policy-mode",
			Properties:       sarifRuleProperty{Tags: []string{"tls", "policy"}},
		})
	}
	return rules
}

func sarifResultsForFailures(host, port, serverName string, results []scan.TLSScanResult, failures []policy.Failure) []sarifResult {
	sarifResults := make([]sarifResult, 0, len(failures))
	for _, failure := range failures {
		sarifResults = append(sarifResults, sarifResult{
			RuleID:  failure.Check,
			Level:   "error",
			Message: sarifText{Text: failure.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: targetURI(host, port, serverName)},
					Region:           sarifRegion{Snippet: sarifText{Text: sarifSnippet(failure, results)}},
				},
			}},
		})
	}
	return sarifResults
}

func sarifSnippet(failure policy.Failure, results []scan.TLSScanResult) string {
	for _, result := range results {
		if result.Version == failure.Version {
			return fmt.Sprintf("%s status=%s supported=%t certificate=%s cipher=%s", result.Version, result.Status, result.Supported, valueOrDash(result.CertValidationStatus), valueOrDash(result.CipherDiscovery))
		}
	}
	if failure.Version != "" {
		return failure.Version
	}
	return "target"
}

func targetURI(host, port, serverName string) string {
	label := targetLabel(host, port, serverName)
	return "tlsanalyzer://" + strings.ReplaceAll(label, " ", "%20")
}

func targetLabel(host, port, serverName string) string {
	label := host
	if port != "" {
		label += ":" + port
	}
	if serverName != "" {
		label += " sni=" + serverName
	}
	return label
}

func isScanExecutionError(status string) bool {
	switch status {
	case scan.ScanStatusNetworkError, scan.ScanStatusTimeout, scan.ScanStatusHandshake:
		return true
	default:
		return false
	}
}

func totalDurationMillis(results []scan.TLSScanResult) int64 {
	var total int64
	for _, result := range results {
		total += result.DurationMillis
	}
	return total
}

func junitSeconds(milliseconds int64) string {
	return fmt.Sprintf("%.3f", float64(milliseconds)/float64(time.Second/time.Millisecond))
}

func versionSuffix(version string) string {
	if version == "" {
		return ""
	}
	return "." + strings.ReplaceAll(version, " ", "-")
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
