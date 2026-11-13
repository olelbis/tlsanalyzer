package analyzer

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/olelbis/tlsanalyzer/policy"
	"github.com/olelbis/tlsanalyzer/scan"
)

// An endpoint whose only suites are outside what crypto/tls can negotiate used
// to look like it supported no TLS version at all: every handshake failed, so
// policy gates had nothing to judge. It must be scanned and fail the gates.
func TestRunJudgesEndpointGoCannotNegotiateWith(t *testing.T) {
	host, port := cipherServer(t, []uint16{tls.TLS_RSA_WITH_RC4_128_SHA})

	result, err := Run(scanRangeOptions(host, port, tls.VersionTLS12, policy.Config{FailOn: []string{policy.CheckWeakCipher}}), Hooks{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if RunFailed(result.Results) {
		t.Fatal("RunFailed() = true, want the endpoint to be scanned")
	}

	var tls12 *scan.TLSScanResult
	for i := range result.Results {
		if result.Results[i].VersionID == tls.VersionTLS12 {
			tls12 = &result.Results[i]
		}
	}
	if tls12 == nil || !tls12.Supported || tls12.VersionEvidence != scan.VersionEvidenceRawProbe {
		t.Fatalf("TLS 1.2 result = %+v, want supported with raw version evidence", tls12)
	}
	if tls12.CipherEvidenceIncomplete {
		t.Fatalf("CipherEvidenceIncomplete = true, warnings %v", tls12.Warnings)
	}

	if result.Policy.Passed {
		t.Fatal("weak-cipher gate passed on an RC4-only endpoint")
	}
	for _, failure := range result.Policy.Failures {
		if strings.Contains(failure.Message, "incomplete") {
			t.Fatalf("unexpected incomplete-evidence failure: %+v", failure)
		}
	}
	found := false
	for _, failure := range result.Policy.Failures {
		if failure.Check == policy.CheckWeakCipher && strings.Contains(failure.Message, "TLS_RSA_WITH_RC4_128_SHA") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Failures = %+v, want a weak-cipher failure naming TLS_RSA_WITH_RC4_128_SHA", result.Policy.Failures)
	}
}
