package baseline

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/olelbis/tlsanalyzer/output"
	"github.com/olelbis/tlsanalyzer/policy"
	"github.com/olelbis/tlsanalyzer/scan"
)

func cert(validTo, algorithm string, bits int) *output.JSONCertificate {
	return &output.JSONCertificate{ValidFrom: "2026-01-01T00:00:00Z", ValidTo: validTo, PublicKeyAlgorithm: algorithm, PublicKeyBits: bits}
}

func version(id uint16, name, status string, suites []string, c *output.JSONCertificate) output.JSONScanResult {
	r := output.JSONScanResult{Version: name, VersionID: id, Status: status, Supported: status == scan.ScanStatusSupported}
	if r.Supported {
		r.CipherDiscovery = scan.CipherDiscoveryProbed
		r.CipherSuites = suites
		r.Certificate = c
		r.CertValidationStatus = scan.CertValidationValid
	} else {
		r.CipherDiscovery = scan.CipherDiscoveryNegotiated
	}
	return r
}

func report(results ...output.JSONScanResult) *Report {
	return &Report{Host: "example.com", Port: "443", Results: results}
}

const (
	gcm    = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	gcm256 = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	rc4    = "TLS_RSA_WITH_RC4_128_SHA"
	cbc    = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
)

func failureMessages(c Comparison) string {
	var parts []string
	for _, f := range c.Failures {
		if f.Check != policy.CheckBaseline {
			panic("failure with check " + f.Check)
		}
		parts = append(parts, f.Message)
	}
	return strings.Join(parts, " | ")
}

func notes(c Comparison) string { return strings.Join(c.Notes, " | ") }

func TestCompareIdenticalReportsHaveNoFailuresOrNotes(t *testing.T) {
	base := report(
		version(tls.VersionTLS12, "TLS 1.2", "supported", []string{gcm, cbc}, cert("2027-01-01T00:00:00Z", "RSA", 2048)),
		version(tls.VersionTLS11, "TLS 1.1", "unsupported", nil, nil),
	)
	got := Compare(base, *base)
	if len(got.Failures) != 0 || len(got.Notes) != 0 {
		t.Fatalf("Compare(x, x) = %+v, want nothing", got)
	}
}

func TestCompareVersionChanges(t *testing.T) {
	tests := []struct {
		name         string
		base, cur    output.JSONScanResult
		wantFailure  string
		wantNote     string
		wantNoReport bool
	}{
		{
			name:        "legacy version appears",
			base:        version(tls.VersionTLS10, "TLS 1.0", "unsupported", nil, nil),
			cur:         version(tls.VersionTLS10, "TLS 1.0", "supported", []string{cbc}, cert("2027-01-01T00:00:00Z", "RSA", 2048)),
			wantFailure: "TLS 1.0 is now supported",
		},
		{
			name:     "TLS 1.3 appears",
			base:     version(tls.VersionTLS13, "TLS 1.3", "unsupported", nil, nil),
			cur:      version(tls.VersionTLS13, "TLS 1.3", "supported", nil, cert("2027-01-01T00:00:00Z", "RSA", 2048)),
			wantNote: "TLS 1.3 is now supported",
		},
		{
			name:        "TLS 1.3 disappears",
			base:        version(tls.VersionTLS13, "TLS 1.3", "supported", nil, cert("2027-01-01T00:00:00Z", "RSA", 2048)),
			cur:         version(tls.VersionTLS13, "TLS 1.3", "unsupported", nil, nil),
			wantFailure: "TLS 1.3 is no longer supported",
		},
		{
			name:     "TLS 1.2 disappears",
			base:     version(tls.VersionTLS12, "TLS 1.2", "supported", []string{gcm}, cert("2027-01-01T00:00:00Z", "RSA", 2048)),
			cur:      version(tls.VersionTLS12, "TLS 1.2", "unsupported", nil, nil),
			wantNote: "TLS 1.2 is no longer supported",
		},
		{
			name:     "legacy version disappears",
			base:     version(tls.VersionTLS10, "TLS 1.0", "supported", []string{cbc}, cert("2027-01-01T00:00:00Z", "RSA", 2048)),
			cur:      version(tls.VersionTLS10, "TLS 1.0", "unsupported", nil, nil),
			wantNote: "TLS 1.0 is no longer supported",
		},
		{
			name:     "a timeout is not a verdict",
			base:     version(tls.VersionTLS13, "TLS 1.3", "supported", nil, cert("2027-01-01T00:00:00Z", "RSA", 2048)),
			cur:      version(tls.VersionTLS13, "TLS 1.3", "timeout", nil, nil),
			wantNote: "TLS 1.3 was not compared: baseline status supported, current status timeout",
		},
		{
			name:     "an undetermined baseline is not a verdict either",
			base:     version(tls.VersionTLS10, "TLS 1.0", "network_error", nil, nil),
			cur:      version(tls.VersionTLS10, "TLS 1.0", "supported", []string{cbc}, cert("2027-01-01T00:00:00Z", "RSA", 2048)),
			wantNote: "TLS 1.0 was not compared",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compare(report(tt.base), *report(tt.cur))
			if tt.wantFailure != "" {
				if !strings.Contains(failureMessages(got), tt.wantFailure) {
					t.Fatalf("failures = %q, want %q (notes %q)", failureMessages(got), tt.wantFailure, notes(got))
				}
				return
			}
			if len(got.Failures) != 0 {
				t.Fatalf("failures = %q, want none", failureMessages(got))
			}
			if !strings.Contains(notes(got), tt.wantNote) {
				t.Fatalf("notes = %q, want %q", notes(got), tt.wantNote)
			}
		})
	}
}

func TestCompareCipherSuites(t *testing.T) {
	cur := func(suites ...string) *Report {
		return report(version(tls.VersionTLS12, "TLS 1.2", "supported", suites, cert("2027-01-01T00:00:00Z", "RSA", 2048)))
	}
	base := cur(gcm, cbc)

	t.Run("weak suite added fails", func(t *testing.T) {
		got := Compare(base, *cur(gcm, cbc, rc4))
		if m := failureMessages(got); !strings.Contains(m, "now offers "+rc4) {
			t.Fatalf("failures = %q, want one naming %s", m, rc4)
		}
	})
	t.Run("unclassified suite added fails", func(t *testing.T) {
		got := Compare(base, *cur(gcm, cbc, "TLS_ECDHE_RSA_WITH_FUTURE_128_GCM_SHA256"))
		if m := failureMessages(got); !strings.Contains(m, "unclassified") {
			t.Fatalf("failures = %q, want an unclassified suite failure", m)
		}
	})
	t.Run("strong suite added is a note", func(t *testing.T) {
		got := Compare(base, *cur(gcm, cbc, gcm256))
		if len(got.Failures) != 0 || !strings.Contains(notes(got), "now offers "+gcm256) {
			t.Fatalf("got failures %q notes %q, want a note only", failureMessages(got), notes(got))
		}
	})
	t.Run("suite removed is a note, even a strong one", func(t *testing.T) {
		got := Compare(base, *cur(gcm))
		if len(got.Failures) != 0 || !strings.Contains(notes(got), "no longer offers "+cbc) {
			t.Fatalf("got failures %q notes %q, want a note only", failureMessages(got), notes(got))
		}
	})
	t.Run("order does not matter", func(t *testing.T) {
		got := Compare(base, *cur(cbc, gcm))
		if len(got.Failures) != 0 || len(got.Notes) != 0 {
			t.Fatalf("got %+v, want nothing", got)
		}
	})
	t.Run("incomplete evidence became a failure", func(t *testing.T) {
		current := cur(gcm)
		current.Results[0].CipherEvidenceIncomplete = true
		got := Compare(base, *current)
		if m := failureMessages(got); !strings.Contains(m, "cipher evidence is incomplete") {
			t.Fatalf("failures = %q, want an incomplete evidence failure", m)
		}
		if strings.Contains(notes(got), "no longer offers") {
			t.Fatalf("notes = %q, removals must not be claimed from incomplete evidence", notes(got))
		}
	})
	t.Run("incomplete baseline is explained", func(t *testing.T) {
		incomplete := cur(gcm)
		incomplete.Results[0].CipherEvidenceIncomplete = true
		got := Compare(incomplete, *cur(gcm, gcm256))
		if len(got.Failures) != 0 || !strings.Contains(notes(got), "baseline is incomplete") {
			t.Fatalf("got failures %q notes %q", failureMessages(got), notes(got))
		}
	})
	t.Run("negotiated-only baseline cannot compare suites", func(t *testing.T) {
		negotiated := cur(gcm)
		negotiated.Results[0].CipherDiscovery = scan.CipherDiscoveryNegotiated
		got := Compare(negotiated, *cur(gcm, rc4))
		if len(got.Failures) != 0 || !strings.Contains(notes(got), "cipher suites were not compared for TLS 1.2") {
			t.Fatalf("got failures %q notes %q, want a not-compared note", failureMessages(got), notes(got))
		}
	})
}

func TestCompareCertificate(t *testing.T) {
	with := func(c *output.JSONCertificate) *Report {
		return report(version(tls.VersionTLS12, "TLS 1.2", "supported", []string{gcm}, c))
	}
	base := with(cert("2027-01-01T00:00:00Z", "RSA", 2048))

	t.Run("expires earlier fails", func(t *testing.T) {
		got := Compare(base, *with(cert("2026-12-01T00:00:00Z", "RSA", 2048)))
		if m := failureMessages(got); !strings.Contains(m, "expires earlier than in the baseline (2026-12-01, was 2027-01-01)") {
			t.Fatalf("failures = %q", m)
		}
	})
	t.Run("renewal is a note", func(t *testing.T) {
		got := Compare(base, *with(cert("2028-01-01T00:00:00Z", "RSA", 2048)))
		if len(got.Failures) != 0 || !strings.Contains(notes(got), "certificate was replaced and now expires 2028-01-01") {
			t.Fatalf("got failures %q notes %q", failureMessages(got), notes(got))
		}
	})
	t.Run("shorter key fails", func(t *testing.T) {
		got := Compare(base, *with(cert("2027-01-01T00:00:00Z", "RSA", 1024)))
		if m := failureMessages(got); !strings.Contains(m, "key is shorter than in the baseline (1024 bits, was 2048)") {
			t.Fatalf("failures = %q", m)
		}
	})
	t.Run("longer key is silent", func(t *testing.T) {
		got := Compare(base, *with(cert("2027-01-01T00:00:00Z", "RSA", 4096)))
		if len(got.Failures) != 0 || len(got.Notes) != 0 {
			t.Fatalf("got %+v, want nothing", got)
		}
	})
	t.Run("algorithm change is a note, bits are not comparable", func(t *testing.T) {
		got := Compare(base, *with(cert("2027-01-01T00:00:00Z", "ECDSA", 256)))
		if len(got.Failures) != 0 || !strings.Contains(notes(got), "key algorithm changed from RSA to ECDSA") {
			t.Fatalf("got failures %q notes %q", failureMessages(got), notes(got))
		}
	})
	t.Run("valid to invalid fails", func(t *testing.T) {
		current := with(cert("2027-01-01T00:00:00Z", "RSA", 2048))
		current.Results[0].CertValidationStatus = scan.CertValidationInvalid
		current.Results[0].CertValidationMessage = "x509: certificate signed by unknown authority"
		got := Compare(base, *current)
		if m := failureMessages(got); !strings.Contains(m, "changed from valid to invalid: x509: certificate signed by unknown authority") {
			t.Fatalf("failures = %q", m)
		}
	})
	t.Run("missing certificate is a note", func(t *testing.T) {
		current := with(nil)
		current.Results[0].VersionEvidence = scan.VersionEvidenceRawProbe
		got := Compare(base, *current)
		if len(got.Failures) != 0 || !strings.Contains(notes(got), "was not compared: the current scan did not retrieve it (version detected with a ClientHello-only raw probe)") {
			t.Fatalf("got failures %q notes %q", failureMessages(got), notes(got))
		}
	})
}

func TestCompareScanRangeDifferences(t *testing.T) {
	base := report(
		version(tls.VersionTLS10, "TLS 1.0", "unsupported", nil, nil),
		version(tls.VersionTLS11, "TLS 1.1", "unsupported", nil, nil),
		version(tls.VersionTLS12, "TLS 1.2", "supported", []string{gcm}, cert("2027-01-01T00:00:00Z", "RSA", 2048)),
	)
	current := report(version(tls.VersionTLS12, "TLS 1.2", "supported", []string{gcm}, cert("2027-01-01T00:00:00Z", "RSA", 2048)))
	got := Compare(base, *current)
	if len(got.Failures) != 0 || !strings.Contains(notes(got), "TLS 1.0, TLS 1.1 are in the baseline but not scanned in this run") {
		t.Fatalf("got failures %q notes %q", failureMessages(got), notes(got))
	}

	// A version the baseline never scanned cannot be called a regression.
	wider := report(version(tls.VersionTLS12, "TLS 1.2", "supported", []string{gcm}, cert("2027-01-01T00:00:00Z", "RSA", 2048)))
	narrow := report(
		version(tls.VersionTLS11, "TLS 1.1", "supported", []string{cbc}, cert("2027-01-01T00:00:00Z", "RSA", 2048)),
		version(tls.VersionTLS12, "TLS 1.2", "supported", []string{gcm}, cert("2027-01-01T00:00:00Z", "RSA", 2048)),
	)
	got = Compare(wider, *narrow)
	if len(got.Failures) != 0 || !strings.Contains(notes(got), "TLS 1.1 is supported but the baseline did not scan it") {
		t.Fatalf("got failures %q notes %q", failureMessages(got), notes(got))
	}
}

func TestNeedsCipherProbe(t *testing.T) {
	probed := report(version(tls.VersionTLS12, "TLS 1.2", "supported", []string{gcm}, nil))
	if !NeedsCipherProbe(probed) {
		t.Fatal("NeedsCipherProbe() = false for a baseline with probed suites")
	}
	negotiated := report(version(tls.VersionTLS12, "TLS 1.2", "supported", []string{gcm}, nil))
	negotiated.Results[0].CipherDiscovery = scan.CipherDiscoveryNegotiated
	if NeedsCipherProbe(negotiated) {
		t.Fatal("NeedsCipherProbe() = true for a negotiated-only baseline")
	}
	if NeedsCipherProbe(nil) {
		t.Fatal("NeedsCipherProbe(nil) = true")
	}
}

func TestApplyEnablesAndFailsThePolicyResult(t *testing.T) {
	result := policy.Result{Passed: true}
	Comparison{Notes: []string{"baseline: something changed"}}.Apply(&result)
	if !result.Enabled || !result.Passed || len(result.Notes) != 1 {
		t.Fatalf("Apply(notes only) = %+v, want enabled and passed", result)
	}
	Comparison{Failures: []policy.Failure{{Check: policy.CheckBaseline, Message: "worse"}}}.Apply(&result)
	if result.Passed || len(result.Failures) != 1 {
		t.Fatalf("Apply(failure) = %+v, want failed", result)
	}

	// A failure from another gate stays a failure.
	other := policy.Result{Failures: []policy.Failure{{Check: policy.CheckWeakCipher, Message: "rc4"}}}
	Comparison{}.Apply(&other)
	if other.Passed {
		t.Fatal("Apply(empty) must not turn a failed policy result into a passing one")
	}
}
