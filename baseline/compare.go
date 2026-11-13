package baseline

import (
	"crypto/tls"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/olelbis/tlsanalyzer/output"
	"github.com/olelbis/tlsanalyzer/policy"
	"github.com/olelbis/tlsanalyzer/scan"
	"github.com/olelbis/tlsanalyzer/utils"
)

// Comparison is the outcome of comparing a scan with a baseline.
//
// Failures are the changes that make the posture worse; they fail the run like
// any other policy failure. Notes are everything else worth knowing:
// improvements, differences that are not a regression, and comparisons that
// could not be made.
type Comparison struct {
	Failures []policy.Failure
	Notes    []string
}

// Apply adds the comparison to a policy result. The result becomes enabled
// because a baseline is a gate in its own right, and it fails when the
// comparison found a regression.
func (c Comparison) Apply(result *policy.Result) {
	result.Enabled = true
	result.Failures = append(result.Failures, c.Failures...)
	result.Notes = append(result.Notes, c.Notes...)
	result.Passed = len(result.Failures) == 0
}

// NeedsCipherProbe reports whether the baseline holds cipher suite lists that
// a comparison needs the current scan to probe for. Without it the current scan
// would only know the negotiated suite and every other suite would look
// removed.
func NeedsCipherProbe(base *Report) bool {
	if base == nil {
		return false
	}
	for _, r := range base.Results {
		if r.Status == scan.ScanStatusSupported && comparableDiscovery(r.CipherDiscovery) {
			return true
		}
	}
	return false
}

// Compare reports what changed from base to current, judging only what got
// worse as a failure.
//
// A regression is: a legacy TLS version (1.0, 1.1) supported that was not, TLS
// 1.3 no longer supported, a cipher suite that is insecure, weak or
// unclassified that the baseline did not offer, cipher evidence that became
// incomplete, a certificate that is no longer valid, that expires earlier or
// that has a shorter key. A version or certificate that could not be
// determined on either side is never a regression; it is a note.
func Compare(base *Report, current Report) Comparison {
	var c comparison
	baseByVersion := make(map[uint16]output.JSONScanResult, len(base.Results))
	for _, r := range base.Results {
		baseByVersion[r.VersionID] = r
	}
	seen := make(map[uint16]bool, len(current.Results))

	for _, cur := range current.Results {
		seen[cur.VersionID] = true
		b, ok := baseByVersion[cur.VersionID]
		if !ok {
			if cur.Status == scan.ScanStatusSupported {
				c.note("%s is supported but the baseline did not scan it, so it was not compared", cur.Version)
			}
			continue
		}
		c.version(b, cur)
	}

	var missing []string
	for _, r := range base.Results {
		if !seen[r.VersionID] {
			missing = append(missing, r.Version)
		}
	}
	if len(missing) > 0 {
		c.note("%s %s in the baseline but not scanned in this run (--min-version), so %s not compared",
			strings.Join(missing, ", "), plural(len(missing), "is", "are"), plural(len(missing), "it was", "they were"))
	}
	if len(c.cipherSkipped) > 0 {
		c.note("cipher suites were not compared for %s: the baseline holds negotiated-cipher evidence only (record it with --force-ciphers to compare suites)",
			strings.Join(c.cipherSkipped, ", "))
	}
	return Comparison{Failures: c.failures, Notes: c.notes}
}

type comparison struct {
	failures      []policy.Failure
	notes         []string
	cipherSkipped []string
}

func (c *comparison) fail(version, format string, args ...interface{}) {
	c.failures = append(c.failures, policy.Failure{
		Check:   policy.CheckBaseline,
		Version: version,
		Message: fmt.Sprintf(format, args...),
	})
}

func (c *comparison) note(format string, args ...interface{}) {
	c.notes = append(c.notes, "baseline: "+fmt.Sprintf(format, args...))
}

func (c *comparison) version(b, cur output.JSONScanResult) {
	switch {
	case !determined(b.Status) || !determined(cur.Status):
		c.note("%s was not compared: baseline status %s, current status %s", cur.Version, b.Status, cur.Status)
		return
	case b.Status == scan.ScanStatusUnsupported && cur.Status == scan.ScanStatusUnsupported:
		return
	case b.Status == scan.ScanStatusUnsupported:
		if cur.VersionID < tls.VersionTLS12 {
			c.fail(cur.Version, "%s is now supported; it was not in the baseline", cur.Version)
		} else {
			c.note("%s is now supported; it was not in the baseline (improvement)", cur.Version)
		}
		return
	case cur.Status == scan.ScanStatusUnsupported:
		if cur.VersionID == tls.VersionTLS13 {
			c.fail(cur.Version, "%s is no longer supported; it was in the baseline", cur.Version)
		} else {
			c.note("%s is no longer supported; it was in the baseline", cur.Version)
		}
		return
	}

	c.ciphers(b, cur)
	c.certificate(b, cur)
}

func (c *comparison) ciphers(b, cur output.JSONScanResult) {
	if !comparableDiscovery(b.CipherDiscovery) {
		c.cipherSkipped = append(c.cipherSkipped, cur.Version)
		return
	}
	if !comparableDiscovery(cur.CipherDiscovery) {
		c.note("cipher suites of %s were not compared: the current scan holds %s evidence only", cur.Version, cur.CipherDiscovery)
		return
	}

	if cur.CipherEvidenceIncomplete && !b.CipherEvidenceIncomplete {
		c.fail(cur.Version, "%s cipher evidence is incomplete (probes went unanswered); changes since the baseline cannot be ruled out", cur.Version)
	}
	if b.CipherEvidenceIncomplete {
		c.note("%s cipher evidence in the baseline is incomplete, so suites reported as new may already have been offered; record the baseline again", cur.Version)
	}

	baseSuites := stringSet(b.CipherSuites)
	curSuites := stringSet(cur.CipherSuites)

	for _, name := range sortedDifference(curSuites, baseSuites) {
		switch severity := utils.CipherSuiteSeverityForVersion(cur.VersionID, name); severity {
		case utils.CipherSeverityInsecure, utils.CipherSeverityWeak:
			c.fail(cur.Version, "%s now offers %s (%s); the baseline did not", cur.Version, name, severity)
		case utils.CipherSeverityUnknown:
			c.fail(cur.Version, "%s now offers %s (unclassified); the baseline did not", cur.Version, name)
		default:
			c.note("%s now offers %s (%s)", cur.Version, name, severity)
		}
	}
	if !cur.CipherEvidenceIncomplete {
		for _, name := range sortedDifference(baseSuites, curSuites) {
			c.note("%s no longer offers %s", cur.Version, name)
		}
	}
}

func (c *comparison) certificate(b, cur output.JSONScanResult) {
	if b.Certificate == nil {
		return
	}
	if cur.Certificate == nil {
		c.note("the certificate of %s was not compared: the current scan did not retrieve it (%s)", cur.Version, certificateReason(cur))
		return
	}
	baseCert, curCert := b.Certificate, cur.Certificate

	if b.CertValidationStatus == scan.CertValidationValid && cur.CertValidationStatus == scan.CertValidationInvalid {
		message := cur.CertValidationMessage
		if message == "" {
			message = "no reason reported"
		}
		c.fail(cur.Version, "%s certificate validation changed from valid to invalid: %s", cur.Version, message)
	}

	baseExpiry, baseErr := time.Parse(time.RFC3339, baseCert.ValidTo)
	curExpiry, curErr := time.Parse(time.RFC3339, curCert.ValidTo)
	switch {
	case baseErr != nil || curErr != nil:
		c.note("the certificate expiry of %s was not compared: valid_to could not be read", cur.Version)
	case curExpiry.Before(baseExpiry):
		c.fail(cur.Version, "%s certificate expires earlier than in the baseline (%s, was %s)",
			cur.Version, curExpiry.UTC().Format("2006-01-02"), baseExpiry.UTC().Format("2006-01-02"))
	case !curExpiry.Equal(baseExpiry):
		c.note("%s certificate was replaced and now expires %s (was %s)",
			cur.Version, curExpiry.UTC().Format("2006-01-02"), baseExpiry.UTC().Format("2006-01-02"))
	}

	switch {
	case baseCert.PublicKeyAlgorithm != curCert.PublicKeyAlgorithm:
		c.note("%s certificate key algorithm changed from %s to %s", cur.Version, valueOrNone(baseCert.PublicKeyAlgorithm), valueOrNone(curCert.PublicKeyAlgorithm))
	case baseCert.PublicKeyBits > 0 && curCert.PublicKeyBits > 0 && curCert.PublicKeyBits < baseCert.PublicKeyBits:
		c.fail(cur.Version, "%s certificate key is shorter than in the baseline (%d bits, was %d)", cur.Version, curCert.PublicKeyBits, baseCert.PublicKeyBits)
	}
}

func certificateReason(r output.JSONScanResult) string {
	switch {
	case r.VersionEvidence != "":
		return "version detected with a ClientHello-only raw probe"
	case r.CertValidationMessage != "":
		return r.CertValidationMessage
	default:
		return "no certificate in the result"
	}
}

// determined reports whether a version status says for certain whether the
// version is supported. Timeouts, network and handshake errors do not.
func determined(status string) bool {
	return status == scan.ScanStatusSupported || status == scan.ScanStatusUnsupported
}

func comparableDiscovery(discovery string) bool {
	switch discovery {
	case scan.CipherDiscoveryProbed, scan.CipherDiscoveryRawProbed, scan.CipherDiscoveryObserved:
		return true
	default:
		return false
	}
}

func stringSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, v := range values {
		set[v] = true
	}
	return set
}

func sortedDifference(a, b map[string]bool) []string {
	var diff []string
	for v := range a {
		if !b[v] {
			diff = append(diff, v)
		}
	}
	sort.Strings(diff)
	return diff
}

func valueOrNone(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
