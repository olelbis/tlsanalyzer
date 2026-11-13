package scan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/olelbis/tlsanalyzer/tlsprobe"
	"github.com/olelbis/tlsanalyzer/utils"
)

type TLSScanResult struct {
	Version                   string
	VersionID                 uint16
	DurationMillis            int64
	HandshakeAttempts         int
	KeyExchangeGroup          string
	ALPNProtocol              string
	CipherDiscovery           string
	NegotiatedCipherSuite     string
	CipherSuites              []string
	CipherSuitesObserved      bool
	CipherProbeDurationMillis int64
	CipherProbeResults        []CipherProbeStatus
	// CipherEvidenceIncomplete reports that cipher probing could not classify
	// every suite, so CipherSuites may be missing supported suites.
	CipherEvidenceIncomplete bool
	// VersionEvidence is empty when the protocol version was established by
	// a full crypto/tls handshake, and VersionEvidenceRawProbe when only a
	// ClientHello-only raw probe could establish it. In the second case no
	// certificate, key exchange group or ALPN protocol is available.
	VersionEvidence       string
	Warnings              []string
	Supported             bool
	Status                string
	ErrorMessage          string
	Certificate           *x509.Certificate
	CertInfos             []utils.CertInfo
	CertValidationStatus  string
	CertValidationMessage string
}

type Options struct {
	Host         string
	Port         string
	ServerName   string
	Timeout      time.Duration
	MinVersion   uint16
	ForceCiphers bool
	SkipVerify   bool
}

type CertValidation struct {
	Status  string
	Message string
}

const (
	ScanStatusSupported    = "supported"
	ScanStatusUnsupported  = "unsupported"
	ScanStatusNetworkError = "network_error"
	ScanStatusTimeout      = "timeout"
	ScanStatusHandshake    = "handshake_error"

	CipherDiscoveryNegotiated = "negotiated"
	CipherDiscoveryProbed     = "probed"
	CipherDiscoveryRawProbed  = "raw-probed"
	CipherDiscoveryObserved   = "observed"

	// VersionEvidenceRawProbe marks a protocol version detected from the
	// ServerHello answering a raw ClientHello, without a completed handshake.
	VersionEvidenceRawProbe = "clienthello-serverhello"

	CertValidationValid       = "valid"
	CertValidationInvalid     = "invalid"
	CertValidationSkipped     = "skipped"
	CertValidationUnavailable = "unavailable"
)

type CipherProbeResult struct {
	CipherSuites []string
	Discovery    string
	Attempts     int
	Warnings     []string
	ObservedOnly bool
	// Incomplete reports that some cipher suites could not be classified
	// (dropped or unanswered probes), so absence from CipherSuites does not
	// prove a suite is unsupported.
	Incomplete     bool
	Statuses       []CipherProbeStatus
	DurationMillis int64
}

type CipherProbeStatus struct {
	CipherSuite              string
	Status                   string
	Evidence                 string
	Alert                    string
	AlertLevel               uint8
	AlertDescription         uint8
	SelectedGroup            string
	HelloRetryRequest        bool
	HelloRetryRequestRetried bool
	Error                    string
}

func DefaultALPNProtocols() []string {
	return []string{"h2", "http/1.1"}
}

func ScanTLSVersion(opts Options, version uint16) (result TLSScanResult) {
	start := time.Now()
	result = TLSScanResult{
		Version:           utils.TLSVersions[version],
		VersionID:         version,
		HandshakeAttempts: 1,
		CipherDiscovery:   CipherDiscoveryNegotiated,
		Status:            ScanStatusUnsupported,
	}
	defer func() {
		result.DurationMillis = time.Since(start).Milliseconds()
	}()

	address := net.JoinHostPort(opts.Host, opts.Port)
	serverName := opts.tlsServerName()
	config := &tls.Config{
		ServerName: serverName,
		// Certificate validation is performed after the handshake so TLS support
		// is not confused with certificate trust failures.
		InsecureSkipVerify: true, // #nosec G402 -- scanner handshake, validation done by ValidatePeerCertificates
		MinVersion:         version,
		MaxVersion:         version,
		NextProtos:         DefaultALPNProtocols(),
	}
	if version < tls.VersionTLS13 {
		// Offer the same suites the cipher probe can detect. The crypto/tls
		// default list leaves out legacy suites (static RSA key exchange,
		// 3DES), so an endpoint that only supports those would otherwise look
		// like it does not support the protocol version at all.
		config.CipherSuites = utils.CipherSuiteIDsForVersion(version)
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: opts.Timeout}, "tcp", address, config)
	if err != nil {
		result.Status, result.ErrorMessage = classifyScanError(err)
		if version < tls.VersionTLS13 && rawVersionFallbackApplies(result.Status, err) {
			return rawVersionFallback(opts, version, result)
		}
		return result
	}
	return buildSupportedResult(result, conn, opts, serverName)
}

// rawVersionFallbackApplies reports whether a failed crypto/tls handshake may
// still hide a supported protocol version. That is the case when the server
// was reached and then refused or dropped the handshake. The usual cause is
// that crypto/tls can only offer the suites it implements, so an endpoint
// limited to RC4, NULL, DHE or other suites outside that set refuses every
// crypto/tls ClientHello; an endpoint that demands a client certificate ends
// the handshake the same way.
//
// A version the server explicitly rejects, a timeout and a failed TCP
// connection are final: asking again would not change the answer.
func rawVersionFallbackApplies(status string, err error) bool {
	switch status {
	case ScanStatusHandshake:
		return true
	case ScanStatusNetworkError:
		var opErr *net.OpError
		return !(errors.As(err, &opErr) && opErr.Op == "dial")
	default:
		return false
	}
}

// rawVersionFallback asks the server, with one raw ClientHello offering the
// whole tlsprobe catalog, whether it speaks the protocol version at all. If
// the ServerHello selects a suite on that version the version is reported as
// supported with ClientHello-only evidence; otherwise failed is returned with
// the extra attempt counted.
func rawVersionFallback(opts Options, version uint16, failed TLSScanResult) TLSScanResult {
	failed.HandshakeAttempts++
	raw, err := tlsprobe.SelectLegacyCipherSuite(context.Background(), tlsprobe.Options{
		Address:    net.JoinHostPort(opts.Host, opts.Port),
		ServerName: opts.tlsServerName(),
		Timeout:    opts.Timeout,
		ALPN:       DefaultALPNProtocols(),
	}, version, tlsprobe.LegacyCipherSuitesForVersion(version))
	if err != nil || raw.Status != tlsprobe.StatusSupported {
		return failed
	}

	result := failed
	result.Supported = true
	result.Status = ScanStatusSupported
	// ErrorMessage keeps the reason the full handshake failed.
	result.VersionEvidence = VersionEvidenceRawProbe
	result.NegotiatedCipherSuite = raw.Name
	result.CipherSuites = []string{raw.Name}
	result.CertValidationStatus = CertValidationUnavailable
	result.CertValidationMessage = "certificate not retrieved: the protocol version was detected with a ClientHello-only raw probe"
	result.Warnings = append(result.Warnings, fmt.Sprintf(
		"%s was detected with a ClientHello-only raw probe: the server selected %s, but a full handshake could not be completed (%s). Certificate, key exchange group and ALPN are not available for this version.",
		result.Version, raw.Name, failed.ErrorMessage))
	return result
}

func buildSupportedResult(result TLSScanResult, conn *tls.Conn, opts Options, serverName string) TLSScanResult {
	defer conn.Close()
	state := conn.ConnectionState()
	infos := utils.ExtractCertInfos(state.PeerCertificates)
	validation := ValidatePeerCertificates(serverName, state.PeerCertificates, opts.SkipVerify)
	cipher := tls.CipherSuiteName(state.CipherSuite)
	result.Supported = true
	result.Status = ScanStatusSupported
	result.CertInfos = infos
	result.CertValidationStatus = validation.Status
	result.CertValidationMessage = validation.Message
	result.NegotiatedCipherSuite = cipher
	result.CipherSuites = []string{cipher}
	result.KeyExchangeGroup = keyExchangeGroupName(state)
	result.ALPNProtocol = state.NegotiatedProtocol
	if len(state.PeerCertificates) > 0 {
		result.Certificate = state.PeerCertificates[0]
	}
	return result
}

func keyExchangeGroupName(state tls.ConnectionState) string {
	if state.CurveID == 0 {
		return ""
	}
	return state.CurveID.String()
}

func (opts Options) tlsServerName() string {
	if opts.ServerName != "" {
		return opts.ServerName
	}
	return opts.Host
}

func ValidatePeerCertificates(host string, peerCertificates []*x509.Certificate, skipVerify bool) CertValidation {
	if skipVerify {
		return CertValidation{Status: CertValidationSkipped, Message: "certificate validation skipped"}
	}
	if len(peerCertificates) == 0 {
		return CertValidation{Status: CertValidationUnavailable, Message: "no peer certificate presented"}
	}

	intermediates := x509.NewCertPool()
	for _, cert := range peerCertificates[1:] {
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		DNSName:       host,
		Intermediates: intermediates,
	}
	if _, err := peerCertificates[0].Verify(opts); err != nil {
		return CertValidation{Status: CertValidationInvalid, Message: err.Error()}
	}

	return CertValidation{Status: CertValidationValid, Message: "certificate validation passed"}
}

func GetSupportedCiphersForVersion(opts Options, version uint16) []string {
	return ProbeCipherSuitesForVersion(opts, version).CipherSuites
}

func ProbeCipherSuitesForVersion(opts Options, version uint16) CipherProbeResult {
	start := time.Now()
	supported := []string{}
	result := CipherProbeResult{
		Discovery: CipherDiscoveryProbed,
	}

	if version != tls.VersionTLS13 {
		supported = append(supported, probeLegacyCipherSuites(opts, version, &result)...)
	}

	if version == tls.VersionTLS13 {
		rawResult := probeTLS13CipherSuites(opts)
		result.Attempts = rawResult.Attempts
		result.Statuses = rawResult.Statuses
		if len(rawResult.CipherSuites) > 0 {
			rawResult.DurationMillis = time.Since(start).Milliseconds()
			return rawResult
		}

		result.Discovery = CipherDiscoveryObserved
		result.ObservedOnly = true
		result.Warnings = append(result.Warnings, "TLS 1.3 raw probing did not confirm cipher support; only the cipher suite negotiated by the version handshake is reported.")
	}

	supported = utils.UniqueStrings(supported)
	sort.Strings(supported)
	result.CipherSuites = supported
	result.DurationMillis = time.Since(start).Milliseconds()
	return result
}

// legacyEnumerationChunk is the number of catalog suites offered together in
// one raw enumeration. The catalog is split so that the enumerations can run
// side by side and every ClientHello stays small.
const legacyEnumerationChunk = 32

// runBounded calls fn(i) for every i in [0, n) with at most limit calls in flight.
func runBounded(n, limit int, fn func(i int)) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, limit)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fn(i)
		}()
	}
	wg.Wait()
}

// probeLegacyCipherSuites finds the cipher suites an endpoint supports on one
// TLS 1.0-1.2 version and returns their names.
//
// Step 1 enumerates the whole tlsprobe catalog with raw ClientHellos that
// offer many suites at once: a server that supports k suites costs about k
// connections plus one refusal per chunk, not one connection per catalog
// suite. That keeps the scan below the connection rate limits that endpoints
// and firewalls enforce, and it reaches suites crypto/tls cannot offer (RC4,
// DHE, anonymous, EXPORT, CAMELLIA, ARIA, CCM...).
//
// Step 2 confirms with a full crypto/tls handshake every enumerated suite that
// crypto/tls implements, so those keep full-handshake evidence. Suites that
// only the raw enumeration can see are reported with a ClientHello-only status
// row.
//
// When the enumeration cannot be trusted (it did not finish, or it saw none of
// the suites crypto/tls can negotiate on a version that is known to work), all
// crypto/tls suites are probed one by one, as before the enumeration existed,
// and the result is flagged as incomplete.
func probeLegacyCipherSuites(opts Options, version uint16, result *CipherProbeResult) []string {
	versionName := utils.TLSVersions[version]

	var fullHandshake []utils.CipherSuite
	implemented := make(map[uint16]bool)
	for _, cs := range utils.AllCipherSuites {
		if utils.IsCipherSuiteCompatibleWith(version, cs.ID) {
			fullHandshake = append(fullHandshake, cs)
			implemented[cs.ID] = true
		}
	}

	selected, unresolved, total, reason := enumerateLegacyCipherSuites(opts, version, result)
	implementedSelected := 0
	for id := range selected {
		if implemented[id] {
			implementedSelected++
		}
	}
	switch {
	case reason != "":
		result.Incomplete = true
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"%s: the raw cipher enumeration could not finish (%s); %d of %d legacy cipher suites were not classified, so the cipher list is incomplete.",
			versionName, reason, unresolved, total))
	case implementedSelected == 0 && fullHandshakeSucceeds(opts, version, fullHandshake, result):
		// A full handshake negotiates a crypto/tls suite, so an enumeration
		// that saw none of them is not telling the truth. When the handshake
		// fails too, the endpoint simply has no suite crypto/tls implements
		// (RC4-only, DHE-only...) and the enumeration is consistent.
		result.Incomplete = true
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"%s: the raw cipher enumeration found none of the suites this endpoint negotiates with full handshakes; legacy cipher suites outside the full-handshake probe set could not be verified, so the cipher list is incomplete.",
			versionName))
	}

	// Full-handshake confirmation: only what the enumeration found, or
	// everything crypto/tls implements when the enumeration is not trusted.
	candidates := fullHandshake
	if !result.Incomplete {
		candidates = nil
		for _, cs := range fullHandshake {
			if selected[cs.ID] {
				candidates = append(candidates, cs)
			}
		}
	}
	errs := fullHandshakeCipherProbes(opts, version, candidates, result)

	var supported []string
	timedOut := 0
	rawOnly := make(map[string]bool)
	for i, cs := range candidates {
		switch {
		case errs[i] == nil:
			supported = append(supported, cs.Name)
		case selected[cs.ID]:
			// The server selected it in ServerHello but the full handshake
			// did not complete: keep it, with the weaker evidence.
			rawOnly[cs.Name] = true
		default:
			if status, _ := classifyScanError(errs[i]); status == ScanStatusTimeout {
				timedOut++
			}
		}
		delete(selected, cs.ID)
	}
	for id := range selected {
		rawOnly[tlsprobe.CipherSuiteName(id)] = true
	}

	for name := range rawOnly {
		supported = append(supported, name)
		result.Statuses = append(result.Statuses, CipherProbeStatus{
			CipherSuite: name,
			Status:      string(tlsprobe.StatusSupported),
			Evidence:    "clienthello-serverhello",
		})
	}
	sort.SliceStable(result.Statuses, func(i, j int) bool {
		return result.Statuses[i].CipherSuite < result.Statuses[j].CipherSuite
	})

	if len(rawOnly) > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"%s: %d cipher suite(s) were confirmed only by ClientHello-only raw probes (listed in the cipher probe results); full TLS handshakes are not completed for them.",
			versionName, len(rawOnly)))
	}
	if timedOut > 0 {
		result.Incomplete = true
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"%s: %d of %d full-handshake cipher probes timed out twice; the endpoint or a network device may be dropping probes and the cipher list is incomplete.",
			versionName, timedOut, len(candidates)))
	}
	return supported
}

// fullHandshakeSucceeds reports whether one crypto/tls handshake offering all
// of suites completes on the given version.
func fullHandshakeSucceeds(opts Options, version uint16, suites []utils.CipherSuite, result *CipherProbeResult) bool {
	ids := make([]uint16, 0, len(suites))
	for _, cs := range suites {
		ids = append(ids, cs.ID)
	}
	if len(ids) == 0 {
		return false
	}
	result.Attempts++
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: opts.Timeout}, "tcp", net.JoinHostPort(opts.Host, opts.Port), &tls.Config{
		MinVersion:         version,
		MaxVersion:         version,
		CipherSuites:       ids,
		InsecureSkipVerify: true, // #nosec G402 -- scanner probe, validation done separately
		ServerName:         opts.tlsServerName(),
		NextProtos:         DefaultALPNProtocols(),
	})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// enumerateLegacyCipherSuites runs the raw enumeration over the tlsprobe
// catalog. It returns the IDs the server selected, the number of catalog
// suites left unclassified out of total, and a short reason when the
// enumeration could not finish.
func enumerateLegacyCipherSuites(opts Options, version uint16, result *CipherProbeResult) (selected map[uint16]bool, unresolved, total int, reason string) {
	selected = make(map[uint16]bool)
	catalog := tlsprobe.LegacyCipherSuitesForVersion(version)
	total = len(catalog)

	rawOptions := tlsprobe.Options{
		Address:    net.JoinHostPort(opts.Host, opts.Port),
		ServerName: opts.tlsServerName(),
		Timeout:    opts.Timeout,
		ALPN:       DefaultALPNProtocols(),
	}
	if err := tlsprobe.ValidateOptions(rawOptions); err != nil {
		return selected, total, total, err.Error()
	}

	var chunks [][]uint16
	for start := 0; start < len(catalog); start += legacyEnumerationChunk {
		end := start + legacyEnumerationChunk
		if end > len(catalog) {
			end = len(catalog)
		}
		chunks = append(chunks, catalog[start:end])
	}

	enumerations := make([]tlsprobe.LegacyEnumeration, len(chunks))
	enumerationErrors := make([]error, len(chunks))
	runBounded(len(chunks), len(chunks), func(i int) {
		enumerations[i], enumerationErrors[i] = tlsprobe.EnumerateLegacyCipherSuites(context.Background(), rawOptions, version, chunks[i])
	})

	for i, enumeration := range enumerations {
		result.Attempts += enumeration.Connections
		for _, supported := range enumeration.Supported {
			selected[supported.CipherSuite] = true
		}
		if enumeration.Complete && enumerationErrors[i] == nil {
			continue
		}
		unresolved += len(enumeration.Unresolved)
		if reason != "" {
			continue
		}
		switch {
		case enumerationErrors[i] != nil:
			reason = enumerationErrors[i].Error()
		case enumeration.Last.Error != "":
			reason = string(enumeration.Last.Status) + ": " + enumeration.Last.Error
		default:
			reason = string(enumeration.Last.Status)
		}
	}
	return selected, unresolved, total, reason
}

// fullHandshakeCipherProbes offers each suite in its own crypto/tls handshake
// and returns one error per suite, nil when the suite was negotiated.
//
// A handshake that fails for a network reason (timeout, reset, refused) says
// nothing about the suite, so those probes are repeated once.
func fullHandshakeCipherProbes(opts Options, version uint16, suites []utils.CipherSuite, result *CipherProbeResult) []error {
	errs := make([]error, len(suites))
	dial := func(i int) {
		conf := &tls.Config{
			MinVersion:   version,
			MaxVersion:   version,
			CipherSuites: []uint16{suites[i].ID},
			// Cipher probing only needs the server to accept or reject
			// the offered suite; certificate trust is evaluated once by
			// ValidatePeerCertificates, not on every probe connection.
			InsecureSkipVerify: true, // #nosec G402 -- scanner probe, validation done separately
			ServerName:         opts.tlsServerName(),
			NextProtos:         DefaultALPNProtocols(),
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: opts.Timeout}, "tcp", net.JoinHostPort(opts.Host, opts.Port), conf)
		if err == nil {
			conn.Close()
		}
		errs[i] = err
	}

	result.Attempts += len(suites)
	runBounded(len(suites), utils.DefaultMaxConcurrency, dial)

	var retry []int
	for i, err := range errs {
		if isTransientProbeError(err) {
			retry = append(retry, i)
		}
	}
	if len(retry) > 0 {
		result.Attempts += len(retry)
		runBounded(len(retry), utils.DefaultMaxConcurrency, func(i int) { dial(retry[i]) })
	}
	return errs
}

// isTransientProbeError reports whether a failed probe handshake was caused by
// the network rather than by the server refusing the offered cipher suite.
func isTransientProbeError(err error) bool {
	if err == nil {
		return false
	}
	status, _ := classifyScanError(err)
	return status == ScanStatusTimeout || status == ScanStatusNetworkError
}

func probeTLS13CipherSuites(opts Options) CipherProbeResult {
	cipherIDs := tlsprobe.SupportedTLS13CipherSuites()
	probeResults, err := tlsprobe.ProbeTLS13CipherSuites(context.Background(), tlsprobe.Options{
		Address:    net.JoinHostPort(opts.Host, opts.Port),
		ServerName: opts.tlsServerName(),
		Timeout:    opts.Timeout,
		ALPN:       DefaultALPNProtocols(),
	}, cipherIDs)

	result := CipherProbeResult{
		Discovery: CipherDiscoveryRawProbed,
		Attempts:  len(cipherIDs),
		Warnings: []string{
			"TLS 1.3 cipher suites were raw-probed with ClientHello-only handshakes; full TLS handshakes are not completed by the raw probe.",
		},
	}
	if err != nil {
		result.Warnings = append(result.Warnings, "TLS 1.3 raw probe failed: "+err.Error())
		return result
	}

	for _, probeResult := range probeResults {
		result.Statuses = append(result.Statuses, CipherProbeStatus{
			CipherSuite:              probeResult.Name,
			Status:                   string(probeResult.Status),
			Evidence:                 rawProbeEvidence(probeResult),
			Alert:                    probeResult.Alert,
			AlertLevel:               probeResult.AlertLevel,
			AlertDescription:         probeResult.AlertDescription,
			SelectedGroup:            probeResult.SelectedGroupName,
			HelloRetryRequest:        probeResult.HelloRetryRequest,
			HelloRetryRequestRetried: probeResult.HelloRetryRequestRetried,
			Error:                    probeResult.Error,
		})
		if probeResult.Status == tlsprobe.StatusSupported {
			result.CipherSuites = append(result.CipherSuites, probeResult.Name)
		}
		if probeResult.Status == tlsprobe.StatusHelloRetryRequest {
			result.Warnings = append(result.Warnings, probeResult.Name+" returned HelloRetryRequest; the raw probe could not complete the retry.")
		}
	}

	result.CipherSuites = utils.UniqueStrings(result.CipherSuites)
	sort.Strings(result.CipherSuites)
	return result
}

func rawProbeEvidence(result tlsprobe.Result) string {
	switch result.Status {
	case tlsprobe.StatusSupported, tlsprobe.StatusRejected:
		if result.HelloRetryRequestRetried {
			return "clienthello-hrr-serverhello"
		}
		return "clienthello-serverhello"
	case tlsprobe.StatusHelloRetryRequest:
		return "clienthello-hello-retry-request"
	case tlsprobe.StatusAlert:
		return "clienthello-alert"
	case tlsprobe.StatusTimeout:
		return "clienthello-timeout"
	case tlsprobe.StatusClosed:
		return "clienthello-closed"
	default:
		return "clienthello-inconclusive"
	}
}

func classifyScanError(err error) (string, string) {
	message := err.Error()
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ScanStatusTimeout, message
	}

	lowerMessage := strings.ToLower(message)
	if strings.Contains(lowerMessage, "protocol version not supported") ||
		strings.Contains(lowerMessage, "unsupported protocol") ||
		strings.Contains(lowerMessage, "unsupported versions") ||
		strings.Contains(lowerMessage, "no supported versions satisfy") {
		return ScanStatusUnsupported, message
	}
	if strings.Contains(lowerMessage, "handshake failure") ||
		strings.Contains(lowerMessage, "bad certificate") ||
		strings.Contains(lowerMessage, "certificate required") ||
		strings.Contains(lowerMessage, "unknown certificate") {
		return ScanStatusHandshake, message
	}

	return ScanStatusNetworkError, message
}
