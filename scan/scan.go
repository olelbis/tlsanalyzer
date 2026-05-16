// File: scan/scan.go
package scan

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/olelbis/tlsanalyzer/utils"
)

type TLSScanResult struct {
	Version               string
	VersionID             uint16
	CipherSuites          []string
	CipherSuitesObserved  bool
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

	CertValidationValid       = "valid"
	CertValidationInvalid     = "invalid"
	CertValidationSkipped     = "skipped"
	CertValidationUnavailable = "unavailable"
)

func ScanTLSVersion(opts Options, version uint16) TLSScanResult {
	result := TLSScanResult{
		Version:   utils.TLSVersions[version],
		VersionID: version,
		Status:    ScanStatusUnsupported,
	}

	address := net.JoinHostPort(opts.Host, opts.Port)
	config := &tls.Config{
		ServerName: opts.Host,
		// Certificate validation is performed after the handshake so TLS support
		// is not confused with certificate trust failures.
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
	}

	if opts.ForceCiphers && version <= tls.VersionTLS12 {
		var suiteIDs []uint16
		for _, cs := range utils.AllCipherSuites {
			suiteIDs = append(suiteIDs, cs.ID)
		}
		config.CipherSuites = suiteIDs
	}

	if opts.ForceCiphers && version == tls.VersionTLS13 {
		for i := 0; i < utils.DefaultTLS13Tries; i++ {
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: opts.Timeout}, "tcp", address, config)
			if err != nil {
				status, message := classifyScanError(err)
				result.Status = status
				result.ErrorMessage = message
				continue
			}
			return buildSupportedResult(result, conn, opts)
		}
		if result.ErrorMessage == "" {
			result.ErrorMessage = "all TLS 1.3 handshakes failed"
		}
		return result
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: opts.Timeout}, "tcp", address, config)
	if err != nil {
		result.Status, result.ErrorMessage = classifyScanError(err)
		return result
	}
	return buildSupportedResult(result, conn, opts)
}

func buildSupportedResult(result TLSScanResult, conn *tls.Conn, opts Options) TLSScanResult {
	defer conn.Close()
	state := conn.ConnectionState()
	infos := utils.ExtractCertInfos(state.PeerCertificates)
	validation := ValidatePeerCertificates(opts.Host, state.PeerCertificates, opts.SkipVerify)
	cipher := tls.CipherSuiteName(state.CipherSuite)
	result.Supported = true
	result.Status = ScanStatusSupported
	result.CertInfos = infos
	result.CertValidationStatus = validation.Status
	result.CertValidationMessage = validation.Message
	result.CipherSuites = []string{cipher}
	if len(state.PeerCertificates) > 0 {
		result.Certificate = state.PeerCertificates[0]
	}
	return result
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
	supported := []string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, utils.DefaultMaxConcurrency)

	if version != tls.VersionTLS13 {
		for _, cs := range utils.AllCipherSuites {
			if !utils.IsCipherSuiteCompatibleWith(version, cs.ID) {
				continue
			}
			cs := cs
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				conf := &tls.Config{
					MinVersion:         version,
					MaxVersion:         version,
					CipherSuites:       []uint16{cs.ID},
					InsecureSkipVerify: true,
					ServerName:         opts.Host,
				}
				conn, err := tls.DialWithDialer(&net.Dialer{Timeout: opts.Timeout}, "tcp", net.JoinHostPort(opts.Host, opts.Port), conf)
				if err == nil {
					conn.Close()
					mu.Lock()
					supported = append(supported, cs.Name)
					mu.Unlock()
				}
			}()
		}

		wg.Wait()
	}

	if version == tls.VersionTLS13 {
		found := make(map[string]bool)
		var tls13Mutex sync.Mutex
		var wg3 sync.WaitGroup
		for i := 0; i < utils.DefaultTLS13Tries; i++ {
			wg3.Add(1)
			go func() {
				defer wg3.Done()
				conf := &tls.Config{
					MinVersion:         tls.VersionTLS13,
					MaxVersion:         tls.VersionTLS13,
					InsecureSkipVerify: true,
					ServerName:         opts.Host,
				}
				conn, err := tls.DialWithDialer(&net.Dialer{Timeout: opts.Timeout}, "tcp", net.JoinHostPort(opts.Host, opts.Port), conf)
				if err == nil {
					cs := tls.CipherSuiteName(conn.ConnectionState().CipherSuite)
					tls13Mutex.Lock()
					found[cs] = true
					tls13Mutex.Unlock()
					conn.Close()
				}
			}()
		}
		wg3.Wait()
		for cs := range found {
			supported = append(supported, cs)
		}
	}

	supported = utils.UniqueStrings(supported)
	sort.Strings(supported)
	return supported
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
