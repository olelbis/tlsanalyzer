// File: scan/scan.go
package scan

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/olelbis/tlsanalyzer/utils"
)

type TLSScanResult struct {
	Version               string
	CipherSuites          []string
	CipherSuitesObserved  bool
	Supported             bool
	Certificate           *x509.Certificate
	CertValidationStatus  string
	CertValidationMessage string
}

type CertValidation struct {
	Status  string
	Message string
}

const (
	CertValidationValid       = "valid"
	CertValidationInvalid     = "invalid"
	CertValidationSkipped     = "skipped"
	CertValidationUnavailable = "unavailable"
)

func ScanTLSVersion(host, port string, version uint16, timeoutSec int, skipVerify bool) (bool, *x509.Certificate, string, []utils.CertInfo, CertValidation, error) {
	address := net.JoinHostPort(host, port)
	config := &tls.Config{
		ServerName: host,
		// Certificate validation is performed after the handshake so TLS support
		// is not confused with certificate trust failures.
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
	}

	if *ForceCiphers && version <= tls.VersionTLS12 {
		var suiteIDs []uint16
		for _, cs := range utils.AllCipherSuites {
			suiteIDs = append(suiteIDs, cs.ID)
		}
		config.CipherSuites = suiteIDs
		fmt.Printf("\n🔧 Forcing cipher suites for %s", utils.TLSVersions[version])
	}

	fmt.Printf("\n👉 Trying TLS version %s", utils.TLSVersions[version])

	if *ForceCiphers && version == tls.VersionTLS13 {
		var cert *x509.Certificate
		var infos []utils.CertInfo
		for i := 0; i < utils.DefaultTLS13Tries; i++ {
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second}, "tcp", address, config)
			if err != nil {
				continue
			}
			state := conn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				cert = state.PeerCertificates[0]
			}
			infos = utils.ExtractCertInfos(state.PeerCertificates)
			validation := ValidatePeerCertificates(host, state.PeerCertificates, skipVerify)
			conn.Close()
			return true, cert, tls.CipherSuiteName(state.CipherSuite), infos, validation, nil
		}
		return false, nil, "", nil, CertValidation{}, fmt.Errorf("all TLS 1.3 handshakes failed")
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second}, "tcp", address, config)
	if err != nil {
		return false, nil, "", nil, CertValidation{}, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	infos := utils.ExtractCertInfos(state.PeerCertificates)
	validation := ValidatePeerCertificates(host, state.PeerCertificates, skipVerify)
	cipher := tls.CipherSuiteName(state.CipherSuite)
	if len(state.PeerCertificates) > 0 {
		return true, state.PeerCertificates[0], cipher, infos, validation, nil
	}
	return true, nil, cipher, infos, validation, nil
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

func GetSupportedCiphersForVersion(host, port string, timeout int, version uint16) []string {
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
					ServerName:         host,
				}
				conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Duration(timeout) * time.Second}, "tcp", net.JoinHostPort(host, port), conf)
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
					ServerName:         host,
				}
				conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Duration(timeout) * time.Second}, "tcp", net.JoinHostPort(host, port), conf)
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
