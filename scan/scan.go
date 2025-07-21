// File: scan/scan.go
package scan

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"time"
	"tlsanalyzer/utils"
)

type TLSScanResult struct {
	Version      string
	CipherSuites []string
	Supported    bool
	Certificate  *x509.Certificate
}

func ScanTLSVersion(host, port string, version uint16, timeoutSec int) (bool, *x509.Certificate, string, []utils.CertInfo, error) {
	address := net.JoinHostPort(host, port)
	config := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
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
			conn.Close()
			return true, cert, tls.CipherSuiteName(state.CipherSuite), infos, nil
		}
		return false, nil, "", nil, fmt.Errorf("all TLS 1.3 handshakes failed")
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second}, "tcp", address, config)
	if err != nil {
		return false, nil, "", nil, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	infos := utils.ExtractCertInfos(state.PeerCertificates)
	cipher := tls.CipherSuiteName(state.CipherSuite)
	if len(state.PeerCertificates) > 0 {
		return true, state.PeerCertificates[0], cipher, infos, nil
	}
	return true, nil, cipher, infos, nil
}

func GetSupportedCiphersForVersion(host, port string, timeout int, version uint16) []string {
	supported := []string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, utils.DefaultMaxConcurrency)

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
				InsecureSkipVerify: false,
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
					InsecureSkipVerify: false,
					ServerName:         host,
				}
				conn, err := tls.Dial("tcp", net.JoinHostPort(host, port), conf)
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

	return utils.UniqueStrings(supported)
}
