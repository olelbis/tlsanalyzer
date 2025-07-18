package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxConcurrency = 20
	defaultTLS13Tries     = 10
	defaultTimeout        = 5
)

var tlsVersions = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

var allCipherSuites = []struct {
	id   uint16
	name string
}{
	{tls.TLS_RSA_WITH_RC4_128_SHA, "TLS_RSA_WITH_RC4_128_SHA"},
	{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
	{tls.TLS_RSA_WITH_AES_128_CBC_SHA, "TLS_RSA_WITH_AES_128_CBC_SHA"},
	{tls.TLS_RSA_WITH_AES_256_CBC_SHA, "TLS_RSA_WITH_AES_256_CBC_SHA"},
	{tls.TLS_RSA_WITH_AES_128_CBC_SHA256, "TLS_RSA_WITH_AES_128_CBC_SHA256"},
	{tls.TLS_RSA_WITH_AES_128_GCM_SHA256, "TLS_RSA_WITH_AES_128_GCM_SHA256"},
	{tls.TLS_RSA_WITH_AES_256_GCM_SHA384, "TLS_RSA_WITH_AES_256_GCM_SHA384"},
	{tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"},
	{tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"},
	{tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"},
	{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
	{tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"},
	{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
	{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
	{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
	{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"},
	{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"},
	{tls.TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256"},
	{tls.TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384"},
	{tls.TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256"},
}

type SecurityLevel int

const (
	SecurityInsecure SecurityLevel = iota
	SecurityWeak
	SecurityAcceptable
	SecuritySecure
	SecurityModern
)

func (s SecurityLevel) String() string {
	switch s {
	case SecurityInsecure:
		return "🔴 INSECURE"
	case SecurityWeak:
		return "🟠 WEAK"
	case SecurityAcceptable:
		return "🟡 ACCEPTABLE"
	case SecuritySecure:
		return "🟢 SECURE"
	case SecurityModern:
		return "🟢 MODERN"
	default:
		return "❓ UNKNOWN"
	}
}

var cipherClassification = map[string]SecurityLevel{
	"TLS_RSA_WITH_RC4_128_SHA":                SecurityInsecure,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           SecurityInsecure,
	"TLS_RSA_WITH_AES_128_CBC_SHA":            SecurityWeak,
	"TLS_RSA_WITH_AES_256_CBC_SHA":            SecurityWeak,
	"TLS_RSA_WITH_AES_128_CBC_SHA256":         SecurityWeak,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":         SecuritySecure,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":         SecuritySecure,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":        SecurityInsecure,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    SecurityAcceptable,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    SecurityAcceptable,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":          SecurityInsecure,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     SecurityInsecure,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      SecurityAcceptable,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      SecurityAcceptable,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": SecuritySecure,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":   SecuritySecure,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": SecuritySecure,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": SecuritySecure,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   SecuritySecure,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   SecuritySecure,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  SecurityModern,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    SecurityModern,
	"TLS_AES_128_GCM_SHA256":                  SecurityModern,
	"TLS_AES_256_GCM_SHA384":                  SecurityModern,
	"TLS_CHACHA20_POLY1305_SHA256":            SecurityModern,
}

type CertInfo struct {
	CommonName string
	PEM        string
}

var certInfos []CertInfo

// Command line flags definition
var (
	host            = flag.String("host", "", "Hostname or server IP (mandatory)")
	port            = flag.String("port", "443", "TLS server port")
	certChain       = flag.Bool("cert", false, "Print cerificate chain")
	checkCertExpiry = flag.Bool("checkcert", false, "Check if the certificate is about to expire")
	timeout         = flag.Int("timeout", defaultTimeout, "Connection Timeout")
	outputFile      = flag.String("output", "", "File to save the PEM output to (optional), only used with --cert")
	minVersionStr   = flag.String("min-version", "1.0", "Minimum TLS version to test (1.0, 1.1, 1.2, 1.3)")
	outputMarkdown  = flag.String("markdown", "", "Write scan result to markdown file")
	forceCiphers    = flag.Bool("force-ciphers", false, "Force all cipher suites during version scan")
)

type TLSScanResult struct {
	Version      string
	CipherSuites []string
	Supported    bool
	Certificate  *x509.Certificate
}

func BuildMarkdownReportFromResults(host, port string, results []TLSScanResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# TLS Scan Report for host %s:%s\n\n", host, port))

	sb.WriteString("## TLS Versions Supported\n")
	for _, r := range results {
		if r.Supported {
			sb.WriteString(fmt.Sprintf("- ✅ %s\n", r.Version))
		} else {
			sb.WriteString(fmt.Sprintf("- ❌ %s\n", r.Version))
		}
	}
	sb.WriteString("\n")

	sb.WriteString("## Cipher Suites\n")
	for _, r := range results {
		if r.Supported && len(r.CipherSuites) > 0 {
			sb.WriteString(fmt.Sprintf("\n### %s\n", r.Version))
			for _, cs := range r.CipherSuites {
				label := cipherClassification[cs]
				if label.String() != "" {
					sb.WriteString(fmt.Sprintf("\n- %s %s", cs, label))
				} else {
					sb.WriteString(fmt.Sprintf("\n- %s", cs))
				}
			}
		}
	}

	for _, r := range results {
		if r.Supported && r.Certificate != nil {
			sb.WriteString("\n## Certificate Details\n")
			sb.WriteString(fmt.Sprintf("- **Subject CN**: %s\n", r.Certificate.Subject.CommonName))
			sb.WriteString(fmt.Sprintf("- **Issuer**: %s\n", r.Certificate.Issuer.CommonName))
			sb.WriteString(fmt.Sprintf("- **Valid From**: %s\n", r.Certificate.NotBefore.Format("2006-01-02")))
			sb.WriteString(fmt.Sprintf("- **Valid To**: %s\n", r.Certificate.NotAfter.Format("2006-01-02")))
			sb.WriteString(fmt.Sprintf("- **Days Until Expiry**: %d\n", int(time.Until(r.Certificate.NotAfter).Hours()/24)))
			if len(r.Certificate.DNSNames) > 0 {
				sb.WriteString(fmt.Sprintf("- **DNS Names**: %s\n", strings.Join(r.Certificate.DNSNames, ", ")))
			}
			break // Only show the first valid cert
		}
	}

	return sb.String()
}

func WriteMarkdownReportToFile(host, port string, results []TLSScanResult, outputPath string) error {
	report := BuildMarkdownReportFromResults(host, port, results)
	return os.WriteFile(outputPath+".md", []byte(report), 0640)
}

func clearScreen() {
	switch runtime.GOOS {
	case "linux", "darwin":
		fmt.Print("\033[H\033[2J")
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	default:
		fmt.Println("Screen cleaning not supported on this system!")
	}
}

// TLS String to Constant Conversion
func tlsVersionToUint16(ver string) uint16 {
	switch ver {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS10
	}
}

func scanTLSVersion(host string, port string, version uint16, timeoutSec int) (bool, *x509.Certificate, string, error) {
	address := net.JoinHostPort(host, port)
	config := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
		MinVersion:         version,
		MaxVersion:         version,
	}

	if *forceCiphers && version <= tls.VersionTLS12 {
		var suiteIDs []uint16
		for _, cs := range allCipherSuites {
			suiteIDs = append(suiteIDs, cs.id)
		}
		config.CipherSuites = suiteIDs
		fmt.Printf("\n🔧 Forcing cipher suites for %s", tlsVersions[version])
	}

	fmt.Printf("\n👉 Trying TLS version %s\n", tlsVersions[version])

	// if TLS 1.3 and forceCiphers active → try n times
	if *forceCiphers && version == tls.VersionTLS13 {
		var cipher string
		var cert *x509.Certificate
		var success bool

		for i := range defaultTLS13Tries {
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second}, "tcp", address, config)
			if err != nil {
				if strings.Contains(err.Error(), "protocol version not supported") {
					fmt.Printf("❌ Handshake failed: %v", err)
					return false, nil, "", err
				}
				fmt.Printf("❌ Handshake attempt %d failed: %v\n", i+1, err)
				continue
			}
			state := conn.ConnectionState()
			cipher = tls.CipherSuiteName(state.CipherSuite)
			if len(state.PeerCertificates) > 0 {
				cert = state.PeerCertificates[0]
			}

			certInfos = append(certInfos, extractCertInfos(state.PeerCertificates)...)
			conn.Close()
			success = true
			break
		}

		if success {
			return true, cert, cipher, nil
		}
		return false, nil, "", fmt.Errorf("all TLS 1.3 handshakes failed")
	}

	// TLS 1.0–1.2 o normal case
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second}, "tcp", address, config)
	if err != nil {
		fmt.Printf("❌ Handshake failed: %v", err)
		return false, nil, "", err
	}
	defer conn.Close()

	state := conn.ConnectionState()

	certInfos = append(certInfos, extractCertInfos(state.PeerCertificates)...)
	cipher := tls.CipherSuiteName(state.CipherSuite)

	if len(state.PeerCertificates) > 0 {
		return true, state.PeerCertificates[0], cipher, nil
	}
	return true, nil, cipher, nil
}

func isCipherSuiteCompatibleWith(version uint16, id uint16) bool {
	// TLS 1.3 cipher suites
	if version == tls.VersionTLS13 {
		return id == tls.TLS_AES_128_GCM_SHA256 ||
			id == tls.TLS_AES_256_GCM_SHA384 ||
			id == tls.TLS_CHACHA20_POLY1305_SHA256
	}

	// TLS 1.0–1.2 cipher suites
	return id != tls.TLS_AES_128_GCM_SHA256 &&
		id != tls.TLS_AES_256_GCM_SHA384 &&
		id != tls.TLS_CHACHA20_POLY1305_SHA256
}

func uniqueStrings(input []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, s := range input {
		if _, exists := seen[s]; !exists {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}

func GetSupportedCiphersForVersion(host, port string, timeout int, version uint16) []string {
	supported := []string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, defaultMaxConcurrency) // configurable max goroutines

	for _, cs := range allCipherSuites {
		if !isCipherSuiteCompatibleWith(version, cs.id) {
			continue
		}
		cs := cs // capture range variable
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			conf := &tls.Config{
				MinVersion:         version,
				MaxVersion:         version,
				CipherSuites:       []uint16{cs.id},
				InsecureSkipVerify: false,
				ServerName:         host,
			}
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Duration(timeout) * time.Second}, "tcp", net.JoinHostPort(host, port), conf)
			if err == nil {
				conn.Close()
				mu.Lock()
				supported = append(supported, cs.name)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// TLS 1.3 parallel scan
	if version == tls.VersionTLS13 {
		found := make(map[string]bool)
		var tls13Mutex sync.Mutex
		var wg3 sync.WaitGroup
		for i := 0; i < defaultTLS13Tries; i++ {
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

	return uniqueStrings(supported)
}

// Certificate Informaion print function
func printCertInfos(certInfos []CertInfo) {
	for i, ci := range certInfos {
		fmt.Printf("\nCertificate %d:\n", i)
		fmt.Printf("  CN:  %s\n", ci.CommonName)
		fmt.Printf("  PEM:\n%s\n", ci.PEM)
	}
}

func extractCertInfos(certs []*x509.Certificate) []CertInfo {
	var infos []CertInfo
	for _, cert := range certs {
		infos = append(infos, CertInfo{
			CommonName: cert.Subject.CommonName,
			PEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		})
	}
	return infos
}

// Calculate the days remaining until the certificate expires
func checkCertificateExpiry(cert *x509.Certificate) int {
	return int(time.Until(cert.NotAfter).Hours() / 24)
}

func saveOrPrintCertToFile(prefix string, certInfos []CertInfo) {
	var output = ""
	if *outputFile != "" {
		for _, ci := range certInfos {

			output += ci.PEM
		}
		err := os.WriteFile(prefix+"_"+*outputFile, []byte(output), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error saving to file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Output saved to %s\n", prefix+"_"+*outputFile)
		output = ""
	} else {
		printCertInfos(certInfos)
	}
}

func printCertSummary(cert *x509.Certificate, cipher string, version string) {
	fmt.Printf("✅ \033[1m%s\033[0m: supported\n", version)
	fmt.Printf("   Negotiated Cipher suite: %s\n", cipher)
	fmt.Printf("   CN: %s\n", cert.Subject.CommonName)
	fmt.Printf("   Issuer: %s\n", cert.Issuer.CommonName)
	fmt.Printf("   Valid: %s - %s\n", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))

	if *checkCertExpiry {
		fmt.Printf("   Days to Expiration: %d\n", checkCertificateExpiry(cert))
	}

	fmt.Printf("   DNS: %v\n", cert.DNSNames)
}

func init() {
	clearScreen()
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", filepath.Base(os.Args[0]))
		fmt.Println("Scan TLS versions and cipher suites on a target host.")
		fmt.Println()
		fmt.Println("Mandatory flags:")
		fmt.Println("  --host string\tHostname or server IP to scan")
		fmt.Println()
		fmt.Println("Optional flags:")
		flag.PrintDefaults()
		fmt.Println("\nExample:")
		fmt.Println("  tlsanalyzer --host example.com --port 443 --cert --output cert.pem --checkcert --markdown report")
	}
}

func main() {

	clearScreen()

	flag.Parse()

	if *host == "" {
		fmt.Println("Error: --host is required")
		flag.Usage()
		os.Exit(1)
	}

	h := strings.TrimSpace(*host)
	if h == "" {
		fmt.Println("Error: host cannot be empty")
		os.Exit(1)
	}

	minVersion := tlsVersionToUint16(*minVersionStr)
	if minVersion == 0 {
		fmt.Printf("Error: invalid --min-version '%s'. Use 1.0, 1.1, 1.2 or 1.3\n", *minVersionStr)
		os.Exit(1)
	}

	fmt.Printf("\nStarting TLS analysis for %s:%s with minimum TLS version %s\n", h, *port, *minVersionStr)

	// Sort versions in ascending order
	keys := make([]uint16, 0, len(tlsVersions))
	for v := range tlsVersions {
		if v >= minVersion {
			keys = append(keys, v)
		}
	}
	slices.Sort(keys)
	fmt.Printf("\n\033[1mTLS Analisys for:\033[0m [%s:%s]\n", *host, *port)

	var results []TLSScanResult

	for _, version := range keys {
		name := tlsVersions[version]
		supported, cert, cipher, err := scanTLSVersion(*host, *port, version, *timeout)
		if err != nil {
			fmt.Printf("\n🚫 %s: unsupported\n", name)
			results = append(results, TLSScanResult{Version: name, Supported: false})
			continue
		}

		if supported {
			ciphers := GetSupportedCiphersForVersion(*host, *port, *timeout, version)

			results = append(results, TLSScanResult{
				Version:      name,
				CipherSuites: ciphers,
				Supported:    true,
				Certificate:  cert,
			})

			if cert != nil {
				printCertSummary(cert, cipher, name)
				if len(ciphers) > 0 {
					fmt.Println("   Supported cipher suites:")
					for _, cs := range ciphers {
						fmt.Printf("     • %s\n", cs)
					}
				}

				if *certChain {
					saveOrPrintCertToFile(strings.ReplaceAll(name, " ", ""), certInfos)
					certInfos = nil
				}
			}

		} else {
			fmt.Printf("\n🚫 %s: unsupported\n", name)
			results = append(results, TLSScanResult{Version: name, Supported: false})
		}
	}
	// ➕ Write Markdown reports
	if *outputMarkdown != "" {
		err := WriteMarkdownReportToFile(*host, *port, results, *outputMarkdown)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to write markdown report: %v\n", err)
		} else {
			fmt.Printf("✅ Markdown report saved to %s\n", *outputMarkdown)
		}
	}

}
