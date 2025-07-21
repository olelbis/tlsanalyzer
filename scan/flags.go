// File: scan/flags.go
package scan

import (
	"flag"
)

var (
	Host            = flag.String("host", "", "Hostname or server IP (mandatory)")
	Port            = flag.String("port", "443", "TLS server port")
	CertChain       = flag.Bool("cert", false, "Print certificate chain")
	CheckCertExpiry = flag.Bool("checkcert", false, "Check if the certificate is about to expire")
	Timeout         = flag.Int("timeout", 5, "Connection timeout in seconds")
	OutputFile      = flag.String("output", "", "Output file for PEM (only with --cert)")
	MinVersionStr   = flag.String("min-version", "1.0", "Minimum TLS version to test (1.0, 1.1, 1.2, 1.3)")
	OutputMarkdown  = flag.String("markdown", "", "Write scan result to markdown file")
	ForceCiphers    = flag.Bool("force-ciphers", false, "Force all cipher suites during version scan")
)

func init() {
	flag.Usage = func() {
		flag.CommandLine.Output().Write([]byte("Usage of tlsanalyzer:\n"))
		flag.PrintDefaults()
	}
}
