package tlsprobe_test

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/olelbis/tlsanalyzer/internal/tlsprobe"
)

func ExampleProbeTLS13CipherSuite() {
	result, err := tlsprobe.ProbeTLS13CipherSuite(context.Background(), tlsprobe.Options{
		Address:    net.JoinHostPort("example.com", "443"),
		ServerName: "example.com",
		Timeout:    5 * time.Second,
		ALPN:       []string{"h2", "http/1.1"},
	}, tlsprobe.SupportedTLS13CipherSuites()[0])
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(result.Status)
}

func ExampleProbeTLS13CipherSuites() {
	results, err := tlsprobe.ProbeTLS13CipherSuites(context.Background(), tlsprobe.Options{
		Address:    net.JoinHostPort("example.com", "443"),
		ServerName: "example.com",
		Timeout:    5 * time.Second,
	}, tlsprobe.SupportedTLS13CipherSuites())
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, result := range results {
		fmt.Printf("%s: %s\n", result.Name, result.Status)
	}
}
