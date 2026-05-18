package tlsprobe_test

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/olelbis/tlsanalyzer/tlsprobe"
)

func ExampleValidateOptions() {
	err := tlsprobe.ValidateOptions(tlsprobe.Options{
		Address: net.JoinHostPort("service.example.test", "443"),
		Timeout: 5 * time.Second,
		ALPN:    []string{"h2", "http/1.1"},
	})

	fmt.Println(err == nil)
	// Output: true
}

func ExampleSupportedTLS13CipherSuites() {
	for _, cipherSuite := range tlsprobe.SupportedTLS13CipherSuites() {
		fmt.Printf("0x%04x\n", cipherSuite)
	}
	// Output:
	// 0x1301
	// 0x1302
	// 0x1303
}

func ExampleProbeTLS13CipherSuite() {
	address, closeServer := localAlertServer()
	defer closeServer()

	result, err := tlsprobe.ProbeTLS13CipherSuite(context.Background(), tlsprobe.Options{
		Address: address,
		Timeout: time.Second,
	}, tlsprobe.SupportedTLS13CipherSuites()[0])
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(result.Status)
	fmt.Println(result.Alert)
	// Output:
	// alert
	// fatal/handshake_failure
}

func localAlertServer() (string, func()) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	done := make(chan struct{})

	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		header := make([]byte, 5)
		if _, err := conn.Read(header); err != nil {
			return
		}
		_, _ = conn.Write([]byte{21, 3, 3, 0, 2, 2, 40})
	}()

	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
	}
}
