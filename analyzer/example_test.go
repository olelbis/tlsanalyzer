package analyzer_test

import (
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/olelbis/tlsanalyzer/analyzer"
	"github.com/olelbis/tlsanalyzer/policy"
)

func ExampleDefaultOptions() {
	opts := analyzer.DefaultOptions("example.com")
	opts.ServerName = "example.com"
	opts.MinVersion = tls.VersionTLS12
	opts.PolicyConfig = policy.Config{Name: policy.NameModern}

	_ = opts
}

func ExampleRun() {
	opts := analyzer.DefaultOptions("example.com")
	opts.Timeout = 3 * time.Second
	opts.MinVersion = tls.VersionTLS12

	result, err := analyzer.Run(opts, analyzer.Hooks{
		VersionStart: func(versionName string, _ uint16, _ bool) {
			fmt.Printf("trying %s\n", versionName)
		},
	})
	if err != nil {
		var hookErr *analyzer.HookError
		if errors.As(err, &hookErr) {
			fmt.Printf("hook failed at %s\n", hookErr.Stage)
			return
		}
		fmt.Println(err)
		return
	}
	fmt.Println(len(result.Results))
}
