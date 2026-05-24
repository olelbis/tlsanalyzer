# TLS Probe Go Package

`github.com/olelbis/tlsanalyzer/tlsprobe` exposes the raw TLS 1.3 cipher probe
used by `tlsanalyzer`.

The package is intentionally small and preview-level. It sends minimal TLS 1.3
ClientHello messages, offers one cipher suite at a time and classifies the first
useful server response. It is not a TLS implementation and it does not complete
full TLS handshakes.

## Install

```bash
go get github.com/olelbis/tlsanalyzer@v0.28.0
```

## Example

```go
package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/olelbis/tlsanalyzer/tlsprobe"
)

func main() {
	results, err := tlsprobe.ProbeTLS13CipherSuites(context.Background(), tlsprobe.Options{
		Address:    net.JoinHostPort("example.com", "443"),
		ServerName: "example.com",
		Timeout:    5 * time.Second,
		ALPN:           []string{"h2", "http/1.1"},
		KeyShareGroups: tlsprobe.SupportedKeyShareGroups(),
	}, tlsprobe.SupportedTLS13CipherSuites())
	if err != nil {
		panic(err)
	}

	for _, result := range results {
		fmt.Printf("%s: %s\n", result.Name, result.Status)
	}
}
```

## API Contract

Public entry points:

- `Options`
- `Result`
- `Status`
- `ConfigError`
- `ValidateOptions`
- `SupportedTLS13CipherSuites`
- `SupportedKeyShareGroups`
- `ProbeTLS13CipherSuite`
- `ProbeTLS13CipherSuites`

Configuration errors are returned as `*tlsprobe.ConfigError`. Network and TLS
protocol outcomes are normally returned as `Result` values with a `Status`.

Consumers should rely on `Status` values for automation. `Result.Error` is
human-readable diagnostic detail and may change while the package remains under
`v0.x`.

`Result` also includes optional evidence metadata:

- `SelectedGroup` and `SelectedGroupName` when ServerHello or HelloRetryRequest exposes a key share group.
- `HelloRetryRequest` and `HelloRetryRequestRetried` when the server asks the probe to retry with another group.
- `Alert`, `AlertLevel` and `AlertDescription` when the server returns a TLS alert.

## Status Values

| Status | Meaning |
| --- | --- |
| `supported` | The server selected the offered TLS 1.3 cipher suite. |
| `rejected` | The server replied with ServerHello but selected another cipher suite. |
| `hello-retry-request` | The server sent HelloRetryRequest and the probe could not complete a retry. |
| `alert` | The server returned a TLS alert. |
| `timeout` | Connect, write or read exceeded the configured timeout. |
| `closed` | The peer closed the connection before a supported/rejected decision. |
| `inconclusive` | The response could not be classified deterministically. |

## Current Limits

- TLS 1.3 only.
- ClientHello-only evidence; no full TLS handshake completion.
- Supported key share groups are configurable. Defaults are X25519, P-256, P-384 and P-521.
- Fragmented handshake records are reassembled for ServerHello parsing, but this is still a focused probe rather than a complete TLS parser.
- API is public but preview-level until a future `v1.0` compatibility freeze.
