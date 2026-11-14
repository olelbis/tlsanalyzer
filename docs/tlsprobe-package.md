# TLS Probe Go Package

`github.com/olelbis/tlsanalyzer/tlsprobe` exposes the raw probes used by
`tlsanalyzer`: cipher suite probes for TLS 1.3 and for TLS 1.0 to 1.2, and the
enumeration of the key exchange groups a TLS 1.3 server accepts.

The package is intentionally small and preview-level. It sends minimal
ClientHello messages and classifies the first useful server response. The
`Probe*` functions offer one cipher suite at a time; the `Enumerate*` functions
offer many candidates at once and remove the one the server selects, so a server
with k entries costs about k+1 connections. Group enumeration sends an empty
`key_share`, which makes the server name its preferred group in a
HelloRetryRequest, so no key material is generated. It is not a TLS
implementation and it does not complete full TLS handshakes.

## Install

```bash
go get github.com/olelbis/tlsanalyzer@v0.35.0
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
		fmt.Printf("%s: %s (%s)\n", result.Name, result.Status, result.EvidenceLevel)
	}
}
```

## API Contract

Public entry points:

- `Options`
- `Result`
- `Status`
- `EvidenceLevel`
- `ErrorCode`
- `Summary`
- `ConfigError`
- `ValidateOptions`
- `CipherSuiteName`
- `SupportedTLS13CipherSuites`
- `SupportedKeyShareGroups`
- `ProbeTLS13CipherSuite`
- `ProbeTLS13CipherSuites`
- `LegacyCipherSuite`
- `LegacyCipherSuites`
- `LegacyCipherSuitesForVersion`
- `LegacyEnumeration`
- `EnumerateLegacyCipherSuites`
- `SelectLegacyCipherSuite`
- `KeyExchangeGroup`
- `KeyExchangeGroups`
- `KeyExchangeGroupIDs`
- `LookupKeyExchangeGroup`
- `IsPostQuantumGroup`
- `GroupEnumeration`
- `EnumerateTLS13Groups`
- `ProbeLegacyCipherSuite`
- `ProbeLegacyCipherSuites`
- `Summarize`

Configuration errors are returned as `*tlsprobe.ConfigError`. Network and TLS
protocol outcomes are normally returned as `Result` values with a `Status`.

Consumers should rely on `Status`, `EvidenceLevel`, `CompletedHandshake` and
`ErrorCode` values for automation. `Result.Error` is human-readable diagnostic
detail and may change while the package remains under `v0.x`.

`Result` also includes optional evidence metadata:

- `EvidenceLevel` is currently `clienthello-only`.
- `CompletedHandshake` is currently always `false` because the probe stops after
  enough ServerHello, HelloRetryRequest, alert, timeout or close evidence is
  observed.
- `SelectedGroup` and `SelectedGroupName` when ServerHello or HelloRetryRequest exposes a key share group.
- `HelloRetryRequest` and `HelloRetryRequestRetried` when the server asks the probe to retry with another group.
- `Alert`, `AlertLevel` and `AlertDescription` when the server returns a TLS alert.
- `ErrorCode` for stable machine-readable diagnostics when `Error` is populated.

`Options.DialContext` can be set by embedded callers that need custom network
behavior, tests, proxy integration or connection instrumentation. When it is
nil, the package uses `net.Dialer`.

`Summarize` returns status counts for a result set so callers do not need to
duplicate basic aggregation logic.

## TLS 1.0 to 1.2 Probe

```go
suites := tlsprobe.LegacyCipherSuitesForVersion(tls.VersionTLS12)
results, err := tlsprobe.ProbeLegacyCipherSuites(ctx, tlsprobe.Options{
	Address:    net.JoinHostPort("example.com", "443"),
	ServerName: "example.com",
	Timeout:    5 * time.Second,
}, tls.VersionTLS12, suites)
```

`ProbeLegacyCipherSuite` sends a ClientHello whose `client_version` is the
probed version (`tls.VersionTLS10`, `tls.VersionTLS11` or `tls.VersionTLS12`),
with a single cipher suite and no `supported_versions` extension. Any other
version is a `*tlsprobe.ConfigError` for the `version` field.

- `supported`: the ServerHello selected the offered suite on the probed version.
- `rejected` with `ErrorCode` `server_version_mismatch`: the server selected the
  suite on a lower protocol version.
- `alert` (normally `handshake_failure`, or `protocol_version`) or `closed`: the
  server does not support the suite on that version.

`LegacyCipherSuites` returns the catalog (ID, IANA name and minimum protocol
version). It includes suites `crypto/tls` does not implement, because the probe
stops at ServerHello and performs no key exchange. `Options.KeyShareGroups`
controls the `supported_groups` extension. PSK, SRP, Kerberos, GOST and static
DH/ECDH suites are not in the catalog, and calls are sequential: callers that
need concurrency run `ProbeLegacyCipherSuite` from their own goroutines.

`ProbeLegacyCipherSuites` opens one connection per suite. To learn which suites
a server supports, prefer `EnumerateLegacyCipherSuites`:

```go
enumeration, err := tlsprobe.EnumerateLegacyCipherSuites(ctx, opts, tls.VersionTLS12,
	tlsprobe.LegacyCipherSuitesForVersion(tls.VersionTLS12))
```

It offers all remaining suites in one ClientHello, records the suite the server
selects, removes it and repeats until the server refuses the rest: k supported
suites cost k+1 connections. `Supported` lists the selected suites in server
preference order. `Complete` is false, and `Unresolved` holds the suites that
were not classified, when the enumeration could not finish (unanswered
ClientHellos after one retry, or a ServerHello selecting a suite that was not
offered). This is how `tlsanalyzer` stays below connection rate limits.

## TLS 1.3 Key Exchange Groups

`EnumerateTLS13Groups` finds which named groups a TLS 1.3 server accepts,
post-quantum hybrids included:

```go
enumeration, err := tlsprobe.EnumerateTLS13Groups(ctx, opts, tlsprobe.KeyExchangeGroupIDs())
for _, group := range enumeration.Supported {
	fmt.Println(group.Name, group.PostQuantum)
}
```

Each ClientHello offers all remaining groups with an empty `key_share`. The
server answers with a HelloRetryRequest that names the group it wants (RFC 8446
section 4.2.8), the group is recorded and removed, and the probe repeats until
the server refuses with `handshake_failure` or `insufficient_security`: k groups
cost k+1 connections. Because no key share is sent, no key material is needed
and ML-KEM does not have to be implemented. A group is supported when the
server selects it; no handshake is completed. `Supported` is in the order the
server selected the groups, `Complete` is false and `Unresolved` holds the
groups that were not classified when the enumeration could not finish (other
alerts, unanswered ClientHellos after one retry, or a group that was not
offered). A caller that also has a full handshake should check that the group it
negotiated is in `Supported`.

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

## Evidence Values

| Evidence level | Meaning |
| --- | --- |
| `clienthello-only` | The probe sent a raw ClientHello and classified the first useful server response. It did not complete a full TLS handshake. |

## Current Limits

- TLS 1.0 to 1.3; no SSLv2 or SSLv3.
- The TLS 1.0 to 1.2 probe does not read ServerKeyExchange, so it reports neither the selected curve nor the DHE parameter size.
- ClientHello-only evidence; no full TLS handshake completion.
- Supported key share groups are configurable. Defaults are X25519, P-256, P-384 and P-521.
- Fragmented handshake records are reassembled for ServerHello parsing, but this is still a focused probe rather than a complete TLS parser.
- API is public but preview-level until a future `v1.0` compatibility freeze.
