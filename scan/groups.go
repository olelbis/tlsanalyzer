package scan

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/olelbis/tlsanalyzer/tlsprobe"
)

// KeyExchangeGroupResult is one TLS 1.3 key exchange group an endpoint
// accepts.
type KeyExchangeGroupResult struct {
	ID          uint16
	Name        string
	PostQuantum bool
}

// GroupProbeResult is the outcome of ProbeKeyExchangeGroups.
type GroupProbeResult struct {
	// Groups are the groups the server selected, in the order it selected
	// them.
	Groups []KeyExchangeGroupResult
	// Incomplete reports that the enumeration could not classify every
	// group, or contradicted the version handshake, so a group missing from
	// Groups is not proven unsupported.
	Incomplete     bool
	Warnings       []string
	Connections    int
	DurationMillis int64
}

// HasPostQuantum reports whether any enumerated group includes a post-quantum
// KEM.
func (r GroupProbeResult) HasPostQuantum() bool {
	for _, group := range r.Groups {
		if group.PostQuantum {
			return true
		}
	}
	return false
}

// ProbeKeyExchangeGroups finds the TLS 1.3 key exchange groups an endpoint
// accepts, including the post-quantum hybrids.
//
// The probe only sends ClientHellos and reads the HelloRetryRequest the server
// answers with, so a group counts as supported when the server selects it; no
// handshake is completed with it. negotiatedGroup is the group the version
// handshake negotiated, as crypto/tls spells it (it may be empty): the
// enumeration has to contain it, and when it does not the result is marked
// incomplete instead of being trusted.
func ProbeKeyExchangeGroups(opts Options, negotiatedGroup string) GroupProbeResult {
	start := time.Now()
	result := GroupProbeResult{
		Warnings: []string{
			"TLS 1.3 key exchange groups were enumerated with ClientHello-only HelloRetryRequest probes; no handshake is completed with any group.",
		},
	}

	enumeration, err := tlsprobe.EnumerateTLS13Groups(context.Background(), tlsprobe.Options{
		Address:     net.JoinHostPort(opts.Host, opts.Port),
		ServerName:  opts.tlsServerName(),
		Timeout:     opts.Timeout,
		ALPN:        DefaultALPNProtocols(),
		DialContext: opts.probeDialContext(),
	}, tlsprobe.KeyExchangeGroupIDs())
	result.Connections = enumeration.Connections
	for _, group := range enumeration.Supported {
		result.Groups = append(result.Groups, KeyExchangeGroupResult{ID: group.ID, Name: group.Name, PostQuantum: group.PostQuantum})
	}

	switch {
	case err != nil:
		result.Incomplete = true
		result.Warnings = append(result.Warnings, "TLS 1.3 key exchange group enumeration failed: "+err.Error())
	case !enumeration.Complete:
		result.Incomplete = true
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"TLS 1.3 key exchange group enumeration could not finish (%s); %d of %d groups were not classified, so the group list is incomplete.",
			describeGroupEnumerationEnd(enumeration.Last), len(enumeration.Unresolved), len(tlsprobe.KeyExchangeGroupIDs())))
	}

	if id, ok := groupIDForCryptoTLSName(negotiatedGroup); ok && !containsKeyExchangeGroup(result.Groups, id) {
		result.Incomplete = true
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"the TLS 1.3 handshake negotiated %s but the group enumeration did not find it; the endpoint may not answer key-share-less ClientHellos, so the group list is incomplete.",
			negotiatedGroup))
	}

	result.DurationMillis = time.Since(start).Milliseconds()
	return result
}

func describeGroupEnumerationEnd(last tlsprobe.Result) string {
	switch {
	case last.Alert != "":
		return "the server answered " + last.Alert
	case last.Error != "":
		return last.Error
	default:
		return string(last.Status)
	}
}

func containsKeyExchangeGroup(groups []KeyExchangeGroupResult, id uint16) bool {
	for _, group := range groups {
		if group.ID == id {
			return true
		}
	}
	return false
}

// groupIDForCryptoTLSName maps the group name crypto/tls reports for a
// connection (tls.CurveID.String) to a catalog group ID.
func groupIDForCryptoTLSName(name string) (uint16, bool) {
	if name == "" {
		return 0, false
	}
	for _, id := range tlsprobe.KeyExchangeGroupIDs() {
		if tls.CurveID(id).String() == name {
			return id, true
		}
	}
	return 0, false
}

// KeyExchangeGroupNames returns the names of groups, in order.
func KeyExchangeGroupNames(groups []KeyExchangeGroupResult) []string {
	names := make([]string, len(groups))
	for i, group := range groups {
		names[i] = group.Name
	}
	return names
}

// FormatKeyExchangeGroups renders groups for console output, marking the
// post-quantum ones.
func FormatKeyExchangeGroups(groups []KeyExchangeGroupResult) string {
	parts := make([]string, len(groups))
	for i, group := range groups {
		parts[i] = group.Name
		if group.PostQuantum {
			parts[i] += " (post-quantum)"
		}
	}
	return strings.Join(parts, ", ")
}
