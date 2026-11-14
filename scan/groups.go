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
	// Evidence says how the group was established: GroupEvidenceHRR when the
	// server selected it in a HelloRetryRequest, GroupEvidenceHandshake when
	// a complete TLS 1.3 handshake was also made with it, and
	// GroupEvidenceHandshakeFailed when the server selected it but the
	// handshake then failed.
	Evidence string
}

// Evidence levels of a key exchange group.
const (
	GroupEvidenceHRR             = "hello-retry-request"
	GroupEvidenceHandshake       = "handshake"
	GroupEvidenceHandshakeFailed = "handshake-failed"
)

// Server key exchange group preference values.
const (
	// PreferencePostQuantum: the server picks a post-quantum group even when
	// the client lists classical groups first.
	PreferencePostQuantum = "post-quantum"
	// PreferenceClassical: the server picks a classical group even when the
	// client lists post-quantum groups first.
	PreferenceClassical = "classical"
	// PreferenceClient: the server follows the client's order, so it uses a
	// post-quantum group only when the client lists one first.
	PreferenceClient = "client-order"
	// PreferenceInconclusive: the probes did not give a usable answer.
	PreferenceInconclusive = "inconclusive"
)

// GroupProbeResult is the outcome of ProbeKeyExchangeGroups.
type GroupProbeResult struct {
	// Groups are the groups the server selected, in the order it selected
	// them.
	Groups []KeyExchangeGroupResult
	// Preference is the server's group preference class (Preference*). It is
	// empty when no post-quantum group was found, since there is nothing to
	// prefer.
	Preference string
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
// accepts, including the post-quantum hybrids, and which class of group it
// prefers.
//
// Groups are found with ClientHellos that carry no key share and read the
// HelloRetryRequest the server answers with, so a group counts as supported
// when the server selects it. X25519MLKEM768, the hybrid current browsers use,
// is also confirmed with a complete handshake. The preference is read with two
// more ClientHellos that list the post-quantum groups first and last.
// negotiatedGroup is the group the version
// handshake negotiated, as crypto/tls spells it (it may be empty): the
// enumeration has to contain it, and when it does not the result is marked
// incomplete instead of being trusted.
func ProbeKeyExchangeGroups(opts Options, negotiatedGroup string) GroupProbeResult {
	start := time.Now()
	result := GroupProbeResult{
		Warnings: []string{
			"TLS 1.3 key exchange groups were enumerated with ClientHello-only HelloRetryRequest probes; only X25519MLKEM768 is confirmed with a complete handshake.",
		},
	}

	probeOpts := tlsprobe.Options{
		Address:     net.JoinHostPort(opts.Host, opts.Port),
		ServerName:  opts.tlsServerName(),
		Timeout:     opts.Timeout,
		ALPN:        DefaultALPNProtocols(),
		DialContext: opts.probeDialContext(),
	}
	enumeration, err := tlsprobe.EnumerateTLS13Groups(context.Background(), probeOpts, tlsprobe.KeyExchangeGroupIDs())
	result.Connections = enumeration.Connections
	for _, group := range enumeration.Supported {
		result.Groups = append(result.Groups, KeyExchangeGroupResult{
			ID: group.ID, Name: group.Name, PostQuantum: group.PostQuantum, Evidence: GroupEvidenceHRR,
		})
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

	result.confirmHybridHandshake(opts)
	result.probePreference(probeOpts)

	result.DurationMillis = time.Since(start).Milliseconds()
	return result
}

// confirmHybridHandshake completes a TLS 1.3 handshake offering only
// X25519MLKEM768 when the enumeration found it. A HelloRetryRequest shows that
// the server selects the group, not that the handshake works with it.
func (r *GroupProbeResult) confirmHybridHandshake(opts Options) {
	index := -1
	for i, group := range r.Groups {
		if group.ID == tlsprobe.GroupX25519MLKEM768 {
			index = i
		}
	}
	if index < 0 {
		return
	}

	r.Connections++
	conn, err := opts.dialTLS(&tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768},
		InsecureSkipVerify: true, // #nosec G402 -- scanner probe, validation done separately
		ServerName:         opts.tlsServerName(),
		NextProtos:         DefaultALPNProtocols(),
	})
	if err != nil {
		r.Groups[index].Evidence = GroupEvidenceHandshakeFailed
		r.Warnings = append(r.Warnings, fmt.Sprintf(
			"the server selected X25519MLKEM768 in a HelloRetryRequest but a handshake offering only that group failed (%s); the group is not confirmed.",
			stableHandshakeError(err)))
		return
	}
	_ = conn.Close()
	r.Groups[index].Evidence = GroupEvidenceHandshake
}

// probePreference finds out whether the server prefers a post-quantum group.
// It offers the groups the server already accepted twice, post-quantum first
// and classical first, and compares the classes the server selects.
func (r *GroupProbeResult) probePreference(probeOpts tlsprobe.Options) {
	var postQuantum, classical []uint16
	for _, group := range r.Groups {
		if group.Evidence == GroupEvidenceHandshakeFailed {
			continue
		}
		if group.PostQuantum {
			postQuantum = append(postQuantum, group.ID)
		} else {
			classical = append(classical, group.ID)
		}
	}
	if len(postQuantum) == 0 {
		return
	}
	if len(classical) == 0 {
		r.Preference = PreferencePostQuantum
		return
	}

	pqFirst := append(append([]uint16{}, postQuantum...), classical...)
	pqLast := append(append([]uint16{}, classical...), postQuantum...)
	first, firstOK := r.selectedClass(probeOpts, pqFirst)
	last, lastOK := r.selectedClass(probeOpts, pqLast)
	switch {
	case !firstOK || !lastOK:
		r.Preference = PreferenceInconclusive
		r.Warnings = append(r.Warnings, "the server did not answer the key exchange group preference probes, so its preference is unknown.")
	case first && last:
		r.Preference = PreferencePostQuantum
	case !first && !last:
		r.Preference = PreferenceClassical
	case first && !last:
		r.Preference = PreferenceClient
	default:
		r.Preference = PreferenceInconclusive
		r.Warnings = append(r.Warnings, "the server chose a classical group when post-quantum groups were listed first and the reverse otherwise; its preference is unclear.")
	}
}

// selectedClass sends one key-share-less ClientHello listing groups and
// reports whether the server selected a post-quantum group. ok is false when
// the answer was not a usable HelloRetryRequest for one of the offered groups.
func (r *GroupProbeResult) selectedClass(probeOpts tlsprobe.Options, groups []uint16) (postQuantum, ok bool) {
	r.Connections++
	answer := tlsprobe.SelectTLS13Group(context.Background(), probeOpts, groups)
	if answer.Status != tlsprobe.StatusHelloRetryRequest || answer.ErrorCode != "" || !containsGroupID(groups, answer.SelectedGroup) {
		return false, false
	}
	return tlsprobe.IsPostQuantumGroup(answer.SelectedGroup), true
}

func containsGroupID(groups []uint16, id uint16) bool {
	for _, group := range groups {
		if group == id {
			return true
		}
	}
	return false
}

func stableHandshakeError(err error) string {
	msg := err.Error()
	if len(msg) > 120 {
		msg = msg[:120]
	}
	return msg
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

// FormatKeyExchangePreference renders a preference value for console output.
func FormatKeyExchangePreference(preference string) string {
	switch preference {
	case PreferencePostQuantum:
		return "post-quantum first (server preference)"
	case PreferenceClassical:
		return "classical first (server preference)"
	case PreferenceClient:
		return "follows the client order (post-quantum only when the client lists it first)"
	case PreferenceInconclusive:
		return "inconclusive"
	default:
		return ""
	}
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
		if group.Evidence == GroupEvidenceHandshakeFailed {
			parts[i] += " [handshake failed]"
		}
	}
	return strings.Join(parts, ", ")
}
