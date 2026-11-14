package tlsprobe

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net"
	"time"
)

// Named groups beyond the four the TLS 1.3 cipher probe can generate key
// shares for. Group enumeration never needs key material (see
// EnumerateTLS13Groups), so any registered group can be listed.
const (
	GroupX448      uint16 = 0x001e
	GroupFFDHE2048 uint16 = 0x0100
	GroupFFDHE3072 uint16 = 0x0101
	GroupFFDHE4096 uint16 = 0x0102
	GroupFFDHE6144 uint16 = 0x0103
	GroupFFDHE8192 uint16 = 0x0104

	// Post-quantum and hybrid groups (ML-KEM, FIPS 203). The hybrids combine
	// a classical exchange with ML-KEM so that a break of either one alone
	// does not expose the session key.
	GroupMLKEM512              uint16 = 0x0200
	GroupMLKEM768              uint16 = 0x0201
	GroupMLKEM1024             uint16 = 0x0202
	GroupSecP256r1MLKEM768     uint16 = 0x11eb
	GroupX25519MLKEM768        uint16 = 0x11ec
	GroupSecP384r1MLKEM1024    uint16 = 0x11ed
	GroupX25519Kyber768Draft00 uint16 = 0x6399
)

// KeyExchangeGroup describes a TLS named group the enumeration can detect.
type KeyExchangeGroup struct {
	ID   uint16
	Name string
	// PostQuantum is true for groups that include a post-quantum KEM
	// (ML-KEM or the pre-standard Kyber draft), hybrid or not.
	PostQuantum bool
}

// keyExchangeGroups is the catalog, in the order groups are offered: strongest
// modern choices first, so that a server that follows the client order reports
// them first.
var keyExchangeGroups = []KeyExchangeGroup{
	{GroupX25519MLKEM768, "X25519MLKEM768", true},
	{GroupSecP256r1MLKEM768, "SecP256r1MLKEM768", true},
	{GroupSecP384r1MLKEM1024, "SecP384r1MLKEM1024", true},
	{GroupMLKEM768, "MLKEM768", true},
	{GroupMLKEM1024, "MLKEM1024", true},
	{GroupMLKEM512, "MLKEM512", true},
	{GroupX25519Kyber768Draft00, "X25519Kyber768Draft00", true},
	{GroupX25519, "X25519", false},
	{GroupP256, "P-256", false},
	{GroupP384, "P-384", false},
	{GroupP521, "P-521", false},
	{GroupX448, "X448", false},
	{GroupFFDHE2048, "ffdhe2048", false},
	{GroupFFDHE3072, "ffdhe3072", false},
	{GroupFFDHE4096, "ffdhe4096", false},
	{GroupFFDHE6144, "ffdhe6144", false},
	{GroupFFDHE8192, "ffdhe8192", false},
}

var keyExchangeGroupByID = func() map[uint16]KeyExchangeGroup {
	groups := make(map[uint16]KeyExchangeGroup, len(keyExchangeGroups))
	for _, group := range keyExchangeGroups {
		groups[group.ID] = group
	}
	return groups
}()

// KeyExchangeGroups returns the named groups the enumeration offers, in the
// order it offers them. The returned slice is a copy.
func KeyExchangeGroups() []KeyExchangeGroup {
	return append([]KeyExchangeGroup(nil), keyExchangeGroups...)
}

// KeyExchangeGroupIDs returns the IDs of KeyExchangeGroups.
func KeyExchangeGroupIDs() []uint16 {
	ids := make([]uint16, len(keyExchangeGroups))
	for i, group := range keyExchangeGroups {
		ids[i] = group.ID
	}
	return ids
}

// LookupKeyExchangeGroup returns the catalog entry for a group ID.
func LookupKeyExchangeGroup(id uint16) (KeyExchangeGroup, bool) {
	group, ok := keyExchangeGroupByID[id]
	return group, ok
}

// IsPostQuantumGroup reports whether a group ID is a post-quantum or hybrid
// group of the catalog.
func IsPostQuantumGroup(id uint16) bool {
	return keyExchangeGroupByID[id].PostQuantum
}

func catalogGroupName(id uint16) (string, bool) {
	group, ok := keyExchangeGroupByID[id]
	return group.Name, ok
}

// GroupEnumeration is the outcome of EnumerateTLS13Groups.
type GroupEnumeration struct {
	// Supported lists the groups the server selected, in the order it
	// selected them. When the server follows its own preference this is its
	// preference order; a server that follows the client order reports the
	// order the groups were offered in.
	Supported []KeyExchangeGroup
	// Complete reports whether every offered group was classified: the server
	// either selected it or refused a ClientHello that still offered it.
	Complete bool
	// Unresolved lists the groups that were never classified because the
	// enumeration could not finish. It is empty when Complete is true.
	Unresolved []uint16
	// Last is the outcome that ended the enumeration.
	Last Result
	// Connections is the number of ClientHellos sent.
	Connections int
}

// EnumerateTLS13Groups finds which of groups a server accepts for TLS 1.3 key
// exchange.
//
// Each ClientHello offers all remaining groups in supported_groups and an
// empty key_share. RFC 8446 section 4.2.8 makes the server answer with a
// HelloRetryRequest that names the group it wants, so no key material is
// needed, which is what allows the post-quantum groups to be listed without
// implementing ML-KEM. The group is recorded, removed from the offer, and the
// probe repeats until the server refuses the remaining groups with a
// handshake_failure or insufficient_security alert: a server with k groups
// costs k+1 connections.
//
// An unanswered ClientHello (timeout, unparseable answer, closed connection)
// is sent again after a short pause. A second closed connection is accepted as
// the server's way of refusing the remaining groups; any other alert, and a
// group the server selected that was not offered, leave the enumeration
// unfinished with the remaining groups in Unresolved.
//
// Configuration errors are returned as errors. If ctx ends, the groups found
// so far are returned together with ctx.Err().
func EnumerateTLS13Groups(ctx context.Context, opts Options, groups []uint16) (GroupEnumeration, error) {
	var enumeration GroupEnumeration
	if err := ValidateOptions(opts); err != nil {
		return enumeration, err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	seen := make(map[uint16]bool, len(groups))
	remaining := make([]uint16, 0, len(groups))
	for _, group := range groups {
		if !seen[group] {
			seen[group] = true
			remaining = append(remaining, group)
		}
	}

	retries := 0
	for len(remaining) > 0 {
		if err := ctx.Err(); err != nil {
			enumeration.Unresolved = remaining
			return enumeration, err
		}

		result := selectTLS13Group(ctx, opts, remaining)
		enumeration.Connections++
		enumeration.Last = result

		switch {
		case result.Status == StatusHelloRetryRequest && result.ErrorCode == "" && containsGroup(remaining, result.SelectedGroup):
			group, ok := keyExchangeGroupByID[result.SelectedGroup]
			if !ok {
				group = KeyExchangeGroup{ID: result.SelectedGroup, Name: keyShareGroupName(result.SelectedGroup)}
			}
			enumeration.Supported = append(enumeration.Supported, group)
			remaining = removeGroup(remaining, result.SelectedGroup)
			continue
		case result.Status == StatusAlert && isNoCommonGroupAlert(result.AlertDescription):
			enumeration.Complete = true
			return enumeration, nil
		case result.Status == StatusAlert,
			result.Status == StatusHelloRetryRequest,
			result.Status == StatusRejected,
			result.Status == StatusSupported:
			// An answer that is not a refusal and not a usable HelloRetryRequest
			// (another alert, a group that was not offered, a ServerHello):
			// it cannot be trusted to mean "none of the remaining groups".
			enumeration.Unresolved = remaining
			return enumeration, nil
		}

		if retries < legacyEnumerationRetries {
			retries++
			select {
			case <-ctx.Done():
			case <-time.After(legacyRetryPause):
			}
			continue
		}
		if result.Status == StatusClosed {
			enumeration.Complete = true
			return enumeration, nil
		}
		enumeration.Unresolved = remaining
		return enumeration, nil
	}

	enumeration.Complete = true
	return enumeration, nil
}

// isNoCommonGroupAlert reports whether an alert is the way a TLS 1.3 server
// says it has no group in common with the client (RFC 8446 section 4.2.8:
// handshake_failure, or insufficient_security for a policy refusal).
func isNoCommonGroupAlert(description uint8) bool {
	return description == 40 || description == 71
}

func containsGroup(groups []uint16, group uint16) bool {
	for _, candidate := range groups {
		if candidate == group {
			return true
		}
	}
	return false
}

func removeGroup(groups []uint16, group uint16) []uint16 {
	kept := make([]uint16, 0, len(groups))
	for _, candidate := range groups {
		if candidate != group {
			kept = append(kept, candidate)
		}
	}
	return kept
}

// selectTLS13Group sends one TLS 1.3 ClientHello that offers groups with an
// empty key_share and reports the HelloRetryRequest, alert or closure that
// answers it.
func selectTLS13Group(ctx context.Context, opts Options, groups []uint16) Result {
	result := Result{
		Status:        StatusInconclusive,
		EvidenceLevel: EvidenceClientHelloOnly,
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	sessionID := make([]byte, 32)
	random := make([]byte, 32)
	for _, buf := range [][]byte{sessionID, random} {
		if _, err := rand.Read(buf); err != nil {
			return withError(result, ErrorCodeBuildClientHelloFailed, err.Error())
		}
	}
	clientHello, err := buildTLS13ClientHello(clientHelloSpec{
		opts:          opts,
		cipherSuites:  []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256},
		sessionID:     sessionID,
		random:        random,
		groups:        groups,
		emptyKeyShare: true,
	})
	if err != nil {
		return withError(result, ErrorCodeBuildClientHelloFailed, err.Error())
	}

	dialContext := opts.DialContext
	if dialContext == nil {
		dialer := net.Dialer{Timeout: timeout}
		dialContext = dialer.DialContext
	}
	conn, err := dialContext(ctx, "tcp", opts.Address)
	if err != nil {
		result.Status = statusForNetworkError(err)
		return withError(result, ErrorCodeConnectFailed, stableNetworkError(err))
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return withError(result, ErrorCodeDeadlineFailed, err.Error())
	}
	stopOnContextDone := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stopOnContextDone()

	if _, err := conn.Write(clientHello); err != nil {
		result.Status = statusForNetworkError(err)
		return withError(result, ErrorCodeWriteFailed, stableNetworkError(err))
	}

	read, _ := readProbeRecord(conn, result)
	return read.result
}
