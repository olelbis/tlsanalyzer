package tlsprobe

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// LegacyCipherSuite describes one TLS 1.0-1.2 cipher suite the raw probe can offer.
//
// MinVersion is the lowest protocol version on which the suite can be
// negotiated: tls.VersionTLS10 for the original suites, tls.VersionTLS12 for
// suites that depend on TLS 1.2 (AEAD modes and SHA-256/SHA-384 MACs).
type LegacyCipherSuite struct {
	ID         uint16
	Name       string
	MinVersion uint16
}

const (
	extensionECPointFormats       uint16 = 11
	extensionPadding              uint16 = 21
	extensionExtendedMasterSecret uint16 = 23
	extensionRenegotiationInfo    uint16 = 0xff01

	// legacyEnumerationRetries is the number of unanswered ClientHellos one
	// enumeration repeats before it gives up.
	legacyEnumerationRetries = 2
)

// legacyRetryPause is waited before an unanswered ClientHello is sent again,
// so that a rate limiter that just dropped the probe has time to recover.
var legacyRetryPause = 300 * time.Millisecond

// legacyClientHelloSignatureAlgorithms is advertised in TLS 1.2 ClientHellos.
// On top of the TLS 1.3 list it keeps the SHA-1 and DSA schemes that legacy
// suites (DHE_DSS, old RSA/ECDSA deployments) need in order to answer with a
// ServerHello instead of a handshake_failure alert.
var legacyClientHelloSignatureAlgorithms = []uint16{
	0x0403, // ecdsa_secp256r1_sha256
	0x0503, // ecdsa_secp384r1_sha384
	0x0603, // ecdsa_secp521r1_sha512
	0x0807, // ed25519
	0x0808, // ed448
	0x0804, // rsa_pss_rsae_sha256
	0x0805, // rsa_pss_rsae_sha384
	0x0806, // rsa_pss_rsae_sha512
	0x0401, // rsa_pkcs1_sha256
	0x0501, // rsa_pkcs1_sha384
	0x0601, // rsa_pkcs1_sha512
	0x0402, // dsa_sha256
	0x0203, // ecdsa_sha1
	0x0201, // rsa_pkcs1_sha1
	0x0202, // dsa_sha1
}

// legacyCipherSuites is the TLS 1.0-1.2 probe catalog. It deliberately includes
// suites crypto/tls does not implement or refuses to offer (NULL, EXPORT,
// anonymous, RC4, DES, DHE, CAMELLIA, ARIA, CCM): the probe only needs the
// server's ServerHello, not a working implementation of the suite.
//
// IDs and names follow the IANA TLS Cipher Suites registry, except for suites
// crypto/tls knows, which keep the crypto/tls spelling so that raw-probed and
// negotiated evidence use the same name.
var legacyCipherSuites = []LegacyCipherSuite{
	// Static RSA key exchange.
	{0x0001, "TLS_RSA_WITH_NULL_MD5", tls.VersionTLS10},
	{0x0002, "TLS_RSA_WITH_NULL_SHA", tls.VersionTLS10},
	{0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", tls.VersionTLS10},
	{0x0004, "TLS_RSA_WITH_RC4_128_MD5", tls.VersionTLS10},
	{0x0005, "TLS_RSA_WITH_RC4_128_SHA", tls.VersionTLS10},
	{0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", tls.VersionTLS10},
	{0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA", tls.VersionTLS10},
	{0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", tls.VersionTLS10},
	{0x0009, "TLS_RSA_WITH_DES_CBC_SHA", tls.VersionTLS10},
	{0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", tls.VersionTLS10},
	{0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA", tls.VersionTLS10},
	{0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", tls.VersionTLS10},
	{0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", tls.VersionTLS10},
	{0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", tls.VersionTLS10},
	{0x0096, "TLS_RSA_WITH_SEED_CBC_SHA", tls.VersionTLS10},
	{0x003b, "TLS_RSA_WITH_NULL_SHA256", tls.VersionTLS12},
	{0x003c, "TLS_RSA_WITH_AES_128_CBC_SHA256", tls.VersionTLS12},
	{0x003d, "TLS_RSA_WITH_AES_256_CBC_SHA256", tls.VersionTLS12},
	{0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256", tls.VersionTLS12},
	{0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384", tls.VersionTLS12},
	{0x00ba, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", tls.VersionTLS12},
	{0x00c0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", tls.VersionTLS12},
	{0xc03c, "TLS_RSA_WITH_ARIA_128_CBC_SHA256", tls.VersionTLS12},
	{0xc03d, "TLS_RSA_WITH_ARIA_256_CBC_SHA384", tls.VersionTLS12},
	{0xc050, "TLS_RSA_WITH_ARIA_128_GCM_SHA256", tls.VersionTLS12},
	{0xc051, "TLS_RSA_WITH_ARIA_256_GCM_SHA384", tls.VersionTLS12},
	{0xc09c, "TLS_RSA_WITH_AES_128_CCM", tls.VersionTLS12},
	{0xc09d, "TLS_RSA_WITH_AES_256_CCM", tls.VersionTLS12},
	{0xc0a0, "TLS_RSA_WITH_AES_128_CCM_8", tls.VersionTLS12},
	{0xc0a1, "TLS_RSA_WITH_AES_256_CCM_8", tls.VersionTLS12},

	// DHE with DSS certificates.
	{0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", tls.VersionTLS10},
	{0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA", tls.VersionTLS10},
	{0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", tls.VersionTLS10},
	{0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", tls.VersionTLS10},
	{0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", tls.VersionTLS10},
	{0x0044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", tls.VersionTLS10},
	{0x0087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", tls.VersionTLS10},
	{0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", tls.VersionTLS12},
	{0x006a, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", tls.VersionTLS12},
	{0x00a2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", tls.VersionTLS12},
	{0x00a3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", tls.VersionTLS12},
	{0x00bd, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256", tls.VersionTLS12},
	{0x00c3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256", tls.VersionTLS12},
	{0xc056, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256", tls.VersionTLS12},
	{0xc057, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384", tls.VersionTLS12},

	// DHE with RSA certificates.
	{0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", tls.VersionTLS10},
	{0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA", tls.VersionTLS10},
	{0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", tls.VersionTLS10},
	{0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", tls.VersionTLS10},
	{0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", tls.VersionTLS10},
	{0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", tls.VersionTLS10},
	{0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", tls.VersionTLS10},
	{0x009a, "TLS_DHE_RSA_WITH_SEED_CBC_SHA", tls.VersionTLS10},
	{0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", tls.VersionTLS12},
	{0x006b, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", tls.VersionTLS12},
	{0x009e, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", tls.VersionTLS12},
	{0x009f, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", tls.VersionTLS12},
	{0x00be, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", tls.VersionTLS12},
	{0x00c4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", tls.VersionTLS12},
	{0xc044, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256", tls.VersionTLS12},
	{0xc045, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384", tls.VersionTLS12},
	{0xc052, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256", tls.VersionTLS12},
	{0xc053, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384", tls.VersionTLS12},
	{0xc09e, "TLS_DHE_RSA_WITH_AES_128_CCM", tls.VersionTLS12},
	{0xc09f, "TLS_DHE_RSA_WITH_AES_256_CCM", tls.VersionTLS12},
	{0xc0a2, "TLS_DHE_RSA_WITH_AES_128_CCM_8", tls.VersionTLS12},
	{0xc0a3, "TLS_DHE_RSA_WITH_AES_256_CCM_8", tls.VersionTLS12},
	{0xccaa, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", tls.VersionTLS12},

	// Anonymous (unauthenticated) Diffie-Hellman.
	{0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", tls.VersionTLS10},
	{0x0018, "TLS_DH_anon_WITH_RC4_128_MD5", tls.VersionTLS10},
	{0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", tls.VersionTLS10},
	{0x001a, "TLS_DH_anon_WITH_DES_CBC_SHA", tls.VersionTLS10},
	{0x001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", tls.VersionTLS10},
	{0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA", tls.VersionTLS10},
	{0x003a, "TLS_DH_anon_WITH_AES_256_CBC_SHA", tls.VersionTLS10},
	{0x0046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", tls.VersionTLS10},
	{0x0089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA", tls.VersionTLS10},
	{0x006c, "TLS_DH_anon_WITH_AES_128_CBC_SHA256", tls.VersionTLS12},
	{0x006d, "TLS_DH_anon_WITH_AES_256_CBC_SHA256", tls.VersionTLS12},
	{0x00a6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256", tls.VersionTLS12},
	{0x00a7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384", tls.VersionTLS12},
	{0x00bf, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256", tls.VersionTLS12},
	{0x00c5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256", tls.VersionTLS12},

	// ECDHE with ECDSA certificates.
	{0xc006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA", tls.VersionTLS10},
	{0xc007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", tls.VersionTLS10},
	{0xc008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", tls.VersionTLS10},
	{0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", tls.VersionTLS10},
	{0xc00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", tls.VersionTLS10},
	{0xc023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", tls.VersionTLS12},
	{0xc024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", tls.VersionTLS12},
	{0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", tls.VersionTLS12},
	{0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", tls.VersionTLS12},
	{0xc048, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256", tls.VersionTLS12},
	{0xc049, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384", tls.VersionTLS12},
	{0xc05c, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", tls.VersionTLS12},
	{0xc05d, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384", tls.VersionTLS12},
	{0xc072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", tls.VersionTLS12},
	{0xc073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", tls.VersionTLS12},
	{0xc0ac, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", tls.VersionTLS12},
	{0xc0ad, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", tls.VersionTLS12},
	{0xc0ae, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", tls.VersionTLS12},
	{0xc0af, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", tls.VersionTLS12},
	{0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", tls.VersionTLS12},

	// ECDHE with RSA certificates.
	{0xc010, "TLS_ECDHE_RSA_WITH_NULL_SHA", tls.VersionTLS10},
	{0xc011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", tls.VersionTLS10},
	{0xc012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", tls.VersionTLS10},
	{0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", tls.VersionTLS10},
	{0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", tls.VersionTLS10},
	{0xc027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", tls.VersionTLS12},
	{0xc028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", tls.VersionTLS12},
	{0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", tls.VersionTLS12},
	{0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", tls.VersionTLS12},
	{0xc04c, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256", tls.VersionTLS12},
	{0xc04d, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384", tls.VersionTLS12},
	{0xc060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", tls.VersionTLS12},
	{0xc061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384", tls.VersionTLS12},
	{0xc076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", tls.VersionTLS12},
	{0xc077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", tls.VersionTLS12},
	{0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", tls.VersionTLS12},

	// Anonymous (unauthenticated) ECDH.
	{0xc015, "TLS_ECDH_anon_WITH_NULL_SHA", tls.VersionTLS10},
	{0xc016, "TLS_ECDH_anon_WITH_RC4_128_SHA", tls.VersionTLS10},
	{0xc017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", tls.VersionTLS10},
	{0xc018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", tls.VersionTLS10},
	{0xc019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", tls.VersionTLS10},
}

var legacyCipherSuiteNames = func() map[uint16]string {
	names := make(map[uint16]string, len(legacyCipherSuites))
	for _, suite := range legacyCipherSuites {
		names[suite.ID] = suite.Name
	}
	return names
}()

// LegacyCipherSuites returns the TLS 1.0-1.2 cipher suites understood by the
// raw probe. The returned slice is a copy.
func LegacyCipherSuites() []LegacyCipherSuite {
	return append([]LegacyCipherSuite(nil), legacyCipherSuites...)
}

// LegacyCipherSuitesForVersion returns the catalog suites that can be
// negotiated on the given protocol version (tls.VersionTLS10, tls.VersionTLS11
// or tls.VersionTLS12). It returns nil for any other version.
func LegacyCipherSuitesForVersion(version uint16) []uint16 {
	if !isLegacyVersion(version) {
		return nil
	}
	ids := make([]uint16, 0, len(legacyCipherSuites))
	for _, suite := range legacyCipherSuites {
		if suite.MinVersion <= version {
			ids = append(ids, suite.ID)
		}
	}
	return ids
}

// LegacyEnumeration is the outcome of EnumerateLegacyCipherSuites.
type LegacyEnumeration struct {
	// Supported holds one StatusSupported result per cipher suite the server
	// selected, in the order the server preferred them.
	Supported []Result
	// Complete reports whether every offered suite was classified: the server
	// either selected it or refused the ClientHello that still offered it.
	Complete bool
	// Unresolved lists the offered suites that were never classified because
	// the enumeration could not finish. It is empty when Complete is true.
	Unresolved []uint16
	// Last is the outcome that ended the enumeration: normally the alert or
	// closed connection that refused the remaining suites.
	Last Result
	// Connections is the number of ClientHellos sent.
	Connections int
}

// EnumerateLegacyCipherSuites finds which of cipherSuites a server supports on
// one TLS 1.0-1.2 protocol version with as few connections as possible.
//
// It offers all remaining suites in a single ClientHello, records the suite
// the ServerHello selects, removes it and repeats until the server refuses the
// rest. A server that supports k of the offered suites is enumerated with k+1
// connections, instead of one connection per offered suite.
//
// An unanswered ClientHello (timeout, unparseable answer, closed connection)
// is sent again after a short pause. A second closed connection is accepted as
// the server's way of refusing the remaining suites; otherwise the enumeration
// ends with Complete set to false and the remaining suites in Unresolved.
//
// Configuration errors are returned as errors. If ctx ends, the suites found
// so far are returned together with ctx.Err().
func EnumerateLegacyCipherSuites(ctx context.Context, opts Options, version uint16, cipherSuites []uint16) (LegacyEnumeration, error) {
	var enumeration LegacyEnumeration
	if err := validateLegacyProbe(opts, version); err != nil {
		return enumeration, err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	seen := make(map[uint16]bool, len(cipherSuites))
	remaining := make([]uint16, 0, len(cipherSuites))
	for _, cipherSuite := range cipherSuites {
		if !seen[cipherSuite] {
			seen[cipherSuite] = true
			remaining = append(remaining, cipherSuite)
		}
	}

	retries := 0
	for len(remaining) > 0 {
		if err := ctx.Err(); err != nil {
			enumeration.Unresolved = remaining
			return enumeration, err
		}

		result, err := probeLegacyOffer(ctx, opts, version, remaining)
		if err != nil {
			enumeration.Unresolved = remaining
			return enumeration, err
		}
		enumeration.Connections++
		enumeration.Last = result

		switch {
		case result.Status == StatusSupported:
			enumeration.Supported = append(enumeration.Supported, result)
			remaining = removeCipherSuite(remaining, result.CipherSuite)
			continue
		case result.Status == StatusAlert,
			result.Status == StatusRejected && result.ErrorCode == ErrorCodeVersionMismatch:
			// The server answered and wants none of the remaining suites on
			// this protocol version.
			enumeration.Complete = true
			return enumeration, nil
		case result.Status == StatusRejected:
			// A suite that was not offered: the answer cannot be trusted.
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

func removeCipherSuite(cipherSuites []uint16, cipherSuite uint16) []uint16 {
	kept := make([]uint16, 0, len(cipherSuites))
	for _, candidate := range cipherSuites {
		if candidate != cipherSuite {
			kept = append(kept, candidate)
		}
	}
	return kept
}

// ProbeLegacyCipherSuites probes each cipher suite independently on one
// TLS 1.0-1.2 protocol version.
//
// Results are returned in the same order as cipherSuites. Configuration errors
// stop probing and are returned as errors; network and protocol outcomes are
// represented in each Result. If ctx ends between two probes, probing stops and
// the results collected so far are returned together with ctx.Err().
//
// It opens one connection per suite. EnumerateLegacyCipherSuites answers the
// same question with far fewer connections when per-suite refusal details are
// not needed.
func ProbeLegacyCipherSuites(ctx context.Context, opts Options, version uint16, cipherSuites []uint16) ([]Result, error) {
	if err := validateLegacyProbe(opts, version); err != nil {
		return nil, err
	}
	if len(cipherSuites) == 0 {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	results := make([]Result, 0, len(cipherSuites))
	for _, cipherSuite := range cipherSuites {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		result, err := ProbeLegacyCipherSuite(ctx, opts, version, cipherSuite)
		if err != nil {
			return results, err
		}
		results = append(results, result)
	}
	return results, nil
}

// ProbeLegacyCipherSuite sends a minimal TLS 1.0, 1.1 or 1.2 ClientHello that
// offers exactly one cipher suite and classifies the first useful response.
//
// The suite is reported as StatusSupported only when the ServerHello selects
// it on the requested protocol version. A ServerHello for the same suite on a
// lower version is StatusRejected with ErrorCodeVersionMismatch. A server that
// does not support the suite normally answers with a handshake_failure alert
// (StatusAlert) or closes the connection (StatusClosed).
//
// Like the TLS 1.3 probe this is ClientHello-only evidence: no key exchange is
// performed, so any cipher suite ID can be offered, including suites that
// crypto/tls does not implement. Options.KeyShareGroups controls the
// supported_groups extension.
func ProbeLegacyCipherSuite(ctx context.Context, opts Options, version uint16, cipherSuite uint16) (Result, error) {
	result, err := probeLegacyOffer(ctx, opts, version, []uint16{cipherSuite})
	// The result always describes the suite that was asked about, also when
	// the server answered with a different one.
	result.CipherSuite = cipherSuite
	result.Name = CipherSuiteName(cipherSuite)
	return result, err
}

// probeLegacyOffer sends one ClientHello offering cipherSuites and classifies
// the answer. On StatusSupported the result names the suite the server
// selected; on every other status it names the first offered suite.
func probeLegacyOffer(ctx context.Context, opts Options, version uint16, cipherSuites []uint16) (Result, error) {
	result := Result{
		Status:        StatusInconclusive,
		EvidenceLevel: EvidenceClientHelloOnly,
	}
	if len(cipherSuites) > 0 {
		result.CipherSuite = cipherSuites[0]
		result.Name = CipherSuiteName(cipherSuites[0])
	}

	if err := validateLegacyProbe(opts, version); err != nil {
		return result, err
	}
	if len(cipherSuites) == 0 {
		return result, configError("cipher_suites", "must not be empty", nil)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	clientHello, err := buildLegacyClientHello(opts, version, cipherSuites)
	if err != nil {
		return withError(result, ErrorCodeBuildClientHelloFailed, err.Error()), nil
	}

	dialContext := opts.DialContext
	if dialContext == nil {
		dialer := net.Dialer{Timeout: timeout}
		dialContext = dialer.DialContext
	}
	conn, err := dialContext(ctx, "tcp", opts.Address)
	if err != nil {
		result.Status = statusForNetworkError(err)
		return withError(result, ErrorCodeConnectFailed, stableNetworkError(err)), nil
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return withError(result, ErrorCodeDeadlineFailed, err.Error()), nil
	}
	stopOnContextDone := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stopOnContextDone()

	if _, err := conn.Write(clientHello); err != nil {
		result.Status = statusForNetworkError(err)
		return withError(result, ErrorCodeWriteFailed, stableNetworkError(err)), nil
	}

	read, err := readProbeRecordWith(conn, result, func(body []byte, result Result) readResult {
		return parseLegacyServerHello(body, result, version, cipherSuites)
	})
	return read.result, err
}

func validateLegacyProbe(opts Options, version uint16) error {
	if err := ValidateOptions(opts); err != nil {
		return err
	}
	if !isLegacyVersion(version) {
		return configError("version", fmt.Sprintf("0x%04x is not TLS 1.0, 1.1 or 1.2", version), nil)
	}
	return nil
}

func isLegacyVersion(version uint16) bool {
	return version == tls.VersionTLS10 || version == tls.VersionTLS11 || version == tls.VersionTLS12
}

func legacyVersionName(version uint16) string {
	switch version {
	case 0x0300:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("version 0x%04x", version)
	}
}

// buildLegacyClientHello builds a ClientHello record whose client_version is
// the probed version and whose cipher_suites list holds exactly the offered
// suites. It carries no supported_versions extension, so a server can only
// answer with the probed version or a lower one.
func buildLegacyClientHello(opts Options, version uint16, cipherSuites []uint16) ([]byte, error) {
	if len(cipherSuites) == 0 {
		return nil, errors.New("no cipher suite to offer")
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}

	var body []byte
	body = appendUint16(body, version)
	body = append(body, random...)
	body = appendOpaque8(body, nil) // empty session ID: no resumption
	body = appendUint16(body, uint16(2*len(cipherSuites)))
	for _, cipherSuite := range cipherSuites {
		body = appendUint16(body, cipherSuite)
	}
	body = append(body, 1, 0) // null compression only

	extensions := buildLegacyClientHelloExtensions(opts, version)
	// Some old TLS stacks hang on ClientHello messages of 256 to 511 bytes;
	// like browsers, pad such a message to 512 bytes (RFC 7685).
	if unpadded := 4 + len(body) + 2 + len(extensions); unpadded >= 256 && unpadded < 512 {
		padding := 512 - unpadded - 4
		if padding < 1 {
			padding = 1
		}
		extensions = appendExtension(extensions, extensionPadding, make([]byte, padding))
	}
	body = appendOpaque16(body, extensions)

	handshake := []byte{1}
	handshake = appendUint24(handshake, len(body))
	handshake = append(handshake, body...)

	// 0x0301 is the record version every TLS 1.0-1.2 stack accepts for the
	// first flight (RFC 5246 appendix E.1).
	record := []byte{22}
	record = appendUint16(record, tls.VersionTLS10)
	record = appendUint16(record, uint16(len(handshake)))
	record = append(record, handshake...)
	return record, nil
}

func buildLegacyClientHelloExtensions(opts Options, version uint16) []byte {
	var extensions []byte
	if opts.ServerName != "" && !isIPLiteral(opts.ServerName) {
		var serverName []byte
		serverName = append(serverName, 0)
		serverName = appendOpaque16(serverName, []byte(opts.ServerName))
		extensions = appendExtension(extensions, extensionServerName, appendOpaque16(nil, serverName))
	}

	// Secure renegotiation and extended master secret are signalled because
	// hardened servers refuse ClientHellos without them; the probe never gets
	// far enough to use either.
	extensions = appendExtension(extensions, extensionRenegotiationInfo, []byte{0})
	extensions = appendExtension(extensions, extensionExtendedMasterSecret, nil)

	// ECDHE suites are only selected when the client names curves it supports.
	var supportedGroups []byte
	for _, group := range normalizedKeyShareGroups(opts) {
		supportedGroups = appendUint16(supportedGroups, group)
	}
	extensions = appendExtension(extensions, extensionSupportedGroups, appendOpaque16(nil, supportedGroups))
	extensions = appendExtension(extensions, extensionECPointFormats, []byte{1, 0}) // uncompressed

	// signature_algorithms exists from TLS 1.2 on (RFC 5246 section 7.4.1.4.1).
	if version == tls.VersionTLS12 {
		var signatureAlgorithms []byte
		for _, algorithm := range legacyClientHelloSignatureAlgorithms {
			signatureAlgorithms = appendUint16(signatureAlgorithms, algorithm)
		}
		extensions = appendExtension(extensions, extensionSignatureAlgorithms, appendOpaque16(nil, signatureAlgorithms))
	}

	var protocols []byte
	for _, protocol := range opts.ALPN {
		if len(protocol) == 0 || len(protocol) > 255 {
			continue
		}
		protocols = appendOpaque8(protocols, []byte(protocol))
	}
	if len(protocols) > 0 {
		extensions = appendExtension(extensions, extensionALPN, appendOpaque16(nil, protocols))
	}

	return extensions
}

// parseLegacyServerHello classifies a TLS 1.0-1.2 ServerHello against the
// suites that were offered. Unlike TLS 1.3, the negotiated version is
// ServerHello.server_version itself, and a server is free to answer a TLS 1.2
// ClientHello on a lower version it still supports.
func parseLegacyServerHello(body []byte, result Result, version uint16, offered []uint16) readResult {
	if len(body) < 38 {
		result.Status = StatusInconclusive
		return readResult{result: withError(result, ErrorCodeServerHelloTooShort, "ServerHello is too short")}
	}

	offset := 34
	sessionIDLength := int(body[offset])
	offset++
	if offset+sessionIDLength+3 > len(body) {
		result.Status = StatusInconclusive
		return readResult{result: withError(result, ErrorCodeServerHelloTruncated, "ServerHello session ID is truncated")}
	}
	offset += sessionIDLength

	selectedCipher := binary.BigEndian.Uint16(body[offset : offset+2])
	wasOffered := false
	for _, cipherSuite := range offered {
		if cipherSuite == selectedCipher {
			wasOffered = true
			break
		}
	}
	if !wasOffered {
		result.Status = StatusRejected
		return readResult{result: withError(result, ErrorCodeRejectedCipher, fmt.Sprintf("server selected %s", CipherSuiteName(selectedCipher)))}
	}

	serverVersion := binary.BigEndian.Uint16(body[0:2])
	if serverVersion != version {
		result.Status = StatusRejected
		return readResult{result: withError(result, ErrorCodeVersionMismatch, fmt.Sprintf(
			"server selected the cipher suite on %s instead of %s", legacyVersionName(serverVersion), legacyVersionName(version)))}
	}

	result.CipherSuite = selectedCipher
	result.Name = CipherSuiteName(selectedCipher)
	result.Status = StatusSupported
	return readResult{result: result}
}
