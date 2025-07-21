// File: utils/tls.go
package utils

import (
	"crypto/tls"
	"sort"
)

const (
	DefaultMaxConcurrency = 20
	DefaultTLS13Tries     = 10
)

var TLSVersions = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

func TLSVersionToUint16(ver string) uint16 {
	switch ver {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	default:
		return 0
	}
}

func FilterTLSVersions(minVersion uint16) []uint16 {
	keys := make([]uint16, 0)
	for v := range TLSVersions {
		if v >= minVersion {
			keys = append(keys, v)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}
