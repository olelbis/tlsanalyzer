package build

import "runtime"

var Version = "v0.31.3"
var BuildTime string
var BuildUser string

// GoVersion returns the Go toolchain version the binary was built with. It
// matters for reports because certificate verdicts depend on the crypto/x509
// behaviour of that toolchain.
func GoVersion() string { return runtime.Version() }
