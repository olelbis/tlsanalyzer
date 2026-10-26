package main

import (
	"runtime"
	"strings"
	"testing"
)

func TestFormatVersionIncludesGoToolchain(t *testing.T) {
	if got := formatVersion(); !strings.Contains(got, "("+runtime.Version()+")") {
		t.Fatalf("formatVersion() = %q, want it to include (%s)", got, runtime.Version())
	}
}
