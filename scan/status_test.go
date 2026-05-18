package scan

import "testing"

func TestIsExecutionStatus(t *testing.T) {
	for _, status := range []string{ScanStatusNetworkError, ScanStatusTimeout, ScanStatusHandshake} {
		if !IsExecutionStatus(status) {
			t.Fatalf("%s should be an execution status", status)
		}
	}
	for _, status := range []string{ScanStatusSupported, ScanStatusUnsupported, ""} {
		if IsExecutionStatus(status) {
			t.Fatalf("%s should not be an execution status", status)
		}
	}
}

func TestIsTransientStatus(t *testing.T) {
	for _, status := range []string{ScanStatusNetworkError, ScanStatusTimeout} {
		if !IsTransientStatus(status) {
			t.Fatalf("%s should be transient", status)
		}
	}
	for _, status := range []string{ScanStatusHandshake, ScanStatusUnsupported, ScanStatusSupported, ""} {
		if IsTransientStatus(status) {
			t.Fatalf("%s should not be transient", status)
		}
	}
}
