package scan

// IsExecutionStatus reports whether a scan status means the scanner could not
// obtain protocol evidence because of an operational failure.
func IsExecutionStatus(status string) bool {
	switch status {
	case ScanStatusNetworkError, ScanStatusTimeout, ScanStatusHandshake:
		return true
	default:
		return false
	}
}

// IsTransientStatus reports whether retrying the scan may reasonably succeed.
func IsTransientStatus(status string) bool {
	switch status {
	case ScanStatusNetworkError, ScanStatusTimeout:
		return true
	default:
		return false
	}
}
