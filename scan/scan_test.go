package scan

import "testing"

func TestValidatePeerCertificatesSkipVerify(t *testing.T) {
	got := ValidatePeerCertificates("example.com", nil, true)

	if got.Status != CertValidationSkipped {
		t.Fatalf("Status = %q, want %q", got.Status, CertValidationSkipped)
	}
	if got.Message == "" {
		t.Fatal("Message should explain that validation was skipped")
	}
}

func TestValidatePeerCertificatesUnavailable(t *testing.T) {
	got := ValidatePeerCertificates("example.com", nil, false)

	if got.Status != CertValidationUnavailable {
		t.Fatalf("Status = %q, want %q", got.Status, CertValidationUnavailable)
	}
	if got.Message == "" {
		t.Fatal("Message should explain why validation is unavailable")
	}
}
