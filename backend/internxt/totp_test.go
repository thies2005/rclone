package internxt

import (
	"regexp"
	"testing"
)

func TestGenerateTOTPCode_EmptySecret(t *testing.T) {
	_, err := generateTOTPCode("")
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestGenerateTOTPCode_InvalidSecret(t *testing.T) {
	_, err := generateTOTPCode("!!!not-base32!!!")
	if err == nil {
		t.Fatal("expected error for invalid secret")
	}
}

func TestGenerateTOTPCode_ValidSecret(t *testing.T) {
	code, err := generateTOTPCode("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	matched, _ := regexp.MatchString(`^\d{6}$`, code)
	if !matched {
		t.Fatalf("expected 6-digit code, got %q", code)
	}
}
