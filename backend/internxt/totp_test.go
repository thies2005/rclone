package internxt

import (
	"regexp"
	"testing"

	"github.com/rclone/rclone/fs/config/obscure"
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

func TestIsBase32Secret(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"", false},
		{"JBSWY3DPEHPK3PXP", true},                 // standard base32 seed
		{"HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", true}, // 32-char seed
		{"JBSWY3DPEHPK3PXP======", true},           // with padding
		{"abc", false},                             // lowercase
		{"JBSWY3DPEHPK3PXPx", false},               // mixed case
		{"JBSWY0Y3DP", false},                      // contains 0
		{"JBSWY1Y3DP", false},                      // contains 1
		{"JBSWY8Y3DP", false},                      // contains 8
		{"JBSWY9Y3DP", false},                      // contains 9
		{"JBSW-Y3DP", false},                       // contains -
		{"JBSW_Y3DP", false},                       // contains _
	}
	for _, tt := range tests {
		got := isBase32Secret(tt.input)
		if got != tt.want {
			t.Errorf("isBase32Secret(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestRevealTOTPSecret_Empty(t *testing.T) {
	got := revealTOTPSecret("")
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestRevealTOTPSecret_PlaintextBase32(t *testing.T) {
	// A standard base32 TOTP seed stored as plaintext (legacy config).
	// This MUST be returned as-is, NOT passed through obscure.Reveal()
	// which would silently corrupt it.
	seed := "JBSWY3DPEHPK3PXP"
	got := revealTOTPSecret(seed)
	if got != seed {
		t.Errorf("revealTOTPSecret(%q) = %q, want %q (plaintext must be preserved)", seed, got, seed)
	}
}

func TestRevealTOTPSecret_LongPlaintextBase32(t *testing.T) {
	// 32-char seed: decodes to 24 bytes via base64url and passes Reveal() length check into garbage.
	// This is the exact scenario described in the bug report.
	seed := "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ"
	got := revealTOTPSecret(seed)
	if got != seed {
		t.Errorf("revealTOTPSecret(%q) = %q, want %q (long base32 plaintext must be preserved)", seed, got, seed)
	}
}

func TestRevealTOTPSecret_Obscured(t *testing.T) {
	// An obscured value should be correctly revealed.
	seed := "JBSWY3DPEHPK3PXP"
	obscured, err := obscure.Obscure(seed)
	if err != nil {
		t.Fatalf("failed to obscure seed: %v", err)
	}
	got := revealTOTPSecret(obscured)
	if got != seed {
		t.Errorf("revealTOTPSecret(obscured(%q)) = %q, want %q", seed, got, seed)
	}
}

func TestRevealTOTPSecret_ObscuredRoundTrip(t *testing.T) {
	// Full round-trip: obscure, reveal, and generate code.
	seed := "JBSWY3DPEHPK3PXP"
	obscured, err := obscure.Obscure(seed)
	if err != nil {
		t.Fatalf("failed to obscure: %v", err)
	}
	revealed := revealTOTPSecret(obscured)
	code, err := generateTOTPCode(revealed)
	if err != nil {
		t.Fatalf("failed to generate TOTP code from revealed secret: %v", err)
	}
	matched, _ := regexp.MatchString(`^\d{6}$`, code)
	if !matched {
		t.Errorf("expected 6-digit code, got %q", code)
	}
}

func TestRevealTOTPSecret_PlaintextRoundTrip(t *testing.T) {
	// Legacy plaintext seed should work directly without obscuring
	seed := "JBSWY3DPEHPK3PXP"
	revealed := revealTOTPSecret(seed)
	code, err := generateTOTPCode(revealed)
	if err != nil {
		t.Fatalf("failed to generate TOTP code from plaintext secret: %v", err)
	}
	matched, _ := regexp.MatchString(`^\d{6}$`, code)
	if !matched {
		t.Errorf("expected 6-digit code, got %q", code)
	}
}
