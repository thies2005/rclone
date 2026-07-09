package internxt

import (
	"fmt"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/rclone/rclone/fs/config/obscure"
)

func generateTOTPCode(secret string) (string, error) {
	return generateTOTPCodeWithOffset(secret, 0)
}

// generateTOTPCodeWithOffset generates a TOTP code for a time window offset from
// now by the given number of 30-second periods (e.g. -1 = 30s ago, +1 = 30s
// ahead). It is used to retry 2FA against adjacent windows when clock skew
// between the device and the Internxt API causes the current-window code to be
// rejected.
func generateTOTPCodeWithOffset(secret string, offset int64) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("totp_secret is empty")
	}
	t := time.Now().Add(time.Duration(offset) * 30 * time.Second)
	code, err := totp.GenerateCode(secret, t)
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP code: %w", err)
	}
	return code, nil
}

// isBase32Secret returns true if s consists entirely of characters used by
// base32 encoding (A-Z, 2-7) plus optional padding (=).  An obscured rclone
// value is base64url-encoded (A-Z, a-z, 0-9, -, _) and will almost always
// contain lowercase letters or digits outside 2-7, so a pure base32 string
// can be confidently identified as a plaintext TOTP seed.
func isBase32Secret(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z':
			// ok
		case c >= '2' && c <= '7':
			// ok
		case c == '=':
			// padding - ok
		default:
			return false
		}
	}
	return true
}

// revealTOTPSecret returns the plaintext TOTP seed from a stored value.
//
// totp_secret is defined with IsPassword: true so rclone auto-obscures it on
// save.  However, configs created before that flag was added may still store
// the seed as plaintext.  Because a standard base32 seed (e.g. a 32-char
// A-Z2-7 string) is also valid base64url, obscure.Reveal() would silently
// "decrypt" such a plaintext seed into garbage without returning an error.
//
// We avoid this by checking whether the raw value looks like a pure base32
// string first.  An obscured value always contains characters outside the
// base32 alphabet (lowercase letters, 0/1/8/9, -, _), so a pure base32 value
// can only be a plaintext seed.
func revealTOTPSecret(raw string) string {
	if raw == "" {
		return ""
	}
	// Pure base32 must be a legacy plaintext seed.
	if isBase32Secret(raw) {
		return raw
	}
	// Otherwise treat it as an obscured rclone value.
	revealed, err := obscure.Reveal(raw)
	if err != nil {
		// Not valid obscured data - return as-is.
		return raw
	}
	return revealed
}
