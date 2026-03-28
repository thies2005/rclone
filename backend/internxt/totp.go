package internxt

import (
	"fmt"
	"time"

	"github.com/pquerna/otp/totp"
)

func generateTOTPCode(secret string) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("totp_secret is empty")
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP code: %w", err)
	}
	return code, nil
}
