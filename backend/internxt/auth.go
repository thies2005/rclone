// Package internxt provides authentication handling
package internxt

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand"
	"time"

	"github.com/golang-jwt/jwt/v5"
	internxtauth "github.com/internxt/rclone-adapter/auth"
	internxtconfig "github.com/internxt/rclone-adapter/config"
	sdkerrors "github.com/internxt/rclone-adapter/errors"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/lib/oauthutil"
	"golang.org/x/oauth2"
)

type userInfo struct {
	RootFolderID string
	Bucket       string
	BridgeUser   string
	UserID       string
}

type userInfoConfig struct {
	Token string
}

type userInfoResult struct {
	Info     *userInfo
	NewToken string
}

// getUserInfo fetches user metadata from the refresh endpoint.
// It also returns the refreshed JWT token so the caller can persist it.
func getUserInfo(ctx context.Context, cfg *userInfoConfig) (*userInfoResult, error) {
	refreshCfg := internxtconfig.NewDefaultToken(cfg.Token)
	resp, err := internxtauth.RefreshToken(ctx, refreshCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}

	if resp.User.Bucket == "" {
		return nil, errors.New("API response missing user.bucket")
	}
	if resp.User.RootFolderID == "" {
		return nil, errors.New("API response missing user.rootFolderId")
	}
	if resp.User.BridgeUser == "" {
		return nil, errors.New("API response missing user.bridgeUser")
	}
	if resp.User.UserID == "" {
		return nil, errors.New("API response missing user.userId")
	}

	info := &userInfo{
		RootFolderID: resp.User.RootFolderID,
		Bucket:       resp.User.Bucket,
		BridgeUser:   resp.User.BridgeUser,
		UserID:       resp.User.UserID,
	}

	useToken := resp.NewToken
	if useToken == "" {
		useToken = resp.Token
	}

	fs.Debugf(nil, "User info: rootFolderId=%s, bucket=%s",
		info.RootFolderID, info.Bucket)

	return &userInfoResult{Info: info, NewToken: useToken}, nil
}

// parseJWTExpiry extracts the expiry time from a JWT token string
func parseJWTExpiry(tokenString string) (time.Time, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return time.Time{}, errors.New("invalid token claims")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return time.Time{}, errors.New("token missing expiration")
	}

	return time.Unix(int64(exp), 0), nil
}

// jwtToOAuth2Token converts a JWT string to an oauth2.Token with expiry
func jwtToOAuth2Token(jwtString string) (*oauth2.Token, error) {
	expiry, err := parseJWTExpiry(jwtString)
	if err != nil {
		return nil, err
	}

	return &oauth2.Token{
		AccessToken: jwtString,
		TokenType:   "Bearer",
		Expiry:      expiry,
	}, nil
}

// computeBasicAuthHeader creates the BasicAuthHeader for bucket operations
func computeBasicAuthHeader(bridgeUser, userID string) string {
	sum := sha256.Sum256([]byte(userID))
	hexPass := hex.EncodeToString(sum[:])
	creds := fmt.Sprintf("%s:%s", bridgeUser, hexPass)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
}

// refreshJWTToken refreshes the token using Internxt's refresh endpoint
func refreshJWTToken(ctx context.Context, name string, m configmap.Mapper) error {
	currentToken, err := oauthutil.GetToken(name, m)
	if err != nil {
		return fmt.Errorf("failed to get current token: %w", err)
	}

	cfg := internxtconfig.NewDefaultToken(currentToken.AccessToken)
	resp, err := internxtauth.RefreshToken(ctx, cfg)
	if err != nil {
		return fmt.Errorf("refresh request failed: %w", err)
	}

	if resp.NewToken == "" {
		return errors.New("refresh response missing newToken")
	}

	// Convert JWT to oauth2.Token format
	token, err := jwtToOAuth2Token(resp.NewToken)
	if err != nil {
		return fmt.Errorf("failed to parse refreshed token: %w", err)
	}

	err = oauthutil.PutToken(name, m, token, false)
	if err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	fs.Debugf(name, "Token refreshed successfully, new expiry: %v", token.Expiry)
	return nil
}

// reLogin performs a full re-login using stored email+password credentials.
// Returns the AccessResponse on success, or an error if 2FA is required or login fails.
func (f *Fs) reLogin(ctx context.Context) (*internxtauth.AccessResponse, error) {
	password, err := obscure.Reveal(f.opt.Pass)
	if err != nil {
		return nil, fmt.Errorf("password appears to be stored as plaintext - please recreate this remote with: rclone config reconnect %s:", f.name)
	}

	cfg := internxtconfig.NewDefaultToken("")
	cfg.HTTPClient = fshttp.NewClient(ctx)

	loginResp, err := internxtauth.Login(ctx, cfg, f.opt.Email)
	if err != nil {
		return nil, fmt.Errorf("re-login check failed: %w", err)
	}

	if loginResp.TFA {
		totpSecret := revealTOTPSecret(f.opt.TOTPSecret)
		if totpSecret == "" {
			return nil, errors.New("account requires 2FA but no totp_secret configured - please run: rclone config reconnect " + f.name + ":")
		}

		// Try the current TOTP window (T), then T-1 and T+1 to tolerate clock
		// skew between the device and the Internxt API. A 401/403 on the 2FA
		// code is treated as "wrong window, try the next"; any other error is
		// returned immediately.
		timeOffsets := []int64{0, -1, 1}
		var lastLoginErr error
		for i, offset := range timeOffsets {
			code, genErr := generateTOTPCodeWithOffset(totpSecret, offset)
			if genErr != nil {
				return nil, fmt.Errorf("failed to generate TOTP code: %w", genErr)
			}
			if offset != 0 {
				fs.Debugf(f, "Generated TOTP code for 2FA with time offset %d (attempt %d/3)", offset, i+1)
			} else {
				fs.Debugf(f, "Generated TOTP code for 2FA (attempt 1/3)")
			}

			resp, loginErr := internxtauth.DoLogin(ctx, cfg, f.opt.Email, password, code)
			if loginErr == nil {
				if offset != 0 {
					fs.Debugf(f, "2FA succeeded with time offset %d", offset)
				}
				return resp, nil
			}
			var httpErr *sdkerrors.HTTPError
			if errors.As(loginErr, &httpErr) && (httpErr.StatusCode() == 401 || httpErr.StatusCode() == 403) {
				lastLoginErr = loginErr
				fs.Debugf(f, "2FA failed with time offset %d, trying next window", offset)
				continue
			}
			return nil, fmt.Errorf("re-login failed: %w", loginErr)
		}
		return nil, fmt.Errorf("re-login failed (all TOTP time windows failed): %w", lastLoginErr)
	}

	resp, err := internxtauth.DoLogin(ctx, cfg, f.opt.Email, password, "")
	if err != nil {
		return nil, fmt.Errorf("re-login failed: %w", err)
	}

	return resp, nil
}

// refreshOrReLogin tries to refresh the JWT token first; if that fails with 401,
// it falls back to a full re-login using stored credentials.
func (f *Fs) refreshOrReLogin(ctx context.Context) error {
	refreshErr := refreshJWTToken(ctx, f.name, f.m)
	if refreshErr == nil {
		newToken, err := oauthutil.GetToken(f.name, f.m)
		if err != nil {
			return fmt.Errorf("failed to get refreshed token: %w", err)
		}
		f.cfg.Token = newToken.AccessToken
		f.cfg.BasicAuthHeader = computeBasicAuthHeader(f.bridgeUser, f.userID)
		fs.Debugf(f, "Token refresh succeeded")
		return nil
	}

	var httpErr *sdkerrors.HTTPError
	if !errors.As(refreshErr, &httpErr) || httpErr.StatusCode() != 401 {
		return refreshErr
	}

	fs.Debugf(f, "Token refresh returned 401, attempting re-login with stored credentials")

	resp, err := f.reLogin(ctx)
	if err != nil {
		return fmt.Errorf("re-login fallback failed: %w", err)
	}

	oauthToken, err := jwtToOAuth2Token(resp.NewToken)
	if err != nil {
		return fmt.Errorf("failed to parse re-login token: %w", err)
	}
	err = oauthutil.PutToken(f.name, f.m, oauthToken, true)
	if err != nil {
		return fmt.Errorf("failed to save re-login token: %w", err)
	}

	f.cfg.Token = oauthToken.AccessToken
	f.bridgeUser = resp.User.BridgeUser
	f.userID = resp.User.UserID
	f.cfg.BasicAuthHeader = computeBasicAuthHeader(f.bridgeUser, f.userID)
	f.cfg.Bucket = resp.User.Bucket
	f.cfg.RootFolderID = resp.User.RootFolderID

	fs.Debugf(f, "Re-login succeeded, new token expiry: %v", oauthToken.Expiry)
	return nil
}

func (f *Fs) reAuthorizeLocked(ctx context.Context) error {
	return f.refreshOrReLogin(ctx)
}

func (f *Fs) renewToken(ctx context.Context) error {
	f.authMu.Lock()
	defer f.authMu.Unlock()

	return f.reAuthorizeLocked(ctx)
}

// getBackoffDuration returns the backoff duration for a given attempt number with jitter.
// Backoff steps: 1m, 5m, 15m, 1h (capped at 1h from attempt 4 on).
// Adds up to 10% random jitter so concurrent Fs instances don't retry in lockstep.
func getBackoffDuration(attempt int) time.Duration {
	var baseDuration time.Duration
	switch {
	case attempt == 1:
		baseDuration = time.Minute
	case attempt == 2:
		baseDuration = 5 * time.Minute
	case attempt == 3:
		baseDuration = 15 * time.Minute
	case attempt >= 4:
		baseDuration = time.Hour
	default:
		baseDuration = time.Minute
	}

	// Subtract up to 10% jitter.
	jitter := time.Duration(mrand.Int63n(int64(baseDuration) / 10))
	return baseDuration - jitter
}

// reAuthorize is called after getting 401 from the server.
// It serializes re-auth attempts under authMu and applies a soft circuit-breaker
// with exponential backoff so a persistently failing account does not hammer the
// Internxt API on every operation. After 5 consecutive failures it returns a
// terminal error ("auth exceeded max retries") that the Android Session Guardian
// surfaces as a "manual re-auth required" notification.
func (f *Fs) reAuthorize(ctx context.Context) error {
	f.authMu.Lock()
	defer f.authMu.Unlock()

	// Respect the backoff window; callers receive the backoff as an error so the
	// operation fails fast instead of retrying a known-bad login.
	if !time.Now().After(f.nextAuthAllowed) {
		return fmt.Errorf("re-authorization blocked until %v (attempt %d/5)", f.nextAuthAllowed, f.authFailCount)
	}

	// Terminal state: too many consecutive failures, give up until manual re-auth.
	if f.authFailCount >= 5 {
		return errors.New("auth exceeded max retries: manual re-auth required")
	}

	err := f.reAuthorizeLocked(ctx)
	if err != nil {
		// Increment failure count and schedule the next allowed attempt.
		f.authFailCount++
		backoff := getBackoffDuration(f.authFailCount)
		f.nextAuthAllowed = time.Now().Add(backoff)
		fs.Debugf(f, "Re-authorization failed (attempt %d/5), backing off %v until %v", f.authFailCount, backoff, f.nextAuthAllowed)

		if f.authFailCount >= 5 {
			return errors.New("auth exceeded max retries: manual re-auth required")
		}
		return err
	}

	// Success - reset the circuit breaker.
	f.authFailCount = 0
	f.nextAuthAllowed = time.Time{}
	fs.Debugf(f, "Re-authorization succeeded, failure count reset to 0")
	return nil
}
