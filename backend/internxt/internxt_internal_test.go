package internxt

import (
	"context"
	"testing"
	"time"

	config "github.com/internxt/rclone-adapter/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/lib/oauthutil"
	"golang.org/x/oauth2"
)

func TestInitTokenRenewerAndShutdown(t *testing.T) {
	t.Parallel()

	m := configmap.Simple{}
	err := oauthutil.PutToken("internxt-test", m, &oauth2.Token{
		AccessToken: "token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}, true)
	if err != nil {
		t.Fatalf("failed to set token in config map: %v", err)
	}

	f := &Fs{
		name: "internxt-test",
		m:    m,
		cfg:  config.NewDefaultToken("token"),
	}

	err = f.initTokenRenewer(context.Background())
	if err != nil {
		t.Fatalf("initTokenRenewer returned error: %v", err)
	}
	if f.tokenSource == nil {
		t.Fatal("expected token source to be initialized")
	}
	if f.tokenRenewer == nil {
		t.Fatal("expected token renewer to be initialized")
	}

	if err := f.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown returned error: %v", err)
	}
	if err := f.Shutdown(context.Background()); err != nil {
		t.Fatalf("second shutdown returned error: %v", err)
	}
}

func TestRenewTokenUsesAuthCircuitBreaker(t *testing.T) {
	t.Parallel()

	f := &Fs{authFailed: true}
	err := f.renewToken(context.Background())
	if err == nil {
		t.Fatal("expected renewToken to return an error when auth has permanently failed")
	}
}
