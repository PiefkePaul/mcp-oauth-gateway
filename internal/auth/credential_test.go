package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

const credentialTestResource = "https://mcp.example.com/legal/mcp"

type credentialTestLogin struct {
	manager  *Manager
	client   *clientRecord
	userID   string
	verifier string
	params   *authorizeParams
}

func newCredentialTestLogin(t *testing.T) *credentialTestLogin {
	t.Helper()
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	client, err := manager.registerClient(
		"Claude Code",
		[]string{"http://localhost:33418/callback"},
		[]string{"authorization_code", "refresh_token"},
		nil,
		"none",
	)
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	verifier := "abcdefghijklmnopqrstuvwxyz0123456789abcdef"
	sum := sha256.Sum256([]byte(verifier))
	return &credentialTestLogin{
		manager:  manager,
		client:   client,
		userID:   manager.ListUsers()[0].ID,
		verifier: verifier,
		params: &authorizeParams{
			ClientID:            client.ID,
			RedirectURI:         "http://localhost:33418/callback",
			Scope:               "mcp",
			Resource:            credentialTestResource,
			CodeChallenge:       base64.RawURLEncoding.EncodeToString(sum[:]),
			CodeChallengeMethod: "S256",
		},
	}
}

// login runs one full authorization-code flow, as a separate machine would.
func (l *credentialTestLogin) login(t *testing.T) *tokenResponse {
	t.Helper()
	code, err := l.manager.createAuthorizationCode(l.userID, l.params)
	if err != nil {
		t.Fatalf("create auth code: %v", err)
	}
	tokens, err := l.manager.exchangeAuthorizationCode(l.client.ID, "", "none", code, l.params.RedirectURI, l.verifier, credentialTestResource)
	if err != nil {
		t.Fatalf("exchange code: %v", err)
	}
	return tokens
}

func (l *credentialTestLogin) refresh(refreshToken string) (*tokenResponse, error) {
	return l.manager.refreshToken(l.client.ID, "", "none", refreshToken, credentialTestResource)
}

func (l *credentialTestLogin) identity(t *testing.T, accessToken string) *Identity {
	t.Helper()
	identity, err := l.manager.ValidateAccessToken(accessToken, credentialTestResource)
	if err != nil {
		t.Fatalf("validate access token: %v", err)
	}
	return identity
}

func TestOAuthIdentityCarriesGrantStableAcrossRefresh(t *testing.T) {
	login := newCredentialTestLogin(t)

	machineA := login.login(t)
	machineB := login.login(t)

	identityA := login.identity(t, machineA.AccessToken)
	identityB := login.identity(t, machineB.AccessToken)
	if identityA.CredentialKind != CredentialOAuth || identityA.ClientID != login.client.ID {
		t.Fatalf("unexpected OAuth identity: %+v", identityA)
	}
	if identityA.CredentialID == "" || identityA.OwnerKey() == identityB.OwnerKey() {
		t.Fatalf("separate logins must be separate agents: %q vs %q", identityA.OwnerKey(), identityB.OwnerKey())
	}
	if identityA.DeviceID != identityB.DeviceID {
		t.Fatalf("same user, client and resource should share the device ID")
	}

	refreshed, err := login.refresh(machineA.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := login.identity(t, refreshed.AccessToken).OwnerKey(); got != identityA.OwnerKey() {
		t.Fatalf("refresh must keep the agent: got %q, want %q", got, identityA.OwnerKey())
	}
}

func TestRefreshTokenReuseWithinGracePeriod(t *testing.T) {
	login := newCredentialTestLogin(t)
	login.manager.cfg.RefreshTokenReuseGrace = 2 * time.Minute
	tokens := login.login(t)
	owner := login.identity(t, tokens.AccessToken).OwnerKey()

	// Two terminals sharing one login refresh with the same token.
	first, err := login.refresh(tokens.RefreshToken)
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	second, err := login.refresh(tokens.RefreshToken)
	if err != nil {
		t.Fatalf("concurrent refresh within grace period: %v", err)
	}
	if first.RefreshToken == second.RefreshToken || first.AccessToken == second.AccessToken {
		t.Fatalf("each refresh must issue its own tokens")
	}
	for _, accessToken := range []string{first.AccessToken, second.AccessToken} {
		if got := login.identity(t, accessToken).OwnerKey(); got != owner {
			t.Fatalf("refresh within grace must stay in the same grant: got %q, want %q", got, owner)
		}
	}
	// Both successors keep working.
	if _, err := login.refresh(first.RefreshToken); err != nil {
		t.Fatalf("refresh successor one: %v", err)
	}
	if _, err := login.refresh(second.RefreshToken); err != nil {
		t.Fatalf("refresh successor two: %v", err)
	}

	// Once the grace period is over the rotated token is dead.
	login.manager.mu.Lock()
	login.manager.data.RefreshTokens[tokens.RefreshToken].RotatedAt = time.Now().Add(-3 * time.Minute).Unix()
	login.manager.mu.Unlock()
	if _, err := login.refresh(tokens.RefreshToken); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected invalid_grant after grace period, got %v", err)
	}
}

func TestRefreshTokenReuseRejectedWithoutGracePeriod(t *testing.T) {
	login := newCredentialTestLogin(t)
	tokens := login.login(t)

	if _, err := login.refresh(tokens.RefreshToken); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, err := login.refresh(tokens.RefreshToken); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected invalid_grant on reuse without grace period, got %v", err)
	}
}

func TestRotatedRefreshTokensDoNotShowAsExtraDevices(t *testing.T) {
	login := newCredentialTestLogin(t)
	login.manager.cfg.RefreshTokenReuseGrace = 2 * time.Minute
	tokens := login.login(t)
	if _, err := login.refresh(tokens.RefreshToken); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	devices := login.manager.ListUserDevices(login.userID)
	if len(devices) != 1 || devices[0].TokenCount != 1 {
		t.Fatalf("expected one device with one live token, got %+v", devices)
	}
}

func TestLegacyOAuthTokenUsesStableDeviceCredential(t *testing.T) {
	login := newCredentialTestLogin(t)
	login.manager.mu.Lock()
	legacy := login.manager.issueTokenSetLocked(time.Now(), login.userID, login.client.ID, "", "mcp", credentialTestResource)
	login.manager.mu.Unlock()

	identity := login.identity(t, legacy.AccessToken)
	if identity.CredentialID != "device:"+identity.DeviceID {
		t.Fatalf("legacy token should fall back to the device, got %q", identity.CredentialID)
	}
	refreshed, err := login.refresh(legacy.RefreshToken)
	if err != nil {
		t.Fatalf("refresh legacy token: %v", err)
	}
	if got := login.identity(t, refreshed.AccessToken).OwnerKey(); got != identity.OwnerKey() {
		t.Fatalf("legacy refresh must keep the agent: got %q, want %q", got, identity.OwnerKey())
	}
}

func TestPersonalTokenIdentityIsItsOwnAgent(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	userID := manager.ListUsers()[0].ID
	tokenA, recordA, err := manager.CreatePersonalAccessToken(userID, "Open WebUI", 0)
	if err != nil {
		t.Fatalf("create token A: %v", err)
	}
	tokenB, _, err := manager.CreatePersonalAccessToken(userID, "Script", 0)
	if err != nil {
		t.Fatalf("create token B: %v", err)
	}

	identityA, err := manager.ValidateAccessToken(tokenA, credentialTestResource)
	if err != nil {
		t.Fatalf("validate token A: %v", err)
	}
	identityB, err := manager.ValidateAccessToken(tokenB, credentialTestResource)
	if err != nil {
		t.Fatalf("validate token B: %v", err)
	}
	if identityA.CredentialKind != CredentialPersonalToken || identityA.CredentialID != recordA.ID {
		t.Fatalf("unexpected personal token identity: %+v", identityA)
	}
	if identityA.OwnerKey() == identityB.OwnerKey() {
		t.Fatalf("different personal tokens must be different agents")
	}
}

func TestOwnerKeyWithoutCredentialFallsBackToUser(t *testing.T) {
	if got := (&Identity{UserID: "u1"}).OwnerKey(); got != "user:u1" {
		t.Fatalf("unexpected owner key %q", got)
	}
	if got := (*Identity)(nil).OwnerKey(); got != "" {
		t.Fatalf("nil identity must have an empty owner key, got %q", got)
	}
}
