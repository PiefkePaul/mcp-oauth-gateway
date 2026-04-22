package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBootstrapUserIsAdmin(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")

	users := manager.ListUsers()
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if !users[0].IsAdmin {
		t.Fatalf("expected bootstrap user to be admin")
	}
}

func TestCannotDeleteLastAdmin(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")

	adminID := manager.ListUsers()[0].ID
	if err := manager.DeleteUser(adminID); err == nil {
		t.Fatalf("expected deleting last admin to fail")
	}
}

func TestCreateAndPromoteUser(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")

	user, err := manager.CreateUser("user@example.com", "another-secret-password", false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if user.IsAdmin {
		t.Fatalf("expected new user to be non-admin")
	}

	if err := manager.SetUserAdmin(user.ID, true); err != nil {
		t.Fatalf("promote user: %v", err)
	}

	users := manager.ListUsers()
	foundAdmin := false
	for _, listed := range users {
		if listed.ID == user.ID && listed.IsAdmin {
			foundAdmin = true
		}
	}
	if !foundAdmin {
		t.Fatalf("expected promoted user to be admin")
	}
}

func TestGroupsAndUserMembership(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")

	group, err := manager.CreateGroup("Legal Team")
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	user, err := manager.CreateUser("user@example.com", "another-secret-password", false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := manager.SetUserGroups(user.ID, []string{group.ID}); err != nil {
		t.Fatalf("set user groups: %v", err)
	}

	users := manager.ListUsers()
	found := false
	for _, listed := range users {
		if listed.ID == user.ID {
			found = true
			if len(listed.GroupNames) != 1 || listed.GroupNames[0] != "Legal Team" {
				t.Fatalf("expected user group membership, got %#v", listed.GroupNames)
			}
		}
	}
	if !found {
		t.Fatalf("expected user to be listed")
	}
}

func TestChangeUserPasswordRequiresCurrentPassword(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	admin := manager.ListUsers()[0]

	if err := manager.changeUserPassword(admin.ID, "wrong-password", "fresh-secret-password"); err == nil {
		t.Fatalf("expected wrong current password to fail")
	}
	if err := manager.changeUserPassword(admin.ID, "super-secret-password", "fresh-secret-password"); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if _, err := manager.authenticateUser("admin@example.com", "super-secret-password"); err == nil {
		t.Fatalf("expected old password to fail")
	}
	if _, err := manager.authenticateUser("admin@example.com", "fresh-secret-password"); err != nil {
		t.Fatalf("expected new password to authenticate: %v", err)
	}
}

func TestUserDevicesCanBeListedAndRevoked(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	admin := manager.ListUsers()[0]
	client, err := manager.registerClient(
		"Open WebUI",
		[]string{"https://openwebui.example.com/oauth/clients/mcp/callback"},
		nil,
		nil,
		"client_secret_post",
	)
	if err != nil {
		t.Fatalf("register client: %v", err)
	}

	manager.mu.Lock()
	tokenSet := manager.issueTokenSetLocked(time.Now(), admin.ID, client.ID, "mcp", "https://mcp.example.com/camoufox/mcp")
	if err := manager.saveLocked(); err != nil {
		t.Fatalf("save token set: %v", err)
	}
	manager.mu.Unlock()

	devices := manager.ListUserDevices(admin.ID)
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %#v", devices)
	}
	if devices[0].ClientName != "Open WebUI" {
		t.Fatalf("expected client name, got %#v", devices[0])
	}

	if err := manager.RevokeUserDevice(admin.ID, devices[0].ID); err != nil {
		t.Fatalf("revoke device: %v", err)
	}
	if _, err := manager.ValidateAccessToken(tokenSet.AccessToken, "https://mcp.example.com/camoufox/mcp"); err == nil {
		t.Fatalf("expected access token to be revoked")
	}
	if got := manager.ListUserDevices(admin.ID); len(got) != 0 {
		t.Fatalf("expected devices to be revoked, got %#v", got)
	}
}

func TestRouteEnvSecretsAreEncryptedAndResolvable(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	secret := " feedfacecafebeef "

	if err := manager.SetRouteEnvSecrets("anna", map[string]string{
		"ANNAS_SECRET_KEY": secret,
	}); err != nil {
		t.Fatalf("set route secrets: %v", err)
	}

	rawStore, err := os.ReadFile(manager.cfg.StorePath)
	if err != nil {
		t.Fatalf("read auth store: %v", err)
	}
	if strings.Contains(string(rawStore), secret) || strings.Contains(string(rawStore), "ANNAS_SECRET_KEY") {
		t.Fatalf("expected route env secrets to be stored only in encrypted payload")
	}

	resolved, err := manager.ResolveRouteEnvSecretRefs("anna", map[string]string{
		"ANNAS_SECRET_KEY": RouteEnvSecretRef("anna", "ANNAS_SECRET_KEY"),
	})
	if err != nil {
		t.Fatalf("resolve route secrets: %v", err)
	}
	if got := resolved["ANNAS_SECRET_KEY"]; got != secret {
		t.Fatalf("expected secret %q, got %q", secret, got)
	}

	if err := manager.DeleteRouteSecrets("anna"); err != nil {
		t.Fatalf("delete route secrets: %v", err)
	}
	if _, err := manager.ResolveRouteEnvSecretRefs("anna", map[string]string{
		"ANNAS_SECRET_KEY": RouteEnvSecretRef("anna", "ANNAS_SECRET_KEY"),
	}); err == nil {
		t.Fatalf("expected deleted route secret to be missing")
	}
}

func newTestManager(t *testing.T, bootstrapEmail, bootstrapPassword string) *Manager {
	t.Helper()

	manager, err := NewManager(Config{
		StorePath:            filepath.Join(t.TempDir(), "auth-store.enc"),
		MasterKey:            []byte("0123456789abcdef0123456789abcdef"),
		AccessTokenTTL:       time.Hour,
		RefreshTokenTTL:      24 * time.Hour,
		AuthorizationCodeTTL: 10 * time.Minute,
		SessionTTL:           24 * time.Hour,
		PublicBaseURL:        "https://mcp.example.com",
		PortalTitle:          "MCP Gateway",
		BootstrapEmail:       bootstrapEmail,
		BootstrapPassword:    bootstrapPassword,
	})
	if err != nil {
		t.Fatalf("create auth manager: %v", err)
	}

	return manager
}
