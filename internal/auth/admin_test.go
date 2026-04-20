package auth

import (
	"path/filepath"
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
