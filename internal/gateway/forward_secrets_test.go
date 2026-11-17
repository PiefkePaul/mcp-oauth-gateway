package gateway

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

func TestFailedRouteSaveKeepsStoredForwardHeaderCredentials(t *testing.T) {
	sawUserHeader := false
	backendServer := httptest.NewServer(apiKeyUpstream(t, &sawUserHeader))
	t.Cleanup(backendServer.Close)
	backend := backendServer.URL
	server := newAdminSaveTestServer(t, nil)
	route := config.Route{
		ID:              "terminal",
		DisplayName:     "Terminal",
		PathPrefix:      "/terminal",
		Upstream:        backend,
		UpstreamMCPPath: "/mcp",
		ForwardHeaders: map[string]string{
			"Authorization": testForwardSecret,
			"X-Api-Key":     "first-key",
		},
	}
	if err := server.upsertRoute("", route); err != nil {
		t.Fatalf("save route: %v", err)
	}

	// Make writing the routes file fail: its parent is a regular file.
	goodPath := server.cfg.RoutesPath
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	server.cfg.RoutesPath = filepath.Join(blocker, "routes.yaml")

	edited, _ := server.routeByID("terminal")
	edited.ForwardHeaders = copyHeaders(edited.ForwardHeaders) // routeByID shares the map
	delete(edited.ForwardHeaders, "Authorization")
	edited.ForwardHeaders["X-Api-Key"] = "second-key"
	edited.ForwardHeaders["X-New-Token"] = "new-token"
	if err := server.upsertRoute("terminal", edited); err == nil {
		t.Fatalf("expected the save to fail")
	}

	// The old route is still active and must still have what it needs.
	if value, ok := server.authManager.RouteForwardHeaderSecret("terminal", "Authorization"); !ok || value != testForwardSecret {
		t.Fatalf("a failed save must not drop the credential of a removed header, got %q %t", value, ok)
	}
	if value, _ := server.authManager.RouteForwardHeaderSecret("terminal", "X-Api-Key"); value != "first-key" {
		t.Fatalf("a failed save must restore the replaced credential, got %q", value)
	}
	if _, ok := server.authManager.RouteForwardHeaderSecret("terminal", "X-New-Token"); ok {
		t.Fatalf("a failed save must not leave the credential of a header that was never saved")
	}
	if active, _ := server.routeByID("terminal"); active.ForwardHeaders["Authorization"] != config.ForwardHeaderSecretMarker {
		t.Fatalf("the old route must stay active, got %v", active.ForwardHeaders)
	}
	if result := server.checkRoute(context.Background(), "terminal"); result.Status != healthStatusOK {
		t.Fatalf("the old route must keep reaching its upstream, got %+v", result)
	}

	// Once the save succeeds, the removed header's value goes and the new
	// values are in place.
	server.cfg.RoutesPath = goodPath
	if err := server.upsertRoute("terminal", edited); err != nil {
		t.Fatalf("save route again: %v", err)
	}
	if _, ok := server.authManager.RouteForwardHeaderSecret("terminal", "Authorization"); ok {
		t.Fatalf("a successful save must drop the credential of a removed header")
	}
	if value, _ := server.authManager.RouteForwardHeaderSecret("terminal", "X-Api-Key"); value != "second-key" {
		t.Fatalf("expected the new credential, got %q", value)
	}
	if value, _ := server.authManager.RouteForwardHeaderSecret("terminal", "X-New-Token"); value != "new-token" {
		t.Fatalf("expected the added credential, got %q", value)
	}
}

func TestRespelledForwardHeaderKeepsItsCredential(t *testing.T) {
	server := newAdminSaveTestServer(t, nil)
	route := config.Route{
		ID:              "tools",
		DisplayName:     "Tools",
		PathPrefix:      "/tools",
		Upstream:        "http://tools:3000",
		UpstreamMCPPath: "/mcp",
		ForwardHeaders:  map[string]string{"X-Api-Key": "the-key"},
	}
	if err := server.upsertRoute("", route); err != nil {
		t.Fatalf("save route: %v", err)
	}

	// The admin form sends the marker back; only the spelling changed.
	saved, _ := server.routeByID("tools")
	saved.ForwardHeaders = copyHeaders(saved.ForwardHeaders)
	delete(saved.ForwardHeaders, "X-Api-Key")
	saved.ForwardHeaders["x-api-key"] = config.ForwardHeaderSecretMarker
	if err := server.upsertRoute("tools", saved); err != nil {
		t.Fatalf("respell header: %v", err)
	}

	if value, ok := server.authManager.RouteForwardHeaderSecret("tools", "x-api-key"); !ok || value != "the-key" {
		t.Fatalf("the credential must follow the respelled header, got %q %t", value, ok)
	}
	if _, ok := server.authManager.RouteForwardHeaderSecret("tools", "X-Api-Key"); ok {
		t.Fatalf("the old spelling must not stay in the store")
	}
	if got := server.forwardHeaderTemplate("tools", "x-api-key", config.ForwardHeaderSecretMarker); got != "the-key" {
		t.Fatalf("the respelled header must resolve to the credential, got %q", got)
	}
}

func TestForwardHeaderTemplateIgnoresHeaderNameCase(t *testing.T) {
	server := newAdminSaveTestServer(t, nil)
	if err := server.authManager.SyncRouteForwardHeaderSecrets("tools", map[string]string{"X-Api-Key": "the-key"}, nil); err != nil {
		t.Fatalf("store credential: %v", err)
	}
	// A routes file edited by hand, never saved through the gateway.
	for _, name := range []string{"X-Api-Key", "x-api-key", "X-API-KEY"} {
		if got := server.forwardHeaderTemplate("tools", name, config.ForwardHeaderSecretMarker); got != "the-key" {
			t.Errorf("%s: expected the stored credential, got %q", name, got)
		}
	}
	if got := server.forwardHeaderTemplate("tools", "X-Other", config.ForwardHeaderSecretMarker); got != "" {
		t.Errorf("an unknown header must resolve to nothing, got %q", got)
	}
	if got := server.forwardHeaderTemplate("tools", "X-User", "{email}"); got != "{email}" {
		t.Errorf("templates pass through, got %q", got)
	}
}

func copyHeaders(headers map[string]string) map[string]string {
	copied := make(map[string]string, len(headers))
	for name, value := range headers {
		copied[name] = value
	}
	return copied
}
