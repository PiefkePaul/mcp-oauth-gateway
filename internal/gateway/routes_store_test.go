package gateway

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

func TestUpsertRoutePersistsToFile(t *testing.T) {
	routesPath := filepath.Join(t.TempDir(), "routes.yaml")
	if err := os.WriteFile(routesPath, []byte("routes: []\n"), 0o644); err != nil {
		t.Fatalf("write routes file: %v", err)
	}

	server := newMutableTestServer(t, routesPath)

	err := server.upsertRoute("", config.Route{
		ID:              "camoufox",
		DisplayName:     "Camoufox",
		PathPrefix:      "/camoufox",
		Upstream:        "http://camoufox-mcp:3000",
		UpstreamMCPPath: "/mcp",
	})
	if err != nil {
		t.Fatalf("upsert route: %v", err)
	}

	routes, err := config.LoadRoutesFile(routesPath)
	if err != nil {
		t.Fatalf("reload routes file: %v", err)
	}
	if len(routes) != 1 || routes[0].ID != "camoufox" {
		t.Fatalf("expected persisted route, got %#v", routes)
	}
}

func TestDeleteRoutePersistsToFile(t *testing.T) {
	routesPath := filepath.Join(t.TempDir(), "routes.yaml")
	if err := os.WriteFile(routesPath, []byte(`
routes:
  - id: n8n
    display_name: n8n MCP
    path_prefix: /n8n
    upstream: http://n8n-mcp:8080
    upstream_mcp_path: /mcp
`), 0o644); err != nil {
		t.Fatalf("write routes file: %v", err)
	}

	routes, err := config.LoadRoutesFile(routesPath)
	if err != nil {
		t.Fatalf("load routes: %v", err)
	}

	server := newMutableTestServerWithRoutes(t, routesPath, routes)
	if err := server.deleteRoute("n8n"); err != nil {
		t.Fatalf("delete route: %v", err)
	}

	persisted, err := config.LoadRoutesFile(routesPath)
	if err != nil {
		t.Fatalf("reload routes: %v", err)
	}
	if len(persisted) != 0 {
		t.Fatalf("expected empty routes file, got %#v", persisted)
	}
}

func newMutableTestServer(t *testing.T, routesPath string) *Server {
	t.Helper()
	return newMutableTestServerWithRoutes(t, routesPath, []config.Route{})
}

func newMutableTestServerWithRoutes(t *testing.T, routesPath string, routes []config.Route) *Server {
	t.Helper()

	manager, err := auth.NewManager(auth.Config{
		StorePath:            filepath.Join(t.TempDir(), "auth-store.enc"),
		MasterKey:            []byte("0123456789abcdef0123456789abcdef"),
		AccessTokenTTL:       time.Hour,
		RefreshTokenTTL:      24 * time.Hour,
		AuthorizationCodeTTL: 10 * time.Minute,
		SessionTTL:           24 * time.Hour,
		PublicBaseURL:        "https://mcp.example.com",
		PortalTitle:          "MCP Gateway",
	})
	if err != nil {
		t.Fatalf("create auth manager: %v", err)
	}

	server, err := New(&config.Config{
		PublicBaseURL: "https://mcp.example.com",
		RoutesPath:    routesPath,
		Routes:        routes,
	}, manager)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	return server
}
