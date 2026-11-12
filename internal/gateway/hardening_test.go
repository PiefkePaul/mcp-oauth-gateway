package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

const testForwardSecret = "Bearer static-api-key"

func routesFileContent(t *testing.T, server *Server) string {
	t.Helper()
	payload, err := os.ReadFile(server.cfg.RoutesPath)
	if err != nil {
		t.Fatalf("read routes file: %v", err)
	}
	return string(payload)
}

func TestForwardHeaderCredentialsLeaveTheRoutesFile(t *testing.T) {
	sawUserHeader := false
	backend := httptest.NewServer(apiKeyUpstream(t, &sawUserHeader))
	t.Cleanup(backend.Close)
	server := newAdminSaveTestServer(t, nil)

	route := config.Route{
		ID:              "terminal",
		DisplayName:     "Terminal",
		PathPrefix:      "/terminal",
		Upstream:        backend.URL,
		UpstreamMCPPath: "/mcp",
		ForwardHeaders: map[string]string{
			"Authorization": testForwardSecret,
			"X-User":        "{email}",
		},
	}
	if err := server.upsertRoute("", route); err != nil {
		t.Fatalf("save route: %v", err)
	}

	if content := routesFileContent(t, server); strings.Contains(content, "static-api-key") || !strings.Contains(content, config.ForwardHeaderSecretMarker) {
		t.Fatalf("the routes file must hold the marker instead of the credential:\n%s", content)
	}
	saved, _ := server.routeByID("terminal")
	if saved.ForwardHeaders["Authorization"] != config.ForwardHeaderSecretMarker {
		t.Fatalf("the route in memory must hold the marker, got %q", saved.ForwardHeaders["Authorization"])
	}
	if saved.ForwardHeaders["X-User"] != "{email}" {
		t.Fatalf("non-credential headers must stay as they are, got %q", saved.ForwardHeaders["X-User"])
	}
	// The upstream still receives the real credential.
	if result := server.checkRoute(context.Background(), "terminal"); result.Status != healthStatusOK {
		t.Fatalf("the stored credential must reach the upstream, got %+v", result)
	}

	// Saving the route again with the marker, as the admin form does, and
	// under a new ID keeps the credential.
	saved.ID = "terminal-2"
	if err := server.upsertRoute("terminal", saved); err != nil {
		t.Fatalf("rename route: %v", err)
	}
	if err := server.authManager.RenameRouteSecrets("terminal", "terminal-2"); err != nil {
		t.Fatalf("rename secrets: %v", err)
	}
	if result := server.checkRoute(context.Background(), "terminal-2"); result.Status != healthStatusOK {
		t.Fatalf("the credential must survive a rename, got %+v", result)
	}

	// Removing the header drops the stored credential.
	renamed, _ := server.routeByID("terminal-2")
	delete(renamed.ForwardHeaders, "Authorization")
	if err := server.upsertRoute("terminal-2", renamed); err != nil {
		t.Fatalf("remove header: %v", err)
	}
	if _, ok := server.authManager.RouteForwardHeaderSecret("terminal-2", "Authorization"); ok {
		t.Fatalf("the stored credential must be dropped with its header")
	}
}

func TestForwardHeaderCredentialsAreMigratedAtStartup(t *testing.T) {
	sawUserHeader := false
	backend := httptest.NewServer(apiKeyUpstream(t, &sawUserHeader))
	t.Cleanup(backend.Close)
	server := newAdminSaveTestServer(t, []config.Route{{
		ID:              "terminal",
		DisplayName:     "Terminal",
		PathPrefix:      "/terminal",
		Upstream:        backend.URL,
		UpstreamMCPPath: "/mcp",
		ForwardHeaders:  map[string]string{"Authorization": testForwardSecret},
	}})

	server.sealStoredForwardHeaders()

	if content := routesFileContent(t, server); strings.Contains(content, "static-api-key") {
		t.Fatalf("startup must move the credential out of the routes file:\n%s", content)
	}
	if result := server.checkRoute(context.Background(), "terminal"); result.Status != healthStatusOK {
		t.Fatalf("the migrated credential must reach the upstream, got %+v", result)
	}

	// The admin export does not contain it either.
	cookies := adminTestSession(t, server)
	req := httptest.NewRequest(http.MethodGet, "/admin/routes/export", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "static-api-key") {
		t.Fatalf("the export must not contain the credential: %d %s", rec.Code, rec.Body.String())
	}
}

func TestStdioChildrenDoNotInheritGatewaySettings(t *testing.T) {
	env := stdioChildBaseEnv([]string{
		"PATH=/usr/bin",
		"MCP_GATEWAY_AUTH_MASTER_KEY=secret",
		"MCP_GATEWAY_BOOTSTRAP_PASSWORD=secret",
		"HOME=/root",
	})
	if strings.Join(env, ",") != "PATH=/usr/bin,HOME=/root" {
		t.Fatalf("gateway settings must be removed from the child environment, got %v", env)
	}
}

func TestPublicCatalogHidesUpstreamAddresses(t *testing.T) {
	server := newAdminSaveTestServer(t, []config.Route{{
		ID:              "tools",
		DisplayName:     "Tools",
		PathPrefix:      "/tools",
		Upstream:        "http://internal-host:3000",
		UpstreamMCPPath: "/mcp",
	}})

	for _, target := range []string{"/?format=json", "/tools", "/healthz"} {
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: unexpected status %d", target, rec.Code)
		}
		if body := rec.Body.String(); strings.Contains(body, "internal-host") || strings.Contains(body, "docker_management") {
			t.Fatalf("%s must not reveal internal details to anonymous callers: %s", target, body)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/?format=json", nil)
	for _, cookie := range adminTestSession(t, server) {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	var payload struct {
		Routes []map[string]any `json:"routes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil || len(payload.Routes) != 1 {
		t.Fatalf("decode catalog: %v %s", err, rec.Body.String())
	}
	if payload.Routes[0]["upstream"] != "http://internal-host:3000" {
		t.Fatalf("admins must still see the upstream, got %v", payload.Routes[0]["upstream"])
	}
}

func TestAccountEndpointsLimitRequestBodies(t *testing.T) {
	server := newAdminSaveTestServer(t, nil)
	body := "client_name=" + strings.Repeat("a", maxAccountRequestBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an oversized form must be rejected, got %d", rec.Code)
	}
}

func TestSecurityHeadersAreSet(t *testing.T) {
	server := newAdminSaveTestServer(t, nil)
	handler := securityHeadersMiddleware("https://mcp.example.com", server)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	for header, want := range map[string]string{
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Strict-Transport-Security": "max-age=31536000",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestLoginRedirectStaysOnTheGateway(t *testing.T) {
	server := newAdminSaveTestServer(t, nil)
	adminTestSession(t, server) // creates the admin account
	form := url.Values{"email": {"admin@example.com"}, "password": {"super-secret-password"}, "csrf_token": {"csrf"}, "next": {"//evil.example/x"}}
	req := httptest.NewRequest(http.MethodPost, "/account/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "mcp_gateway_csrf", Value: "csrf"})
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	if location := rec.Header().Get("Location"); location != "/account" {
		t.Fatalf("login must not redirect to another host, got %q", location)
	}
}
