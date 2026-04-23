package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

func TestProtectedResourceMetadata(t *testing.T) {
	handler := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/.well-known/oauth-protected-resource/n8n/mcp", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	if got, want := payload["resource"], "https://mcp.example.com/n8n/mcp"; got != want {
		t.Fatalf("expected resource %q, got %#v", want, got)
	}
}

func TestGatewayProtectedResourceMetadata(t *testing.T) {
	handler := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if got, want := payload["resource"], "https://mcp.example.com"; got != want {
		t.Fatalf("expected gateway resource %q, got %#v", want, got)
	}
}

func TestPathInsertedAuthorizationMetadata(t *testing.T) {
	handler := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/.well-known/oauth-authorization-server/n8n/mcp", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if got, want := payload["issuer"], "https://mcp.example.com"; got != want {
		t.Fatalf("expected issuer %q, got %#v", want, got)
	}
}

func TestProxyChallengesWithoutBearerToken(t *testing.T) {
	handler := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/n8n/mcp", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	challenge := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/n8n/mcp"`) {
		t.Fatalf("expected metadata challenge, got %q", challenge)
	}
}

func TestProxySetsConfiguredUpstreamBearer(t *testing.T) {
	seenAuthorization := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuthorization <- r.Header.Get("Authorization")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))
	defer upstream.Close()

	route := config.Route{
		ID:              "n8n",
		DisplayName:     "n8n MCP",
		PathPrefix:      "/n8n",
		Upstream:        upstream.URL,
		UpstreamMCPPath: "/mcp",
	}
	if err := config.NormalizeRoute(&route); err != nil {
		t.Fatalf("normalize route: %v", err)
	}
	handler := newTestServerWithRoutes(t, []config.Route{route})
	user, err := handler.authManager.CreateUser("user@example.com", "super-secret-password", false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	gatewayToken, _, err := handler.authManager.CreatePersonalAccessToken(user.ID, "test", time.Hour)
	if err != nil {
		t.Fatalf("create gateway token: %v", err)
	}
	if err := handler.authManager.SetRouteUpstreamBearer("n8n", "n8n-internal-token"); err != nil {
		t.Fatalf("set upstream bearer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/n8n/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+gatewayToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := <-seenAuthorization; got != "Bearer n8n-internal-token" {
		t.Fatalf("expected upstream bearer, got %q", got)
	}
}

func TestProxyPrefersUserSpecificUpstreamBearer(t *testing.T) {
	seenAuthorization := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuthorization <- r.Header.Get("Authorization")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))
	defer upstream.Close()

	route := config.Route{
		ID:              "n8n",
		DisplayName:     "n8n MCP",
		PathPrefix:      "/n8n",
		Upstream:        upstream.URL,
		UpstreamMCPPath: "/mcp",
	}
	if err := config.NormalizeRoute(&route); err != nil {
		t.Fatalf("normalize route: %v", err)
	}
	handler := newTestServerWithRoutes(t, []config.Route{route})
	user, err := handler.authManager.CreateUser("user@example.com", "super-secret-password", false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	gatewayToken, _, err := handler.authManager.CreatePersonalAccessToken(user.ID, "test", time.Hour)
	if err != nil {
		t.Fatalf("create gateway token: %v", err)
	}
	if err := handler.authManager.SetRouteUpstreamBearer("n8n", "global-token"); err != nil {
		t.Fatalf("set global bearer: %v", err)
	}
	if err := handler.authManager.SetRouteUserUpstreamBearer("n8n", user.ID, "user-token"); err != nil {
		t.Fatalf("set user bearer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/n8n/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+gatewayToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := <-seenAuthorization; got != "Bearer user-token" {
		t.Fatalf("expected user-specific upstream bearer, got %q", got)
	}
}

func TestRouteInfo(t *testing.T) {
	handler := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/n8n", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if got, want := payload["mcp_url"], "https://mcp.example.com/n8n/mcp"; got != want {
		t.Fatalf("expected mcp_url %q, got %#v", want, got)
	}
}

func TestPublicDashboardHidesPrivateRoutes(t *testing.T) {
	routes, err := config.ParseRoutesPayload([]byte(`
routes:
  - id: legal
    display_name: Legal MCP
    path_prefix: /legal
    upstream: http://legal-mcp:8000
    upstream_mcp_path: /mcp
  - id: secret
    display_name: Secret MCP
    path_prefix: /secret
    upstream: http://secret-mcp:8000
    upstream_mcp_path: /mcp
    access:
      visibility: private
      mode: restricted
`))
	if err != nil {
		t.Fatalf("parse routes: %v", err)
	}
	handler := newTestServerWithRoutes(t, routes)

	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Legal MCP") {
		t.Fatalf("expected public route in dashboard")
	}
	if strings.Contains(body, "Secret MCP") {
		t.Fatalf("did not expect private route in dashboard")
	}
}

func TestAdminDashboardTemplateRenders(t *testing.T) {
	handler := newTestServer(t)
	group, err := handler.authManager.CreateGroup("Legal Team")
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	user, err := handler.authManager.CreateUser("user@example.com", "another-secret-password", false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := handler.authManager.SetUserGroups(user.ID, []string{group.ID}); err != nil {
		t.Fatalf("set user groups: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/admin", nil)
	rec := httptest.NewRecorder()

	handler.renderAdminDashboard(rec, req, &auth.Identity{
		UserID:  "admin",
		Email:   "admin@example.com",
		IsAdmin: true,
	}, newEmptyRouteFormData(), "", "", http.StatusOK)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Import / Export") {
		t.Fatalf("expected import/export section to render")
	}
}

func TestParseDeploymentFormAppliesN8NDefaults(t *testing.T) {
	handler := newTestServer(t)
	form := url.Values{}
	form.Set("transport", "http")
	form.Set("id", "n8n")
	form.Set("display_name", "n8n MCP")
	form.Set("path_prefix", "/n8n")
	form.Set("image", "ghcr.io/czlonkowski/n8n-mcp:latest")
	form.Set("container_name", "n8n-mcp")
	form.Set("internal_port", "8080")
	form.Set("upstream_mcp_path", "/mcp")
	form.Set("scopes_supported", "mcp")
	form.Set("environment", "AUTH_TOKEN=secret")

	req := httptest.NewRequest(http.MethodPost, "/admin/deployments", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	formData, route, spec, err := handler.parseDeploymentForm(req)
	if err != nil {
		t.Fatalf("parse deployment form: %v", err)
	}
	if got, want := route.Upstream, "http://n8n-mcp:3000"; got != want {
		t.Fatalf("expected n8n upstream %q, got %q", want, got)
	}
	if spec == nil || spec.InternalPort != 3000 {
		t.Fatalf("expected internal port 3000, got %#v", spec)
	}
	if got := spec.Env["PORT"]; got != "3000" {
		t.Fatalf("expected PORT=3000, got %q", got)
	}
	if got := spec.Env["MCP_MODE"]; got != "http" {
		t.Fatalf("expected MCP_MODE=http, got %q", got)
	}
	if !strings.Contains(formData.Notes, "Port 3000") {
		t.Fatalf("expected n8n notes to mention port 3000, got %q", formData.Notes)
	}
}

func TestRouteAccessPolicy(t *testing.T) {
	route := config.Route{
		ID:          "legal",
		DisplayName: "Legal",
		Access: config.RouteAccess{
			Mode:          "restricted",
			AllowedGroups: []string{"Legal Team"},
			DeniedUsers:   []string{"blocked@example.com"},
		},
	}

	if !routeAccessAllowed(route, &auth.Identity{Email: "user@example.com", GroupNames: []string{"Legal Team"}}) {
		t.Fatalf("expected legal team member to be allowed")
	}
	if routeAccessAllowed(route, &auth.Identity{Email: "blocked@example.com", GroupNames: []string{"Legal Team"}}) {
		t.Fatalf("expected denied user to be rejected")
	}
	if routeAccessAllowed(route, &auth.Identity{Email: "blocked@example.com", IsAdmin: true}) {
		t.Fatalf("expected explicit deny to reject admins too")
	}
	if !routeAccessAllowed(route, &auth.Identity{Email: "admin@example.com", IsAdmin: true}) {
		t.Fatalf("expected non-denied admin to bypass route restrictions")
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()

	return newTestServerWithRoutes(t, []config.Route{
		{
			ID:                     "n8n",
			DisplayName:            "n8n MCP",
			PathPrefix:             "/n8n",
			Upstream:               "http://n8n-mcp:8080",
			UpstreamMCPPath:        "/mcp",
			NormalizedPathPrefix:   "/n8n",
			NormalizedUpstreamPath: "/mcp",
		},
	})
}

func newTestServerWithRoutes(t *testing.T, routes []config.Route) *Server {
	t.Helper()

	cfg := &config.Config{
		PublicBaseURL: "https://mcp.example.com",
		Routes:        routes,
	}

	manager, err := auth.NewManager(auth.Config{
		StorePath:            filepath.Join(t.TempDir(), "auth-store.enc"),
		MasterKey:            []byte("0123456789abcdef0123456789abcdef"),
		AccessTokenTTL:       time.Hour,
		RefreshTokenTTL:      24 * time.Hour,
		AuthorizationCodeTTL: 10 * time.Minute,
		SessionTTL:           24 * time.Hour,
		PublicBaseURL:        cfg.PublicBaseURL,
		PortalTitle:          "MCP Gateway",
	})
	if err != nil {
		t.Fatalf("create auth manager: %v", err)
	}

	handler, err := New(cfg, manager)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	return handler
}
