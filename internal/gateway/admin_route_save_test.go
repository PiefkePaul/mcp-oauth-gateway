package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

const adminTestCSRF = "admin-test-csrf-token"

// adminTestSession logs in an admin through the account portal and returns
// the cookies an admin form post needs.
func adminTestSession(t *testing.T, server *Server) []*http.Cookie {
	t.Helper()
	if _, err := server.authManager.CreateUser("admin@example.com", "super-secret-password", true); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	form := url.Values{"email": {"admin@example.com"}, "password": {"super-secret-password"}, "csrf_token": {adminTestCSRF}}
	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/account/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "mcp_gateway_csrf", Value: adminTestCSRF})
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("admin login: %d %s", rec.Code, rec.Body.String())
	}
	cookies := append(rec.Result().Cookies(), &http.Cookie{Name: "mcp_gateway_csrf", Value: adminTestCSRF})
	return cookies
}

func postAdminRouteSave(t *testing.T, server *Server, cookies []*http.Cookie, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	form.Set("csrf_token", adminTestCSRF)
	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/admin/routes/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	return rec
}

func newAdminSaveTestServer(t *testing.T, routes []config.Route) *Server {
	t.Helper()
	for i := range routes {
		if err := config.NormalizeRoute(&routes[i]); err != nil {
			t.Fatalf("normalize route: %v", err)
		}
	}
	server := newTestServerWithRoutes(t, routes)
	server.cfg.RoutesPath = filepath.Join(t.TempDir(), "routes.yaml")
	return server
}

func TestAdminRouteSaveKeepsInstallerSecretRefs(t *testing.T) {
	server := newAdminSaveTestServer(t, []config.Route{{
		ID:          "portainer",
		DisplayName: "Portainer",
		Transport:   "stdio",
		PathPrefix:  "/portainer",
		Stdio: &config.RouteStdio{
			Command:       "/data/stdio-mcp/portainer/bin/portainer-mcp",
			Args:          []string{"-server", "https://portainer:9443"},
			EnvSecretRefs: map[string]string{"PORTAINER_TOKEN": "PORTAINER_TOKEN"},
		},
	}})
	cookies := adminTestSession(t, server)

	rec := postAdminRouteSave(t, server, cookies, url.Values{
		"original_id":   {"portainer"},
		"id":            {"portainer"},
		"display_name":  {"Portainer (edited)"},
		"transport":     {"stdio"},
		"path_prefix":   {"/portainer"},
		"stdio_command": {"/data/stdio-mcp/portainer/bin/portainer-mcp"},
		"stdio_args":    {"-server\nhttps://portainer:9443"},
		"notes":         {"edited in the dashboard"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("save route: %d %s", rec.Code, rec.Body.String())
	}

	saved, ok := server.routeByID("portainer")
	if !ok {
		t.Fatalf("route disappeared")
	}
	if saved.DisplayName != "Portainer (edited)" || saved.Notes != "edited in the dashboard" {
		t.Fatalf("form fields were not applied: %+v", saved)
	}
	if saved.Stdio == nil || saved.Stdio.EnvSecretRefs["PORTAINER_TOKEN"] != "PORTAINER_TOKEN" {
		t.Fatalf("installer secret refs were lost: %+v", saved.Stdio)
	}

	// The persisted routes.yaml keeps them too.
	persisted, err := config.LoadRoutesFile(server.cfg.RoutesPath)
	if err != nil {
		t.Fatalf("load routes file: %v", err)
	}
	if len(persisted) != 1 || persisted[0].Stdio == nil || persisted[0].Stdio.EnvSecretRefs["PORTAINER_TOKEN"] == "" {
		t.Fatalf("routes.yaml lost the secret refs: %+v", persisted)
	}
}

func TestAdminRouteSaveKeepsManagedDeployment(t *testing.T) {
	deployment := &config.RouteDeployment{
		Type:          "docker",
		Managed:       true,
		Image:         "ghcr.io/czlonkowski/n8n-mcp:latest",
		ContainerName: "mcp-n8n",
		InternalPort:  3000,
	}
	server := newAdminSaveTestServer(t, []config.Route{{
		ID:              "n8n",
		DisplayName:     "n8n",
		PathPrefix:      "/n8n",
		Upstream:        "http://mcp-n8n:3000",
		UpstreamMCPPath: "/mcp",
		Deployment:      deployment,
	}})
	cookies := adminTestSession(t, server)

	rec := postAdminRouteSave(t, server, cookies, url.Values{
		"original_id":  {"n8n"},
		"id":           {"n8n"},
		"display_name": {"n8n (edited)"},
		"transport":    {"http"},
		"path_prefix":  {"/n8n"},
		"upstream":     {"http://mcp-n8n:3000"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("save route: %d %s", rec.Code, rec.Body.String())
	}
	saved, _ := server.routeByID("n8n")
	if saved.Deployment == nil || !saved.Deployment.Managed || saved.Deployment.ContainerName != "mcp-n8n" {
		t.Fatalf("managed deployment metadata was lost: %+v", saved.Deployment)
	}
}

func TestAdminRouteSaveDropsSTDIOSecretRefsWhenSwitchingTransport(t *testing.T) {
	server := newAdminSaveTestServer(t, []config.Route{{
		ID:          "tool",
		DisplayName: "Tool",
		Transport:   "stdio",
		PathPrefix:  "/tool",
		Stdio: &config.RouteStdio{
			Command:       "/bin/tool",
			EnvSecretRefs: map[string]string{"TOKEN": "TOKEN"},
		},
	}})
	cookies := adminTestSession(t, server)

	rec := postAdminRouteSave(t, server, cookies, url.Values{
		"original_id":  {"tool"},
		"id":           {"tool"},
		"display_name": {"Tool"},
		"transport":    {"http"},
		"path_prefix":  {"/tool"},
		"upstream":     {"http://tool:8080"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("save route: %d %s", rec.Code, rec.Body.String())
	}
	saved, _ := server.routeByID("tool")
	if saved.Transport != "http" || saved.Stdio != nil {
		t.Fatalf("switching to http must drop STDIO settings, got %+v", saved)
	}
}

func TestValidateUpsertRouteDoesNotLeakRuntimes(t *testing.T) {
	server := newAdminSaveTestServer(t, []config.Route{{
		ID:          "tool",
		DisplayName: "Tool",
		Transport:   "stdio",
		PathPrefix:  "/tool",
		Stdio:       &config.RouteStdio{Command: "/bin/cat"},
	}})
	candidate := config.Route{
		ID:          "other",
		DisplayName: "Other",
		Transport:   "stdio",
		PathPrefix:  "/other",
		Stdio:       &config.RouteStdio{Command: "/bin/cat"},
	}

	before := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		if err := server.validateUpsertRoute("", candidate); err != nil {
			t.Fatalf("validate: %v", err)
		}
	}
	// Each validation builds two STDIO bridges; their sweep loops must stop.
	waitFor(t, func() bool { return runtime.NumGoroutine() <= before+5 })
}
