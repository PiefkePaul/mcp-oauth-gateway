package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

func healthTestServer(t *testing.T, upstream http.Handler) (*Server, *httptest.Server) {
	t.Helper()
	backend := httptest.NewServer(upstream)
	t.Cleanup(backend.Close)
	route := config.Route{
		ID:              "tools",
		DisplayName:     "Tools",
		PathPrefix:      "/tools",
		Upstream:        backend.URL,
		UpstreamMCPPath: "/mcp",
	}
	return newAdminSaveTestServer(t, []config.Route{route}), backend
}

func TestCheckRouteReportsReachableUpstreamAndClosesItsSession(t *testing.T) {
	fake := newFakeMCPServer()
	server, _ := healthTestServer(t, fake)

	result := server.checkRoute(context.Background(), "tools")
	if result.Status != healthStatusOK || result.ToolCount != 1 || result.CheckedAt.IsZero() {
		t.Fatalf("expected a successful check with one tool, got %+v", result)
	}
	if got := len(fake.deletedSessions()); got != 1 {
		t.Fatalf("the probe must close its MCP session, %d closed", got)
	}
	if server.health.get("tools").Status != healthStatusOK {
		t.Fatalf("the result must be stored")
	}
}

func unauthorizedUpstream() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
	})
}

func TestCheckRouteExplainsRejectedUpstreamBearer(t *testing.T) {
	server, _ := healthTestServer(t, unauthorizedUpstream())

	result := server.checkRoute(context.Background(), "tools")
	if result.Status != healthStatusError || !strings.Contains(result.Error, "Upstream Bearer") {
		t.Fatalf("expected an error pointing at the upstream bearer, got %+v", result)
	}

	// With only user-specific bearers the anonymous probe cannot tell.
	user, err := server.authManager.CreateUser("user@example.com", "super-secret-password", false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := server.authManager.SetRouteUserUpstreamBearer("tools", user.ID, "user-token"); err != nil {
		t.Fatalf("set user bearer: %v", err)
	}
	if result := server.checkRoute(context.Background(), "tools"); result.Status != healthStatusWarning {
		t.Fatalf("expected a warning when only user bearers exist, got %+v", result)
	}
}

func TestCheckRouteReportsUnreachableUpstream(t *testing.T) {
	server, backend := healthTestServer(t, newFakeMCPServer())
	backend.Close()

	result := server.checkRoute(context.Background(), "tools")
	if result.Status != healthStatusError || !strings.Contains(result.Error, "could not be reached") {
		t.Fatalf("expected an unreachable error, got %+v", result)
	}
}

func TestCheckAllRoutesCountsAndForgetsRemovedRoutes(t *testing.T) {
	server, _ := healthTestServer(t, newFakeMCPServer())
	server.health.set("removed-route", routeHealth{Status: healthStatusOK})

	ok, total := server.checkAllRoutes(context.Background())
	if ok != 1 || total != 1 {
		t.Fatalf("expected 1 of 1 reachable, got %d of %d", ok, total)
	}
	if server.health.get("removed-route").Status != healthStatusUnknown {
		t.Fatalf("results of removed routes must be dropped")
	}
}

func TestPublicCatalogShowsHealthWithoutErrorDetails(t *testing.T) {
	server, _ := healthTestServer(t, unauthorizedUpstream())
	server.checkRoute(context.Background(), "tools")

	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/?format=json", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	var catalog struct {
		Routes []struct {
			ID     string         `json:"id"`
			Health map[string]any `json:"health"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &catalog); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	if len(catalog.Routes) != 1 || catalog.Routes[0].Health["status"] != healthStatusError {
		t.Fatalf("expected the route's health in the catalog, got %+v", catalog.Routes)
	}
	if strings.Contains(rec.Body.String(), "Upstream Bearer") {
		t.Fatalf("the public catalog must not expose error details: %s", rec.Body.String())
	}

	htmlReq := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/", nil)
	htmlReq.Header.Set("Accept", "text/html")
	htmlRec := httptest.NewRecorder()
	server.ServeHTTP(htmlRec, htmlReq)
	if !strings.Contains(htmlRec.Body.String(), "Gestoert") {
		t.Fatalf("expected the status label in the public dashboard")
	}
}

func TestAdminRouteSaveChecksTheRoute(t *testing.T) {
	server, _ := healthTestServer(t, unauthorizedUpstream())
	cookies := adminTestSession(t, server)

	rec := postAdminRouteSave(t, server, cookies, url.Values{
		"original_id":  {"tools"},
		"id":           {"tools"},
		"display_name": {"Tools"},
		"transport":    {"http"},
		"path_prefix":  {"/tools"},
		"upstream":     {server.runtime["tools"].Route.Upstream},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	location, _ := url.Parse(rec.Header().Get("Location"))
	if !strings.Contains(location.Query().Get("notice"), "MCP check failed") || !strings.Contains(location.Query().Get("error"), "Upstream Bearer") {
		t.Fatalf("saving must report the failed check, got %q", rec.Header().Get("Location"))
	}
}

func TestAdminManualChecksAndOverview(t *testing.T) {
	server, _ := healthTestServer(t, newFakeMCPServer())
	cookies := adminTestSession(t, server)

	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		form.Set("csrf_token", adminTestCSRF)
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com"+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		return rec
	}

	if rec := post("/admin/routes/check", url.Values{"route_id": {"tools"}}); rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "MCP+reachable") {
		t.Fatalf("manual check: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := post("/admin/routes/check-all", url.Values{}); rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "1+of+1") {
		t.Fatalf("check all: %d %q", rec.Code, rec.Header().Get("Location"))
	}

	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/admin", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Erreichbar") || !strings.Contains(rec.Body.String(), "1 Tools") {
		t.Fatalf("the admin overview must show the status and details")
	}
}
