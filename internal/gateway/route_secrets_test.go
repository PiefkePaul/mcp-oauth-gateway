package gateway

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/secretsfile"
)

const (
	fileBearer  = "file-bearer-7f3a9c"
	fileBearer2 = "file-bearer-b81d04"
	storeBearer = "store-bearer-55e2aa"
	userBearer  = "user-bearer-c0ffee"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureGatewayLog(t *testing.T) *syncBuffer {
	t.Helper()
	buffer := &syncBuffer{}
	previous := log.Writer()
	log.SetOutput(buffer)
	t.Cleanup(func() { log.SetOutput(previous) })
	return buffer
}

// newAuthRecordingUpstream answers every request and records the
// Authorization header it carried.
func newAuthRecordingUpstream(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(upstream.Close)
	return upstream, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

type routeSecretsFixture struct {
	server *Server
	token  string
	user   *auth.User
	path   string
	seen   func() []string
}

// newRouteSecretsFixture builds a gateway with one route "german-legal-mcp"
// and a route secrets file with the given content ("" = no file).
func newRouteSecretsFixture(t *testing.T, content string, strict bool) routeSecretsFixture {
	t.Helper()
	upstream, seen := newAuthRecordingUpstream(t)
	route := config.Route{
		ID:              "german-legal-mcp",
		DisplayName:     "German Legal",
		PathPrefix:      "/legal",
		Upstream:        upstream.URL,
		UpstreamMCPPath: "/mcp",
	}
	if err := config.NormalizeRoute(&route); err != nil {
		t.Fatalf("normalize route: %v", err)
	}
	server := newTestServerWithRoutes(t, []config.Route{route})
	path := filepath.Join(t.TempDir(), "gateway-routes.env")
	if content != "" {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	server.cfg.RouteSecrets = config.RouteSecretsConfig{File: path, Reload: time.Second, Strict: strict}
	server.routeSecrets = secretsfile.Open(path)

	user, err := server.authManager.CreateUser("user@example.com", "super-secret-password", false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	token, _, err := server.authManager.CreatePersonalAccessToken(user.ID, "test", time.Hour)
	if err != nil {
		t.Fatalf("create gateway token: %v", err)
	}
	return routeSecretsFixture{server: server, token: token, user: user, path: path, seen: seen}
}

func (f routeSecretsFixture) call(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/legal/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+f.token)
	rec := httptest.NewRecorder()
	f.server.ServeHTTP(rec, req)
	return rec
}

func (f routeSecretsFixture) lastUpstreamAuth(t *testing.T) string {
	t.Helper()
	seen := f.seen()
	if len(seen) == 0 {
		t.Fatalf("the upstream saw no request")
	}
	return seen[len(seen)-1]
}

func TestUpstreamBearerOrderUserThenFileThenStore(t *testing.T) {
	f := newRouteSecretsFixture(t, "GERMAN_LEGAL_MCP='"+fileBearer+"'\n", false)
	if err := f.server.authManager.SetRouteUpstreamBearer("german-legal-mcp", storeBearer); err != nil {
		t.Fatal(err)
	}

	if rec := f.call(t); rec.Code != http.StatusOK {
		t.Fatalf("call: %d %s", rec.Code, rec.Body.String())
	}
	if got := f.lastUpstreamAuth(t); got != "Bearer "+fileBearer {
		t.Fatalf("the file must win over the auth store, upstream saw %q", got)
	}

	if err := f.server.authManager.SetRouteUserUpstreamBearer("german-legal-mcp", f.user.ID, userBearer); err != nil {
		t.Fatal(err)
	}
	f.call(t)
	if got := f.lastUpstreamAuth(t); got != "Bearer "+userBearer {
		t.Fatalf("the user's own bearer must win over the file, upstream saw %q", got)
	}
}

func TestUpstreamBearerFallsBackToStoreWhenFileHasNoValue(t *testing.T) {
	f := newRouteSecretsFixture(t, "OTHER_ROUTE='"+fileBearer+"'\n", false)
	if err := f.server.authManager.SetRouteUpstreamBearer("german-legal-mcp", storeBearer); err != nil {
		t.Fatal(err)
	}
	f.call(t)
	if got := f.lastUpstreamAuth(t); got != "Bearer "+storeBearer {
		t.Fatalf("expected the stored bearer during the transition, upstream saw %q", got)
	}
}

func TestStrictModeAnswers503WithoutCallingTheUpstream(t *testing.T) {
	logs := captureGatewayLog(t)
	f := newRouteSecretsFixture(t, "OTHER_ROUTE='"+fileBearer+"'\n", true)
	if err := f.server.authManager.SetRouteUpstreamBearer("german-legal-mcp", storeBearer); err != nil {
		t.Fatal(err)
	}

	rec := f.call(t)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"upstream_bearer_missing"`) {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
	if seen := f.seen(); len(seen) != 0 {
		t.Fatalf("the upstream must not be called, saw %v", seen)
	}
	if !strings.Contains(logs.String(), "GERMAN_LEGAL_MCP") {
		t.Fatalf("the log should name the missing key: %s", logs.String())
	}
	if strings.Contains(logs.String(), storeBearer) || strings.Contains(rec.Body.String(), storeBearer) {
		t.Fatalf("a bearer leaked")
	}

	// A user's own bearer still works in strict mode.
	if err := f.server.authManager.SetRouteUserUpstreamBearer("german-legal-mcp", f.user.ID, userBearer); err != nil {
		t.Fatal(err)
	}
	if rec := f.call(t); rec.Code != http.StatusOK {
		t.Fatalf("user bearer in strict mode: %d", rec.Code)
	}
	if got := f.lastUpstreamAuth(t); got != "Bearer "+userBearer {
		t.Fatalf("upstream saw %q", got)
	}
}

func TestStrictModeLeavesRoutesWithoutAnyBearerAlone(t *testing.T) {
	f := newRouteSecretsFixture(t, "OTHER_ROUTE='"+fileBearer+"'\n", true)
	if rec := f.call(t); rec.Code != http.StatusOK {
		t.Fatalf("a route that never had a bearer must still be forwarded, got %d", rec.Code)
	}
	if got := f.lastUpstreamAuth(t); got != "" {
		t.Fatalf("no bearer expected, upstream saw %q", got)
	}
}

func TestFileChangeReachesTheUpstreamWithoutRestart(t *testing.T) {
	f := newRouteSecretsFixture(t, "GERMAN_LEGAL_MCP='"+fileBearer+"'\n", true)
	f.call(t)
	if got := f.lastUpstreamAuth(t); got != "Bearer "+fileBearer {
		t.Fatalf("upstream saw %q", got)
	}

	if err := os.WriteFile(f.path, []byte("GERMAN_LEGAL_MCP='"+fileBearer2+"'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.server.routeSecrets.Poll()
	f.server.routeSecrets.Poll()
	f.call(t)
	if got := f.lastUpstreamAuth(t); got != "Bearer "+fileBearer2 {
		t.Fatalf("expected the rotated bearer, upstream saw %q", got)
	}
}

func TestUpstreamBearerKeyOverridesTheDerivedName(t *testing.T) {
	f := newRouteSecretsFixture(t, "LEGAL='"+fileBearer+"'\nGERMAN_LEGAL_MCP='"+fileBearer2+"'\n", false)
	routes := f.server.routesSnapshot()
	routes[0].UpstreamBearerKey = "LEGAL"
	if err := f.server.replaceRoutes(routes); err != nil {
		t.Fatal(err)
	}
	f.call(t)
	if got := f.lastUpstreamAuth(t); got != "Bearer "+fileBearer {
		t.Fatalf("upstream saw %q", got)
	}
}

func TestRoutesSharingASecretKeyAreRejected(t *testing.T) {
	f := newRouteSecretsFixture(t, "GERMAN_LEGAL_MCP='"+fileBearer+"'\n", false)
	routes := f.server.routesSnapshot()
	twin := config.Route{ID: "german_legal_mcp", DisplayName: "Twin", PathPrefix: "/twin", Upstream: routes[0].Upstream, UpstreamMCPPath: "/mcp"}
	err := f.server.replaceRoutes(append(routes, twin))
	if err == nil || !strings.Contains(err.Error(), "GERMAN_LEGAL_MCP") {
		t.Fatalf("expected a collision error, got %v", err)
	}
	twin.UpstreamBearerKey = "TWIN"
	if err := f.server.replaceRoutes(append(routes, twin)); err != nil {
		t.Fatalf("an explicit key resolves the collision: %v", err)
	}
}

func TestNoBearerValueInAdminPagesOrLogs(t *testing.T) {
	logs := captureGatewayLog(t)
	f := newRouteSecretsFixture(t, "GERMAN_LEGAL_MCP='"+fileBearer+"'\n", false)
	f.server.cfg.RoutesPath = filepath.Join(t.TempDir(), "routes.yaml")
	if err := f.server.authManager.SetRouteUpstreamBearer("german-legal-mcp", storeBearer); err != nil {
		t.Fatal(err)
	}
	f.call(t)
	cookies := adminTestSession(t, f.server)

	for _, target := range []string{"/admin", "/admin?route=german-legal-mcp", "/admin/routes/export", "/healthz"} {
		req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com"+target, nil)
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		f.server.ServeHTTP(rec, req)
		body := rec.Body.String()
		if strings.Contains(body, fileBearer) || strings.Contains(body, storeBearer) {
			t.Errorf("%s shows a bearer value", target)
		}
	}
	if out := logs.String(); strings.Contains(out, fileBearer) || strings.Contains(out, storeBearer) {
		t.Fatalf("log contains a bearer value: %s", out)
	}
	if label := f.server.routeBearerSourceLabel(f.server.routesSnapshot()[0]); !strings.Contains(label, "GERMAN_LEGAL_MCP") || strings.Contains(label, fileBearer) {
		t.Fatalf("unexpected source label %q", label)
	}
}

func TestWithoutSecretsFileBehaviourIsUnchanged(t *testing.T) {
	f := newRouteSecretsFixture(t, "GERMAN_LEGAL_MCP='"+fileBearer+"'\n", false)
	f.server.routeSecrets = nil
	f.server.cfg.RouteSecrets = config.RouteSecretsConfig{}
	if err := f.server.authManager.SetRouteUpstreamBearer("german-legal-mcp", storeBearer); err != nil {
		t.Fatal(err)
	}
	f.call(t)
	if got := f.lastUpstreamAuth(t); got != "Bearer "+storeBearer {
		t.Fatalf("upstream saw %q", got)
	}
}

func TestAdminFormShowsSourceAndLocksTheBearerField(t *testing.T) {
	f := newRouteSecretsFixture(t, "GERMAN_LEGAL_MCP='"+fileBearer+"'\n", false)
	cookies := adminTestSession(t, f.server)
	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/admin?route=german-legal-mcp", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	f.server.ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("admin page: %d", rec.Code)
	}
	for _, want := range []string{"aus der Secrets-Datei (GERMAN_LEGAL_MCP", `name="upstream_bearer_key"`, `type="password" autocomplete="off" disabled`} {
		if !strings.Contains(body, want) {
			t.Errorf("admin page lacks %q", want)
		}
	}
}

func TestAdminFormSaysWhereTheBearerIsMaintained(t *testing.T) {
	f := newRouteSecretsFixture(t, "OTHER='"+fileBearer+"'\n", false)
	f.server.cfg.RouteSecrets.Hint = "Infisical nas-stacks/prod/gateway/routen/{route_id}/UPSTREAM_BEARER ({key})"
	cookies := adminTestSession(t, f.server)
	page := func(query string) string {
		req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/admin?"+query, nil)
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		f.server.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("admin page %s: %d", query, rec.Code)
		}
		return rec.Body.String()
	}

	existing := page("route=german-legal-mcp")
	if want := "Infisical nas-stacks/prod/gateway/routen/german-legal-mcp/UPSTREAM_BEARER (GERMAN_LEGAL_MCP)"; !strings.Contains(existing, want) {
		t.Errorf("form of an existing route lacks %q", want)
	}
	if !strings.Contains(existing, "Wert nicht hier eintragen") {
		t.Errorf("form lacks the warning")
	}

	fresh := page("new=1")
	if want := "routen/&lt;route-id&gt;/UPSTREAM_BEARER (&lt;ROUTE_ID&gt;)"; !strings.Contains(fresh, want) {
		t.Errorf("form of a new route lacks %q", want)
	}

	// Without a configured hint the key and the file are named.
	f.server.cfg.RouteSecrets.Hint = ""
	if want := "GERMAN_LEGAL_MCP in " + f.path; !strings.Contains(page("route=german-legal-mcp"), want) {
		t.Errorf("default hint lacks %q", want)
	}

	// Without a secrets file there is no hint at all.
	f.server.routeSecrets = nil
	if strings.Contains(page("route=german-legal-mcp"), "Wert nicht hier eintragen") {
		t.Errorf("hint shown although no secrets file is configured")
	}
}
