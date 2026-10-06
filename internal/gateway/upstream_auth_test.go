package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

func TestNormalizeUpstreamBearer(t *testing.T) {
	cases := []struct {
		in       string
		want     string
		unquoted bool
		wantErr  bool
	}{
		{in: "", want: ""},
		{in: "  abc123=  ", want: "abc123="},
		{in: `"abc123="`, want: "abc123=", unquoted: true},
		{in: `'abc123='`, want: "abc123=", unquoted: true},
		{in: "Bearer abc123=", want: "abc123="},
		{in: `bearer "abc123="`, want: "abc123=", unquoted: true},
		{in: `"abc123=`, wantErr: true},
		{in: `abc"123`, wantErr: true},
		{in: "abc 123", wantErr: true},
		{in: `""`, wantErr: true},
	}
	for _, c := range cases {
		got, unquoted, err := normalizeUpstreamBearer(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: expected an error, got %q", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want || unquoted != c.unquoted {
			t.Errorf("%q: got %q unquoted=%v err=%v, want %q unquoted=%v", c.in, got, unquoted, err, c.want, c.unquoted)
		}
	}
}

func bearerTestRoute() config.Route {
	return config.Route{
		ID:              "camoufox-mcp",
		DisplayName:     "camoufox-mcp",
		PathPrefix:      "/camoufox",
		Upstream:        "http://camoufox-mcp:3000",
		UpstreamMCPPath: "/mcp",
	}
}

func TestAdminRouteSaveStripsQuotesFromUpstreamBearer(t *testing.T) {
	server := newAdminSaveTestServer(t, []config.Route{bearerTestRoute()})
	cookies := adminTestSession(t, server)

	rec := postAdminRouteSave(t, server, cookies, url.Values{
		"original_id":           {"camoufox-mcp"},
		"id":                    {"camoufox-mcp"},
		"display_name":          {"camoufox-mcp"},
		"transport":             {"http"},
		"path_prefix":           {"/camoufox"},
		"upstream":              {"http://camoufox-mcp:3000"},
		"upstream_bearer_token": {`"Y29uZ3Jlc3M="`},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	if location := rec.Header().Get("Location"); !strings.Contains(location, "quotes") {
		t.Fatalf("expected a notice about removed quotes, got redirect %q", location)
	}
	if token, ok := server.authManager.ResolveRouteUpstreamBearer("camoufox-mcp", nil); !ok || token != "Y29uZ3Jlc3M=" {
		t.Fatalf("expected the bearer without quotes, got %q ok=%v", token, ok)
	}
}

func TestAdminRouteSaveRejectsMalformedUpstreamBearerBeforeSaving(t *testing.T) {
	server := newAdminSaveTestServer(t, []config.Route{bearerTestRoute()})
	cookies := adminTestSession(t, server)

	rec := postAdminRouteSave(t, server, cookies, url.Values{
		"original_id":           {"camoufox-mcp"},
		"id":                    {"camoufox-mcp"},
		"display_name":          {"renamed"},
		"transport":             {"http"},
		"path_prefix":           {"/camoufox"},
		"upstream":              {"http://camoufox-mcp:3000"},
		"upstream_bearer_token": {`"Y29uZ3Jlc3M=`},
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "quotes") {
		t.Fatalf("expected 400 explaining the quote, got %d", rec.Code)
	}
	if route, _ := server.routeByID("camoufox-mcp"); route.DisplayName != "camoufox-mcp" {
		t.Fatalf("a rejected bearer must not save the rest of the form, got display name %q", route.DisplayName)
	}
	if _, ok := server.authManager.ResolveRouteUpstreamBearer("camoufox-mcp", nil); ok {
		t.Fatalf("a rejected bearer must not be stored")
	}
}

func proxyAuthTestServer(t *testing.T, passAuthorization bool) (*Server, string) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="upstream"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
	}))
	t.Cleanup(upstream.Close)

	route := bearerTestRoute()
	route.Upstream = upstream.URL
	route.PassAuthorization = passAuthorization
	if err := config.NormalizeRoute(&route); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	server := newTestServerWithRoutes(t, []config.Route{route})
	user, err := server.authManager.CreateUser("user@example.com", "super-secret-password", false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	token, _, err := server.authManager.CreatePersonalAccessToken(user.ID, "test", time.Hour)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	return server, token
}

func TestProxyTurnsUpstreamUnauthorizedIntoBadGateway(t *testing.T) {
	server, token := proxyAuthTestServer(t, false)

	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/camoufox/mcp", strings.NewReader(bindingInitBody))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for an upstream 401, got %d %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("the upstream challenge must not reach the client, got %q", got)
	}
	if !strings.Contains(rec.Body.String(), "upstream_unauthorized") {
		t.Fatalf("expected an explanatory error body, got %s", rec.Body.String())
	}
}

func TestProxyKeepsUpstreamUnauthorizedWhenPassingAuthorization(t *testing.T) {
	server, token := proxyAuthTestServer(t, true)

	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/camoufox/mcp", strings.NewReader(bindingInitBody))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("routes that pass the client's token through keep the upstream 401, got %d", rec.Code)
	}
}
