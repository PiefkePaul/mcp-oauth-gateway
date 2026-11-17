package gateway

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

func TestProxyPathAllowed(t *testing.T) {
	const base = "/a/mcp"
	cases := []struct {
		path string
		want bool
	}{
		{"/a/mcp", true},
		{"/a/mcp/", true},
		{"/a/mcp/sse", true},
		{"/a/mcp/messages/abc", true},
		{"/a/mcp/messages/", true},
		{"/a/mcp/file.name", true},
		{"/a/mcp/..hidden", true},
		{"/a/mcp/a%20b", true}, // "%20" left after one decoding is a literal

		{"/a/mcp/../../internal/admin", false},
		{"/a/mcp/..", false},
		{"/a/mcp/../", false},
		{"/a/mcp/.", false},
		{"/a/mcp/./sse", false},
		{"/a/mcp/x/../y", false},
		{"/a/mcp/x/../../../etc/passwd", false},
		{"/a/mcp//admin", false},
		{"/a/mcp//", false},
		{"/a/mcp/%2e%2e/admin", false},     // double-encoded on the wire
		{"/a/mcp/%2E%2E/admin", false},     //
		{"/a/mcp/%252e%252e/admin", false}, // triple-encoded on the wire
		{"/a/mcp/.%2e/admin", false},
		{"/a/mcp/x%2f..%2fadmin", false},
		{"/a/mcp/x%5c..%5cadmin", false},
		{"/a/mcp/..;/admin", false},
		{"/a/mcp/..;x=1/admin", false},
		{"/a/mcp/.;/admin", false},
		{"/a/mcp/..\\admin", false},
		{"/a/mcp\\..\\admin", false},
		{"/a/mcp/x\x00y", false},
		{"/a/mcp/x\ny", false},
		{"/a/mcpx", false},
		{"/a", false},
		{"/b/mcp", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := proxyPathAllowed(tc.path, base); got != tc.want {
			t.Errorf("proxyPathAllowed(%q) = %t, want %t", tc.path, got, tc.want)
		}
	}
}

func TestRewriteUpstreamPathNeverLeavesUpstreamBase(t *testing.T) {
	cases := []struct {
		path, upstreamBase, want string
	}{
		{"/a/mcp", "/mcp", "/mcp"},
		{"/a/mcp/sse", "/mcp", "/mcp/sse"},
		{"/a/mcp/", "/mcp", "/mcp/"},
		{"/a/mcp/sse", "/", "/sse"},
		{"/a/mcp/../../internal/admin", "/mcp", "/mcp"},
		{"/a/mcp/%2e%2e/admin", "/mcp", "/mcp"},
		{"/a/mcp//admin", "/", "/"},
	}
	for _, tc := range cases {
		if got := rewriteUpstreamPath(tc.path, "/a/mcp", tc.upstreamBase); got != tc.want {
			t.Errorf("rewriteUpstreamPath(%q, upstream %q) = %q, want %q", tc.path, tc.upstreamBase, got, tc.want)
		}
	}
}

// newPathRecordingUpstream starts an upstream that records every request
// path it sees.
func newPathRecordingUpstream(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var (
		mu   sync.Mutex
		seen []string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.EscapedPath())
		mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))
	t.Cleanup(upstream.Close)
	return upstream, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func newProxyTestServer(t *testing.T, upstreamURL string) (*Server, string) {
	t.Helper()
	route := config.Route{
		ID:              "a",
		DisplayName:     "A MCP",
		PathPrefix:      "/a",
		Upstream:        upstreamURL,
		UpstreamMCPPath: "/mcp",
	}
	if err := config.NormalizeRoute(&route); err != nil {
		t.Fatalf("normalize route: %v", err)
	}
	server := newTestServerWithRoutes(t, []config.Route{route})
	user, err := server.authManager.CreateUser("user@example.com", "super-secret-password", false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	token, _, err := server.authManager.CreatePersonalAccessToken(user.ID, "test", time.Hour)
	if err != nil {
		t.Fatalf("create gateway token: %v", err)
	}
	return server, token
}

func TestProxyRejectsPathsOutsideTheMCPPath(t *testing.T) {
	upstream, seenPaths := newPathRecordingUpstream(t)
	server, token := newProxyTestServer(t, upstream.URL)

	// As they arrive on the wire. httptest.NewRequest would reject some of
	// them, so the URL is set by hand like net/http does for a request line.
	targets := []string{
		"/a/mcp/../../internal/admin",
		"/a/mcp/..",
		"/a/mcp/%2e%2e/%2e%2e/internal/admin",
		"/a/mcp/%2E%2E/admin",
		"/a/mcp/%252e%252e/admin",
		"/a/mcp/x/..%2f..%2f..%2fadmin",
		"/a/mcp//internal/admin",
		"/a/mcp/./admin",
		"/a/mcp/..;/admin",
		"/a/mcp/..%5cadmin",
	}
	for _, target := range targets {
		for _, withToken := range []bool{true, false} {
			req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/a/mcp", strings.NewReader(`{}`))
			parsed, err := url.ParseRequestURI(target)
			if err != nil {
				t.Fatalf("parse %q: %v", target, err)
			}
			req.URL.Path, req.URL.RawPath = parsed.Path, parsed.RawPath
			req.RequestURI = target
			if withToken {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s (token=%t): expected 400, got %d: %s", target, withToken, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), `"invalid_path"`) {
				t.Errorf("%s (token=%t): expected invalid_path, got %s", target, withToken, rec.Body.String())
			}
		}
	}
	if seen := seenPaths(); len(seen) != 0 {
		t.Fatalf("upstream must not see rejected requests, saw %v", seen)
	}
}

func TestProxyStillForwardsCleanChildPaths(t *testing.T) {
	upstream, seenPaths := newPathRecordingUpstream(t)
	server, token := newProxyTestServer(t, upstream.URL)

	for _, target := range []string{"/a/mcp", "/a/mcp/sse", "/a/mcp/messages/abc?session=1"} {
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com"+target, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d: %s", target, rec.Code, rec.Body.String())
		}
	}
	want := []string{"/mcp", "/mcp/sse", "/mcp/messages/abc"}
	if got := seenPaths(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("upstream saw %v, want %v", got, want)
	}
}

func TestOpenAPIAdapterDoesNotPassUpstreamErrorTextToClients(t *testing.T) {
	const internalDetail = "connect to db.internal:5432 failed for /srv/secret/app.py"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, internalDetail, http.StatusInternalServerError)
	}))
	defer upstream.Close()
	server, token := newProxyTestServer(t, upstream.URL)

	var logged bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(previous)

	requests := []*http.Request{
		httptest.NewRequest(http.MethodGet, "https://mcp.example.com/a/openapi.json", nil),
		httptest.NewRequest(http.MethodPost, "https://mcp.example.com/a/openapi/tools/anything", strings.NewReader(`{}`)),
	}
	for _, req := range requests {
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("%s: expected 502, got %d: %s", req.URL.Path, rec.Code, rec.Body.String())
		}
		for _, leak := range []string{"db.internal", "/srv/secret", upstream.URL, strings.TrimPrefix(upstream.URL, "http://")} {
			if strings.Contains(rec.Body.String(), leak) {
				t.Fatalf("%s: response leaks %q: %s", req.URL.Path, leak, rec.Body.String())
			}
		}
	}
	if !strings.Contains(logged.String(), "db.internal:5432") {
		t.Fatalf("expected the upstream error in the gateway log, got %s", logged.String())
	}
}

func TestPublicMCPErrorDescriptionKeepsToolErrors(t *testing.T) {
	server := newTestServer(t)
	route := config.Route{ID: "a"}

	toolErr := &mcpJSONRPCError{Code: -32602, Message: "unknown argument \"x\""}
	if got := server.publicMCPErrorDescription(route, "tools/call", toolErr); got != toolErr.Error() {
		t.Fatalf("JSON-RPC errors of the MCP server should reach the caller, got %q", got)
	}
	bridgeErr := &mcpJSONRPCError{Code: -32603, Message: stdioBridgeErrorPrefix + "start stdio command \"/opt/secret/bin\": no such file"}
	if got := server.publicMCPErrorDescription(route, "tools/call", bridgeErr); strings.Contains(got, "/opt/secret") {
		t.Fatalf("bridge errors must not reach the caller, got %q", got)
	}
}

func TestStdioStartFailureIsNotExplainedToClients(t *testing.T) {
	route := config.Route{
		ID:          "broken",
		DisplayName: "Broken MCP",
		Transport:   "stdio",
		PathPrefix:  "/broken",
		Stdio: &config.RouteStdio{
			Command: "/opt/secret-location/does-not-exist",
		},
	}
	if err := config.NormalizeRoute(&route); err != nil {
		t.Fatalf("normalize route: %v", err)
	}
	server := newTestServerWithRoutes(t, []config.Route{route})
	user, err := server.authManager.CreateUser("user@example.com", "super-secret-password", false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	token, _, err := server.authManager.CreatePersonalAccessToken(user.ID, "test", time.Hour)
	if err != nil {
		t.Fatalf("create gateway token: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/broken/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret-location") {
		t.Fatalf("response names the command: %s", rec.Body.String())
	}

	// A client mistake is still explained.
	req = httptest.NewRequest(http.MethodPost, "https://mcp.example.com/broken/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "send initialize first") {
		t.Fatalf("expected 400 with a hint, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestIndexJSONHidesSetupDetailsFromVisitors(t *testing.T) {
	server := newTestServer(t)
	server.cfg.BootstrapEmail = "admin@example.com"

	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/?format=json", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := payload["bootstrap_user_configured"]; ok {
		t.Fatalf("anonymous catalog reveals the bootstrap setting: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "n8n-mcp:8080") {
		t.Fatalf("anonymous catalog reveals an upstream address: %s", rec.Body.String())
	}
}

func TestAccessLogURI(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/", "/"},
		{"/healthz", "/healthz"},
		{"/?format=json", "/?format=json"},
		{"/authorize?response_type=code&client_id=abc&state=S3cret&code_challenge=CH&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=mcp&resource=https%3A%2F%2Fmcp.example.com%2Fa%2Fmcp",
			"/authorize?response_type=code&client_id=abc&state=REDACTED&code_challenge=REDACTED&code_challenge_method=S256&redirect_uri=REDACTED&scope=mcp&resource=https%3A%2F%2Fmcp.example.com%2Fa%2Fmcp"},
		{"/cb?code=AUTHCODE&state=xyz", "/cb?code=REDACTED&state=REDACTED"},
		{"/a/mcp/messages?sessionId=abc&access_token=tok", "/a/mcp/messages?sessionId=REDACTED&access_token=REDACTED"},
		{"/a/mcp?Code=x&STATE=y", "/a/mcp?Code=REDACTED&STATE=REDACTED"},
		{"/a/mcp?token", "/a/mcp?REDACTED"},
		{"/a/mcp?%zz=secret", "/a/mcp?REDACTED"},
		{"/a/mcp?code=a=b&&format=json", "/a/mcp?code=REDACTED&REDACTED&format=json"},
		{"/account/login?next=%2Fauthorize%3Fstate%3DS3cret", "/account/login?next=REDACTED"},
		{"/a%20b/mcp?x=1", "/a%20b/mcp?x=REDACTED"},
	}
	for _, tc := range cases {
		parsed, err := url.ParseRequestURI(tc.in)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.in, err)
		}
		if got := accessLogURI(parsed); got != tc.want {
			t.Errorf("accessLogURI(%q)\n got  %q\n want %q", tc.in, got, tc.want)
		}
	}
}

func TestAccessLogMiddlewareMasksQueryValues(t *testing.T) {
	var logged bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(previous)

	handler := accessLogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The handler itself still gets the real query.
		if r.URL.Query().Get("code") != "AUTHCODE123" {
			t.Errorf("handler lost the query: %q", r.URL.RawQuery)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/token?code=AUTHCODE123&state=STATE456&refresh_token=RT789&format=json", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	line := logged.String()
	for _, secret := range []string{"AUTHCODE123", "STATE456", "RT789"} {
		if strings.Contains(line, secret) {
			t.Fatalf("access log contains %q: %s", secret, line)
		}
	}
	if !strings.Contains(line, `path="/token?code=REDACTED&state=REDACTED&refresh_token=REDACTED&format=json"`) || !strings.Contains(line, "status=204") {
		t.Fatalf("unexpected access log line: %s", line)
	}
}
