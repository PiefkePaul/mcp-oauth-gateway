package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

func TestStdioBridgeForwardsJSONRPCRequest(t *testing.T) {
	script := `while IFS= read -r line; do
case "$line" in
  *'"method":"initialize"'*) printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":"test-stdio","version":"1.0.0"}}}' ;;
  *'"method":"tools/list"'*) printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"hello","description":"Hello tool","inputSchema":{"type":"object"}}]}}' ;;
esac
done`
	route := config.Route{
		ID:              "stdio-test",
		DisplayName:     "STDIO Test",
		Transport:       "stdio",
		PathPrefix:      "/stdio-test",
		UpstreamMCPPath: "/mcp",
		Stdio: &config.RouteStdio{
			Command: "/bin/sh",
			Args:    []string{"-c", script},
		},
	}
	if err := config.NormalizeRoute(&route); err != nil {
		t.Fatalf("normalize route: %v", err)
	}

	handler, closeFn, err := newStdioBridge(route, nil)
	if err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	defer func() { _ = closeFn() }()

	initReq := httptest.NewRequest(http.MethodPost, "/stdio-test/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	initRec := httptest.NewRecorder()
	handler.ServeHTTP(initRec, initReq)
	if initRec.Code != http.StatusOK {
		t.Fatalf("initialize status = %d body=%s", initRec.Code, initRec.Body.String())
	}
	sessionID := initRec.Header().Get(stdioSessionHeader)
	if sessionID == "" {
		t.Fatalf("expected session header")
	}
	if !strings.Contains(initRec.Body.String(), `"test-stdio"`) {
		t.Fatalf("unexpected initialize body: %s", initRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodPost, "/stdio-test/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`))
	listReq.Header.Set(stdioSessionHeader, sessionID)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("tools/list status = %d body=%s", listRec.Code, listRec.Body.String())
	}
	if !strings.Contains(listRec.Body.String(), `"hello"`) {
		t.Fatalf("unexpected tools/list body: %s", listRec.Body.String())
	}
}

func TestStdioBridgeInjectsResolvedSecretEnvironment(t *testing.T) {
	script := `while IFS= read -r line; do
case "$line" in
  *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"%s","version":"1.0.0"}}}\n' "$SECRET_ENV" ;;
esac
done`
	route := config.Route{
		ID:              "secret-stdio-test",
		DisplayName:     "Secret STDIO Test",
		Transport:       "stdio",
		PathPrefix:      "/secret-stdio-test",
		UpstreamMCPPath: "/mcp",
		Stdio: &config.RouteStdio{
			Command: "/bin/sh",
			Args:    []string{"-c", script},
			EnvSecretRefs: map[string]string{
				"SECRET_ENV": "route:secret-stdio-test:env:SECRET_ENV",
			},
		},
	}
	if err := config.NormalizeRoute(&route); err != nil {
		t.Fatalf("normalize route: %v", err)
	}

	handler, closeFn, err := newStdioBridge(route, func(got config.Route) (map[string]string, error) {
		if got.ID != route.ID {
			t.Fatalf("expected resolver route %q, got %q", route.ID, got.ID)
		}
		return map[string]string{"SECRET_ENV": "from-secret-store"}, nil
	})
	if err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	defer func() { _ = closeFn() }()

	initReq := httptest.NewRequest(http.MethodPost, "/secret-stdio-test/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	initRec := httptest.NewRecorder()
	handler.ServeHTTP(initRec, initReq)
	if initRec.Code != http.StatusOK {
		t.Fatalf("initialize status = %d body=%s", initRec.Code, initRec.Body.String())
	}
	if !strings.Contains(initRec.Body.String(), `"from-secret-store"`) {
		t.Fatalf("expected resolved secret in child process environment, got %s", initRec.Body.String())
	}
}

func TestParseJSONRPCMessagesRejectsEmptyBatch(t *testing.T) {
	_, _, err := parseJSONRPCMessages([]byte(`[]`))
	if err == nil {
		t.Fatalf("expected empty batch error")
	}
}

// newOwnershipTestBridge starts a bridge whose child answers initialize and
// ping requests, echoing back the JSON-RPC id it received.
func newOwnershipTestBridge(t *testing.T) http.Handler {
	t.Helper()
	script := `while IFS= read -r line; do
case "$line" in
  *'"method":"initialize"'*) printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"owner-test","version":"1.0.0"}}}' ;;
  *'"method":"ping"'*) printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{}}' ;;
esac
done`
	route := config.Route{
		ID:              "stdio-owner-test",
		DisplayName:     "STDIO Owner Test",
		Transport:       "stdio",
		PathPrefix:      "/stdio-owner-test",
		UpstreamMCPPath: "/mcp",
		Stdio: &config.RouteStdio{
			Command: "/bin/sh",
			Args:    []string{"-c", script},
		},
	}
	if err := config.NormalizeRoute(&route); err != nil {
		t.Fatalf("normalize route: %v", err)
	}
	handler, closeFn, err := newStdioBridge(route, nil)
	if err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	t.Cleanup(func() { _ = closeFn() })
	return handler
}

func stdioOwnerRequest(handler http.Handler, method string, identity *auth.Identity, sessionID, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, "/stdio-owner-test/mcp", nil)
	} else {
		req = httptest.NewRequest(method, "/stdio-owner-test/mcp", strings.NewReader(body))
	}
	if sessionID != "" {
		req.Header.Set(stdioSessionHeader, sessionID)
	}
	if identity != nil {
		req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

const (
	stdioOwnerInitBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	stdioOwnerPingBody = `{"jsonrpc":"2.0","id":2,"method":"ping"}`
)

func initStdioOwnerSession(t *testing.T, handler http.Handler, identity *auth.Identity) string {
	t.Helper()
	rec := stdioOwnerRequest(handler, http.MethodPost, identity, "", stdioOwnerInitBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("initialize status = %d body=%s", rec.Code, rec.Body.String())
	}
	sessionID := rec.Header().Get(stdioSessionHeader)
	if sessionID == "" {
		t.Fatalf("expected session header")
	}
	return sessionID
}

func TestStdioBridgeRejectsCrossUserSessionID(t *testing.T) {
	handler := newOwnershipTestBridge(t)
	alice := &auth.Identity{UserID: "alice-id", Email: "alice@example.com"}
	bob := &auth.Identity{UserID: "bob-id", Email: "bob@example.com"}

	sessionID := initStdioOwnerSession(t, handler, alice)

	rec := stdioOwnerRequest(handler, http.MethodPost, bob, sessionID, stdioOwnerPingBody)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("cross-user status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(stdioSessionHeader); got != "" {
		t.Fatalf("cross-user response must not carry a session header, got %q", got)
	}

	// The error must be indistinguishable from a session that never existed.
	unknown := stdioOwnerRequest(handler, http.MethodPost, bob, "does-not-exist", stdioOwnerPingBody)
	if unknown.Code != rec.Code {
		t.Fatalf("unknown session status = %d, cross-user status = %d", unknown.Code, rec.Code)
	}
	wantBody := strings.ReplaceAll(unknown.Body.String(), "does-not-exist", sessionID)
	if rec.Body.String() != wantBody {
		t.Fatalf("cross-user error leaks existence:\n got: %s\nwant: %s", rec.Body.String(), wantBody)
	}

	// Anonymous callers cannot reach an authenticated user's session either.
	anon := stdioOwnerRequest(handler, http.MethodPost, nil, sessionID, stdioOwnerPingBody)
	if anon.Code != http.StatusBadRequest {
		t.Fatalf("anonymous status = %d body=%s", anon.Code, anon.Body.String())
	}
}

func stdioBridgeSessionCount(t *testing.T, handler http.Handler) int {
	t.Helper()
	bridge, ok := handler.(*stdioBridge)
	if !ok {
		t.Fatalf("handler is %T, want *stdioBridge", handler)
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	return len(bridge.sessions)
}

func TestStdioBridgeRejectsNonInitializeWithoutSessionHeader(t *testing.T) {
	handler := newOwnershipTestBridge(t)
	alice := &auth.Identity{UserID: "alice-id"}
	bob := &auth.Identity{UserID: "bob-id"}

	// Without any session, a header-less request must not spawn a process.
	rec := stdioOwnerRequest(handler, http.MethodPost, alice, "", stdioOwnerPingBody)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("header-less ping status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(stdioSessionHeader); got != "" {
		t.Fatalf("rejected request must not carry a session header, got %q", got)
	}
	if n := stdioBridgeSessionCount(t, handler); n != 0 {
		t.Fatalf("header-less request started %d session(s)", n)
	}

	// Notifications are rejected the same way.
	notify := stdioOwnerRequest(handler, http.MethodPost, alice, "", `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if notify.Code != http.StatusBadRequest {
		t.Fatalf("header-less notification status = %d body=%s", notify.Code, notify.Body.String())
	}

	// With exactly one session open, a header-less request from another user
	// is neither routed to it nor given a new process.
	initStdioOwnerSession(t, handler, alice)
	rec = stdioOwnerRequest(handler, http.MethodPost, bob, "", stdioOwnerPingBody)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("header-less ping with one session status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(stdioSessionHeader); got != "" {
		t.Fatalf("header-less request was routed to session %q", got)
	}
	if n := stdioBridgeSessionCount(t, handler); n != 1 {
		t.Fatalf("expected 1 session, got %d", n)
	}
}

func TestStdioBridgeIgnoresCrossUserDelete(t *testing.T) {
	handler := newOwnershipTestBridge(t)
	alice := &auth.Identity{UserID: "alice-id"}
	bob := &auth.Identity{UserID: "bob-id"}

	sessionID := initStdioOwnerSession(t, handler, alice)

	del := stdioOwnerRequest(handler, http.MethodDelete, bob, sessionID, "")
	if del.Code != http.StatusAccepted {
		t.Fatalf("cross-user delete status = %d", del.Code)
	}

	rec := stdioOwnerRequest(handler, http.MethodPost, alice, sessionID, stdioOwnerPingBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner request after foreign delete status = %d body=%s", rec.Code, rec.Body.String())
	}

	ownDel := stdioOwnerRequest(handler, http.MethodDelete, alice, sessionID, "")
	if ownDel.Code != http.StatusAccepted {
		t.Fatalf("owner delete status = %d", ownDel.Code)
	}
	gone := stdioOwnerRequest(handler, http.MethodPost, alice, sessionID, stdioOwnerPingBody)
	if gone.Code != http.StatusBadRequest {
		t.Fatalf("request after owner delete status = %d body=%s", gone.Code, gone.Body.String())
	}
}

func TestStdioBridgeAllowsSameUserSessionReuse(t *testing.T) {
	handler := newOwnershipTestBridge(t)

	// A fresh *Identity per request, as handleProxy builds one per request.
	sessionID := initStdioOwnerSession(t, handler, &auth.Identity{UserID: "alice-id", Email: "alice@example.com"})
	rec := stdioOwnerRequest(handler, http.MethodPost, &auth.Identity{UserID: "alice-id", Email: "alice@example.com"}, sessionID, stdioOwnerPingBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("same-user status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(stdioSessionHeader); got != sessionID {
		t.Fatalf("expected session %q, got %q", sessionID, got)
	}

	// Without a user ID the email identifies the owner.
	emailSession := initStdioOwnerSession(t, handler, &auth.Identity{Email: "carol@example.com"})
	rec = stdioOwnerRequest(handler, http.MethodPost, &auth.Identity{Email: "carol@example.com"}, emailSession, stdioOwnerPingBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("same-email status = %d body=%s", rec.Code, rec.Body.String())
	}
}
