package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

func newLifecycleTestBridge(t *testing.T, opts stdioBridgeOptions) *stdioBridge {
	t.Helper()
	script := `while IFS= read -r line; do
id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
case "$line" in
  *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"test","version":"1"}}}\n' "$id" ;;
  *'"method":"ping"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{}}\n' "$id" ;;
esac
done`
	route := config.Route{
		ID:          "lifecycle",
		DisplayName: "Lifecycle",
		Transport:   "stdio",
		PathPrefix:  "/lifecycle",
		Stdio:       &config.RouteStdio{Command: "/bin/sh", Args: []string{"-c", script}},
	}
	if err := config.NormalizeRoute(&route); err != nil {
		t.Fatalf("normalize route: %v", err)
	}
	bridge, err := newStdioBridgeWithOptions(route, nil, opts)
	if err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	t.Cleanup(func() { _ = bridge.Close() })
	return bridge
}

func lifecycleRequest(ctx context.Context, bridge http.Handler, method string, identity *auth.Identity, sessionID, body string) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	var req *http.Request
	if reader != nil {
		req = httptest.NewRequest(method, "/lifecycle/mcp", reader)
	} else {
		req = httptest.NewRequest(method, "/lifecycle/mcp", nil)
	}
	req = req.WithContext(auth.WithIdentity(ctx, identity))
	if sessionID != "" {
		req.Header.Set(stdioSessionHeader, sessionID)
	}
	rec := httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	return rec
}

func lifecycleInit(t *testing.T, bridge http.Handler, identity *auth.Identity) string {
	t.Helper()
	rec := lifecycleRequest(context.Background(), bridge, http.MethodPost, identity, "", stdioOwnerInitBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("initialize: %d %s", rec.Code, rec.Body.String())
	}
	return rec.Header().Get(stdioSessionHeader)
}

// openStream holds a GET stream on the session until the returned cancel is
// called, and waits until the bridge counts it as active.
func openStream(t *testing.T, bridge *stdioBridge, identity *auth.Identity, sessionID string) (cancel func(), status func() int) {
	t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/lifecycle/mcp", nil).WithContext(auth.WithIdentity(ctx, identity))
	req.Header.Set(stdioSessionHeader, sessionID)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		bridge.ServeHTTP(rec, req)
		close(done)
	}()
	waitFor(t, func() bool {
		bridge.mu.Lock()
		defer bridge.mu.Unlock()
		session := bridge.sessions[sessionID]
		return session != nil && session.active > 0
	})
	return func() {
			stop()
			<-done
		}, func() int {
			<-done
			return rec.Code
		}
}

func bridgeHasSession(bridge *stdioBridge, sessionID string) bool {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	_, ok := bridge.sessions[sessionID]
	return ok
}

func TestStdioBridgeClosesIdleSessions(t *testing.T) {
	bridge := newLifecycleTestBridge(t, stdioBridgeOptions{IdleTimeout: 50 * time.Millisecond, SweepInterval: 10 * time.Millisecond})
	alice := &auth.Identity{UserID: "alice"}

	sessionID := lifecycleInit(t, bridge, alice)
	waitFor(t, func() bool { return !bridgeHasSession(bridge, sessionID) })

	rec := lifecycleRequest(context.Background(), bridge, http.MethodPost, alice, sessionID, stdioOwnerPingBody)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a reaped session, got %d", rec.Code)
	}
}

func TestStdioBridgeOpenStreamKeepsSessionAlive(t *testing.T) {
	bridge := newLifecycleTestBridge(t, stdioBridgeOptions{IdleTimeout: 50 * time.Millisecond, SweepInterval: 10 * time.Millisecond})
	alice := &auth.Identity{UserID: "alice"}
	sessionID := lifecycleInit(t, bridge, alice)

	closeStream, _ := openStream(t, bridge, alice, sessionID)
	time.Sleep(200 * time.Millisecond)
	if !bridgeHasSession(bridge, sessionID) {
		t.Fatalf("a session with an open stream must not be reaped")
	}
	closeStream()
	waitFor(t, func() bool { return !bridgeHasSession(bridge, sessionID) })
}

func TestStdioBridgeStreamForUnknownSessionIs404(t *testing.T) {
	bridge := newLifecycleTestBridge(t, stdioBridgeOptions{})
	rec := lifecycleRequest(context.Background(), bridge, http.MethodGet, &auth.Identity{UserID: "alice"}, "does-not-exist", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestStdioBridgeAgentLimitEvictsOldestIdleSession(t *testing.T) {
	bridge := newLifecycleTestBridge(t, stdioBridgeOptions{MaxPerAgent: 2})
	alice := &auth.Identity{UserID: "alice"}
	bob := &auth.Identity{UserID: "bob"}

	bobSession := lifecycleInit(t, bridge, bob)
	first := lifecycleInit(t, bridge, alice)
	second := lifecycleInit(t, bridge, alice)
	third := lifecycleInit(t, bridge, alice)

	if bridgeHasSession(bridge, first) {
		t.Fatalf("the oldest idle session of the agent should have been evicted")
	}
	for _, sessionID := range []string{second, third, bobSession} {
		if !bridgeHasSession(bridge, sessionID) {
			t.Fatalf("session %q should still exist", sessionID)
		}
	}
}

func TestStdioBridgeAgentLimitRefusesWhenAllSessionsAreBusy(t *testing.T) {
	bridge := newLifecycleTestBridge(t, stdioBridgeOptions{MaxPerAgent: 2})
	alice := &auth.Identity{UserID: "alice"}

	var closers []func()
	for i := 0; i < 2; i++ {
		closeStream, _ := openStream(t, bridge, alice, lifecycleInit(t, bridge, alice))
		closers = append(closers, closeStream)
	}
	defer func() {
		for _, closeStream := range closers {
			closeStream()
		}
	}()

	rec := lifecycleRequest(context.Background(), bridge, http.MethodPost, alice, "", stdioOwnerInitBody)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("expected 429 with Retry-After, got %d %v", rec.Code, rec.Header())
	}
}

func TestStdioBridgeRouteLimitDoesNotEvictOtherAgents(t *testing.T) {
	bridge := newLifecycleTestBridge(t, stdioBridgeOptions{MaxPerRoute: 2})
	alice := &auth.Identity{UserID: "alice"}
	first := lifecycleInit(t, bridge, alice)
	second := lifecycleInit(t, bridge, alice)

	rec := lifecycleRequest(context.Background(), bridge, http.MethodPost, &auth.Identity{UserID: "bob"}, "", stdioOwnerInitBody)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("expected 503 with Retry-After, got %d", rec.Code)
	}
	if !bridgeHasSession(bridge, first) || !bridgeHasSession(bridge, second) {
		t.Fatalf("another agent's sessions must not be evicted for the route limit")
	}
}

func TestStdioBridgeClosesSessionsThatLoseAuthorization(t *testing.T) {
	var (
		mu      sync.Mutex
		revoked = map[string]bool{}
	)
	bridge := newLifecycleTestBridge(t, stdioBridgeOptions{Authorize: func(identity *auth.Identity) bool {
		mu.Lock()
		defer mu.Unlock()
		return !revoked[identity.UserID]
	}})
	alice := &auth.Identity{UserID: "alice"}
	bob := &auth.Identity{UserID: "bob"}
	aliceSession := lifecycleInit(t, bridge, alice)
	bobSession := lifecycleInit(t, bridge, bob)

	mu.Lock()
	revoked["alice"] = true
	mu.Unlock()
	bridge.sweep()

	if bridgeHasSession(bridge, aliceSession) {
		t.Fatalf("a revoked agent's session must be closed")
	}
	if !bridgeHasSession(bridge, bobSession) {
		t.Fatalf("other sessions must survive")
	}
}

func TestRevokedPersonalTokenClosesItsSTDIOSessions(t *testing.T) {
	server, aliceMac, alicePC, _ := newBindingTestServer(t, config.Route{
		ID:          "tools",
		DisplayName: "Tools",
		Transport:   "stdio",
		PathPrefix:  "/tools",
		Stdio:       &config.RouteStdio{Command: "/bin/cat"},
	})
	bridge := server.runtime["tools"].Handler.(*sessionBinding).next.(*stdioBridge)

	// /bin/cat echoes the request, which is enough to open a session.
	macSession := mcpRequest(server, http.MethodPost, "/tools/mcp", aliceMac, "", bindingInitBody)
	pcSession := mcpRequest(server, http.MethodPost, "/tools/mcp", alicePC, "", bindingInitBody)
	if macSession.Code != http.StatusOK || pcSession.Code != http.StatusOK {
		t.Fatalf("initialize: %d %d", macSession.Code, pcSession.Code)
	}
	countSessions := func() int {
		bridge.mu.Lock()
		defer bridge.mu.Unlock()
		return len(bridge.sessions)
	}
	if got := countSessions(); got != 2 {
		t.Fatalf("expected two sessions, got %d", got)
	}

	user, _ := server.authManager.UserByID(lookupUserIDByEmail(t, server, "alice@example.com"))
	var macTokenID string
	for _, token := range server.authManager.ListUserPersonalAccessTokens(user.ID) {
		if token.Name == aliceMac.name {
			macTokenID = token.ID
		}
	}
	if err := server.authManager.RevokeUserPersonalAccessToken(user.ID, macTokenID); err != nil {
		t.Fatalf("revoke token: %v", err)
	}

	// Only the revoked agent's session is closed.
	waitFor(t, func() bool { return countSessions() == 1 })
	if rec := mcpRequest(server, http.MethodPost, "/tools/mcp", alicePC, pcSession.Header().Get(stdioSessionHeader), bindingPingBody); rec.Code != http.StatusOK {
		t.Fatalf("the other agent's session must survive, got %d %s", rec.Code, rec.Body.String())
	}
}

func lookupUserIDByEmail(t *testing.T, server *Server, email string) string {
	t.Helper()
	for _, user := range server.authManager.ListUsers() {
		if user.Email == email {
			return user.ID
		}
	}
	t.Fatalf("user %s not found", email)
	return ""
}

func TestRemovingGroupAccessClosesSTDIOSessions(t *testing.T) {
	server, aliceMac, _, _ := newBindingTestServer(t, config.Route{
		ID:          "tools",
		DisplayName: "Tools",
		Transport:   "stdio",
		PathPrefix:  "/tools",
		Access:      config.RouteAccess{Visibility: "private", Mode: "restricted", AllowedGroups: []string{"engineers"}},
		Stdio:       &config.RouteStdio{Command: "/bin/cat"},
	})
	group, err := server.authManager.CreateGroup("engineers")
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	aliceID := lookupUserIDByEmail(t, server, "alice@example.com")
	if err := server.authManager.SetUserGroups(aliceID, []string{group.ID}); err != nil {
		t.Fatalf("add alice to group: %v", err)
	}
	bridge := server.runtime["tools"].Handler.(*sessionBinding).next.(*stdioBridge)

	if rec := mcpRequest(server, http.MethodPost, "/tools/mcp", aliceMac, "", bindingInitBody); rec.Code != http.StatusOK {
		t.Fatalf("initialize: %d %s", rec.Code, rec.Body.String())
	}
	if err := server.authManager.SetUserGroups(aliceID, nil); err != nil {
		t.Fatalf("remove alice from group: %v", err)
	}
	waitFor(t, func() bool {
		bridge.mu.Lock()
		defer bridge.mu.Unlock()
		return len(bridge.sessions) == 0
	})
}
