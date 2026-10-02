package gateway

import (
	"context"
	"encoding/json"
	"fmt"
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
)

// fakeMCPServer is a minimal stateful Streamable HTTP MCP server. It is a
// pointer type so the session pool can recognise it as the same handler.
type fakeMCPServer struct {
	mu          sync.Mutex
	nextSession int
	sessions    map[string]bool
	calls       map[string]int
	authHeaders []string
	deleted     []string
}

func newFakeMCPServer() *fakeMCPServer {
	return &fakeMCPServer{sessions: map[string]bool{}, calls: map[string]int{}}
}

func (f *fakeMCPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	sessionID := r.Header.Get(stdioSessionHeader)
	if r.Method == http.MethodDelete {
		f.deleted = append(f.deleted, sessionID)
		delete(f.sessions, sessionID)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	var request struct {
		ID     *int   `json:"id"`
		Method string `json:"method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.authHeaders = append(f.authHeaders, r.Header.Get("Authorization"))

	if request.Method == "initialize" {
		f.nextSession++
		sessionID = fmt.Sprintf("session-%d", f.nextSession)
		f.sessions[sessionID] = true
	} else if !f.sessions[sessionID] {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}
	f.calls[request.Method]++

	w.Header().Set(stdioSessionHeader, sessionID)
	if request.ID == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var result string
	switch request.Method {
	case "initialize":
		result = `{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fake","version":"1"}}`
	case "tools/list":
		result = `{"tools":[{"name":"echo","inputSchema":{"type":"object"}}]}`
	case "tools/call":
		result = fmt.Sprintf(`{"content":[{"type":"text","text":%q}]}`, sessionID)
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":%s}`, *request.ID, result)
}

func (f *fakeMCPServer) count(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[method]
}

func (f *fakeMCPServer) expireSessions() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions = map[string]bool{}
}

func (f *fakeMCPServer) deletedSessions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.deleted...)
}

func callPooledTool(t *testing.T, server *Server, route config.Route, handler http.Handler, identity *auth.Identity, authHeader string) map[string]any {
	t.Helper()
	var result map[string]any
	err := server.withMCPSession(context.Background(), route, handler, identity, authHeader, func(ctx context.Context, session *mcpPooledSession) error {
		tool, err := mcpSessionToolByOperationID(ctx, session, "echo")
		if err != nil {
			return err
		}
		if tool == nil {
			return fmt.Errorf("tool echo not found")
		}
		result, err = session.caller.callTool(ctx, tool.Name, map[string]any{})
		return err
	})
	if err != nil {
		t.Fatalf("pooled tool call: %v", err)
	}
	return result
}

func toolResultText(result map[string]any) string {
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		return ""
	}
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	return text
}

func TestMCPSessionPoolReusesSessionAndToolList(t *testing.T) {
	server := newTestServerWithRoutes(t, nil)
	fake := newFakeMCPServer()
	route := config.Route{ID: "fake", NormalizedPathPrefix: "/fake"}
	identity := &auth.Identity{UserID: "u1", Email: "user@example.com"}

	first := callPooledTool(t, server, route, fake, identity, "Bearer token-1")
	second := callPooledTool(t, server, route, fake, identity, "Bearer token-2")

	if got := fake.count("initialize"); got != 1 {
		t.Fatalf("expected one initialize, got %d", got)
	}
	if got := fake.count("tools/list"); got != 1 {
		t.Fatalf("expected cached tools/list, got %d calls", got)
	}
	if got := fake.count("tools/call"); got != 2 {
		t.Fatalf("expected two tools/call, got %d", got)
	}
	if toolResultText(first) != toolResultText(second) {
		t.Fatalf("expected both calls on the same session, got %q and %q", toolResultText(first), toolResultText(second))
	}
	if last := fake.authHeaders[len(fake.authHeaders)-1]; last != "Bearer token-2" {
		t.Fatalf("expected the current request's Authorization header, got %q", last)
	}
}

func TestMCPSessionPoolSeparatesUsers(t *testing.T) {
	server := newTestServerWithRoutes(t, nil)
	fake := newFakeMCPServer()
	route := config.Route{ID: "fake", NormalizedPathPrefix: "/fake"}

	alice := callPooledTool(t, server, route, fake, &auth.Identity{UserID: "alice"}, "")
	bob := callPooledTool(t, server, route, fake, &auth.Identity{UserID: "bob"}, "")

	if toolResultText(alice) == toolResultText(bob) {
		t.Fatalf("expected separate sessions per user, both used %q", toolResultText(alice))
	}
	if got := fake.count("initialize"); got != 2 {
		t.Fatalf("expected one initialize per user, got %d", got)
	}
}

func TestMCPSessionPoolRetriesRejectedSession(t *testing.T) {
	server := newTestServerWithRoutes(t, nil)
	fake := newFakeMCPServer()
	route := config.Route{ID: "fake", NormalizedPathPrefix: "/fake"}
	identity := &auth.Identity{UserID: "u1"}

	first := callPooledTool(t, server, route, fake, identity, "")
	fake.expireSessions()
	second := callPooledTool(t, server, route, fake, identity, "")

	if toolResultText(first) == toolResultText(second) {
		t.Fatalf("expected a fresh session after the old one was rejected")
	}
	if got := fake.count("initialize"); got != 2 {
		t.Fatalf("expected re-initialize after rejection, got %d initialize calls", got)
	}
	// The rejected attempt never reached the tool, so it ran exactly twice.
	if got := fake.count("tools/call"); got != 2 {
		t.Fatalf("expected two executed tools/call, got %d", got)
	}
}

func TestMCPSessionPoolReplacesSessionWhenHandlerChanges(t *testing.T) {
	server := newTestServerWithRoutes(t, nil)
	oldHandler := newFakeMCPServer()
	newHandler := newFakeMCPServer()
	route := config.Route{ID: "fake", NormalizedPathPrefix: "/fake"}
	identity := &auth.Identity{UserID: "u1"}

	callPooledTool(t, server, route, oldHandler, identity, "")
	callPooledTool(t, server, route, newHandler, identity, "")

	if got := newHandler.count("initialize"); got != 1 {
		t.Fatalf("expected the new handler to get its own session, got %d initialize calls", got)
	}
	waitFor(t, func() bool { return len(oldHandler.deletedSessions()) == 1 })
}

func TestMCPSessionPoolClosesIdleSessions(t *testing.T) {
	server := newTestServerWithRoutes(t, nil)
	server.mcpSessions.idleTTL = 20 * time.Millisecond
	fake := newFakeMCPServer()
	route := config.Route{ID: "fake", NormalizedPathPrefix: "/fake"}

	callPooledTool(t, server, route, fake, &auth.Identity{UserID: "u1"}, "")
	waitFor(t, func() bool { return len(fake.deletedSessions()) == 1 })

	server.mcpSessions.mu.Lock()
	remaining := len(server.mcpSessions.entries)
	server.mcpSessions.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("expected idle session to leave the pool, %d remain", remaining)
	}
}

func TestMCPRouteOpenAPIToolCallReusesSTDIOProcess(t *testing.T) {
	startsFile := filepath.Join(t.TempDir(), "starts")
	script := `echo start >> "$STARTS_FILE"
while IFS= read -r line; do
id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
case "$line" in
  *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"test","version":"1"}}}\n' "$id" ;;
  *'"method":"notifications/initialized"'*) ;;
  *'"method":"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object"}}]}}\n' "$id" ;;
  *'"method":"tools/call"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}]}}\n' "$id" ;;
esac
done`
	route := config.Route{
		ID:          "echo",
		DisplayName: "Echo MCP",
		Transport:   "stdio",
		PathPrefix:  "/echo",
		Stdio: &config.RouteStdio{
			Command: "/bin/sh",
			Args:    []string{"-c", script},
			Env:     map[string]string{"STARTS_FILE": startsFile},
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
	token, _, err := server.authManager.CreatePersonalAccessToken(user.ID, "Open WebUI", 0)
	if err != nil {
		t.Fatalf("create bearer token: %v", err)
	}

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/echo/openapi/tools/echo", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("call %d: expected 200, got %d: %s", i, rec.Code, rec.Body.String())
		}
	}

	starts, err := os.ReadFile(startsFile)
	if err != nil {
		t.Fatalf("read starts file: %v", err)
	}
	if got := strings.Count(string(starts), "start"); got != 1 {
		t.Fatalf("expected one STDIO process for three OpenAPI calls, got %d", got)
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not met before deadline")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestMCPRouteOpenAPIToolCallRecoversFromExitedSTDIOProcess(t *testing.T) {
	script := `while IFS= read -r line; do
id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
case "$line" in
  *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"test","version":"1"}}}\n' "$id" ;;
  *'"method":"notifications/initialized"'*) ;;
  *'"method":"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"once","inputSchema":{"type":"object"}}]}}\n' "$id" ;;
  *'"method":"tools/call"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}]}}\n' "$id"; exit 0 ;;
esac
done`
	route := config.Route{
		ID:          "once",
		DisplayName: "Once MCP",
		Transport:   "stdio",
		PathPrefix:  "/once",
		Stdio: &config.RouteStdio{
			Command: "/bin/sh",
			Args:    []string{"-c", script},
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
	token, _, err := server.authManager.CreatePersonalAccessToken(user.ID, "Open WebUI", 0)
	if err != nil {
		t.Fatalf("create bearer token: %v", err)
	}
	bridge := server.runtime["once"].Handler.(*sessionBinding).next.(*stdioBridge)

	call := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/once/openapi/tools/once", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		return rec
	}

	if rec := call(); rec.Code != http.StatusOK {
		t.Fatalf("first call: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	waitFor(t, func() bool {
		bridge.mu.Lock()
		defer bridge.mu.Unlock()
		for _, session := range bridge.sessions {
			if !session.exited() {
				return false
			}
		}
		return true
	})
	if rec := call(); rec.Code != http.StatusOK {
		t.Fatalf("call after process exit: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}
