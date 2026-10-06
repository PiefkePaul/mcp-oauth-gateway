package gateway

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

// pidScript answers initialize and answers ping with its own process ID, so
// a test can tell whether a session still talks to the same process.
const pidScript = `while IFS= read -r line; do
id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
case "$line" in
  *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"test","version":"1"}}}\n' "$id" ;;
  *'"method":"ping"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"pid":"%s"}}\n' "$id" "$$" ;;
esac
done`

func reuseTestRoute(id string) config.Route {
	return config.Route{
		ID:          id,
		DisplayName: id,
		Transport:   "stdio",
		PathPrefix:  "/" + id,
		Stdio:       &config.RouteStdio{Command: "/bin/sh", Args: []string{"-c", pidScript}},
	}
}

func reuseTestAgent(t *testing.T, server *Server, email string) bindingTestAgent {
	t.Helper()
	user, err := server.authManager.CreateUser(email, "super-secret-password", false)
	if err != nil {
		t.Fatalf("create %s: %v", email, err)
	}
	token, _, err := server.authManager.CreatePersonalAccessToken(user.ID, email, time.Hour)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	return bindingTestAgent{name: email, token: token}
}

func reuseInit(t *testing.T, server *Server, routeID string, agent bindingTestAgent) string {
	t.Helper()
	rec := mcpRequest(server, http.MethodPost, "/"+routeID+"/mcp", agent, "", bindingInitBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("initialize on %s: %d %s", routeID, rec.Code, rec.Body.String())
	}
	return rec.Header().Get(stdioSessionHeader)
}

// reusePing returns the HTTP status and the process ID that answered.
func reusePing(server *Server, routeID string, agent bindingTestAgent, sessionID string) (int, string) {
	rec := mcpRequest(server, http.MethodPost, "/"+routeID+"/mcp", agent, sessionID, bindingPingBody)
	var response struct {
		Result struct {
			PID string `json:"pid"`
		} `json:"result"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &response)
	return rec.Code, response.Result.PID
}

func mustUpsert(t *testing.T, server *Server, route config.Route) {
	t.Helper()
	if err := server.upsertRoute(route.ID, route); err != nil {
		t.Fatalf("upsert route %s: %v", route.ID, err)
	}
}

func TestRouteMetadataChangeKeepsRunningSessions(t *testing.T) {
	server := newAdminSaveTestServer(t, []config.Route{reuseTestRoute("tools")})
	alice := reuseTestAgent(t, server, "alice@example.com")
	sessionID := reuseInit(t, server, "tools", alice)
	_, pidBefore := reusePing(server, "tools", alice, sessionID)

	route, _ := server.routeByID("tools")
	route.DisplayName = "Tools (renamed)"
	route.Notes = "edited"
	route.ResourceDocumentation = "https://example.com/docs"
	route.OpenAPISessionMode = config.OpenAPISessionPerRequest
	mustUpsert(t, server, route)

	status, pidAfter := reusePing(server, "tools", alice, sessionID)
	if status != http.StatusOK || pidAfter != pidBefore {
		t.Fatalf("metadata change must keep the session and its process: status %d, pid %q -> %q", status, pidBefore, pidAfter)
	}
	if got, _ := server.routeByID("tools"); got.DisplayName != "Tools (renamed)" {
		t.Fatalf("the new settings must still apply, got %q", got.DisplayName)
	}
}

func TestRouteRuntimeChangeRestartsOnlyThatRoute(t *testing.T) {
	server := newAdminSaveTestServer(t, []config.Route{reuseTestRoute("tools"), reuseTestRoute("other")})
	alice := reuseTestAgent(t, server, "alice@example.com")
	toolsSession := reuseInit(t, server, "tools", alice)
	otherSession := reuseInit(t, server, "other", alice)
	_, otherPID := reusePing(server, "other", alice, otherSession)

	route, _ := server.routeByID("tools")
	route.Stdio.Env = map[string]string{"NEW_SETTING": "1"}
	mustUpsert(t, server, route)

	if status, _ := reusePing(server, "tools", alice, toolsSession); status != http.StatusNotFound {
		t.Fatalf("a changed STDIO command environment must restart the route, got %d", status)
	}
	if status, pid := reusePing(server, "other", alice, otherSession); status != http.StatusOK || pid != otherPID {
		t.Fatalf("an unrelated route must keep running: status %d, pid %q -> %q", status, otherPID, pid)
	}
}

func TestRouteSecretChangeRestartsRoute(t *testing.T) {
	route := reuseTestRoute("tools")
	route.Stdio.EnvSecretRefs = map[string]string{"API_TOKEN": auth.RouteEnvSecretRef("tools", "API_TOKEN")}
	server := newAdminSaveTestServer(t, nil)
	if err := server.authManager.SetRouteEnvSecrets("tools", map[string]string{"API_TOKEN": "old"}); err != nil {
		t.Fatalf("set secret: %v", err)
	}
	if err := config.NormalizeRoute(&route); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if err := server.upsertRoute("", route); err != nil {
		t.Fatalf("add route: %v", err)
	}
	alice := reuseTestAgent(t, server, "alice@example.com")
	sessionID := reuseInit(t, server, "tools", alice)

	// Saving with unchanged secrets keeps the process.
	mustUpsert(t, server, route)
	if status, _ := reusePing(server, "tools", alice, sessionID); status != http.StatusOK {
		t.Fatalf("unchanged secrets must keep the session, got %d", status)
	}

	if err := server.authManager.SetRouteEnvSecrets("tools", map[string]string{"API_TOKEN": "new"}); err != nil {
		t.Fatalf("change secret: %v", err)
	}
	mustUpsert(t, server, route)
	if status, _ := reusePing(server, "tools", alice, sessionID); status != http.StatusNotFound {
		t.Fatalf("a changed secret value must restart the route, got %d", status)
	}
}

func TestRouteAccessChangeClosesOnlySessionsThatLostAccess(t *testing.T) {
	server := newAdminSaveTestServer(t, []config.Route{reuseTestRoute("tools")})
	alice := reuseTestAgent(t, server, "alice@example.com")
	bob := reuseTestAgent(t, server, "bob@example.com")
	aliceSession := reuseInit(t, server, "tools", alice)
	bobSession := reuseInit(t, server, "tools", bob)
	_, alicePID := reusePing(server, "tools", alice, aliceSession)

	route, _ := server.routeByID("tools")
	route.Access = config.RouteAccess{Visibility: "private", Mode: "restricted", AllowedUsers: []string{"alice@example.com"}}
	mustUpsert(t, server, route)

	bridge := server.runtime["tools"].Handler.(*sessionBinding).next.(*stdioBridge)
	waitFor(t, func() bool {
		bridge.mu.Lock()
		defer bridge.mu.Unlock()
		return len(bridge.sessions) == 1
	})
	if status, _ := reusePing(server, "tools", bob, bobSession); status != http.StatusForbidden {
		t.Fatalf("bob must be refused after losing access, got %d", status)
	}
	if status, pid := reusePing(server, "tools", alice, aliceSession); status != http.StatusOK || pid != alicePID {
		t.Fatalf("alice keeps her session and process: status %d, pid %q -> %q", status, alicePID, pid)
	}
}

func TestRestartRouteForcesNewProcesses(t *testing.T) {
	server := newAdminSaveTestServer(t, []config.Route{reuseTestRoute("tools")})
	alice := reuseTestAgent(t, server, "alice@example.com")
	sessionID := reuseInit(t, server, "tools", alice)

	if err := server.restartRoute("tools"); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if status, _ := reusePing(server, "tools", alice, sessionID); status != http.StatusNotFound {
		t.Fatalf("a restarted route must drop its sessions, got %d", status)
	}
	if err := server.restartRoute("missing"); err == nil {
		t.Fatalf("restarting an unknown route must fail")
	}
}
