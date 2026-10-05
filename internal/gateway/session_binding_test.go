package gateway

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

func TestSessionBindingSealAndUnseal(t *testing.T) {
	binding := newSessionBinding("route-a", []byte("0123456789abcdef0123456789abcdef"), nil)
	sealed := binding.seal("user:u1|oauth:g1", "inner.with.dots")

	if inner, ok := binding.unseal("user:u1|oauth:g1", sealed); !ok || inner != "inner.with.dots" {
		t.Fatalf("expected round trip, got %q ok=%v", inner, ok)
	}
	if _, ok := binding.unseal("user:u1|oauth:g2", sealed); ok {
		t.Fatalf("another agent of the same user must not unseal the session")
	}
	if _, ok := binding.unseal("user:u2|oauth:g1", sealed); ok {
		t.Fatalf("another user must not unseal the session")
	}
	other := newSessionBinding("route-b", []byte("0123456789abcdef0123456789abcdef"), nil)
	if _, ok := other.unseal("user:u1|oauth:g1", sealed); ok {
		t.Fatalf("a session of one route must not be valid on another")
	}
	for _, forged := range []string{"inner.with.dots", "inner", "." + binding.tag("user:u1|oauth:g1", ""), sealed[:len(sealed)-1] + "A"} {
		if _, ok := binding.unseal("user:u1|oauth:g1", forged); ok {
			t.Fatalf("forged session ID %q was accepted", forged)
		}
	}
}

type bindingTestAgent struct {
	name  string
	token string
}

func newBindingTestServer(t *testing.T, route config.Route) (*Server, bindingTestAgent, bindingTestAgent, bindingTestAgent) {
	t.Helper()
	if err := config.NormalizeRoute(&route); err != nil {
		t.Fatalf("normalize route: %v", err)
	}
	server := newTestServerWithRoutes(t, []config.Route{route})
	alice, err := server.authManager.CreateUser("alice@example.com", "super-secret-password", false)
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	bob, err := server.authManager.CreateUser("bob@example.com", "super-secret-password", false)
	if err != nil {
		t.Fatalf("create bob: %v", err)
	}
	token := func(userID, name string) bindingTestAgent {
		value, _, err := server.authManager.CreatePersonalAccessToken(userID, name, time.Hour)
		if err != nil {
			t.Fatalf("create token %s: %v", name, err)
		}
		return bindingTestAgent{name: name, token: value}
	}
	return server, token(alice.ID, "alice-mac"), token(alice.ID, "alice-pc"), token(bob.ID, "bob")
}

func mcpRequest(handler http.Handler, method, path string, agent bindingTestAgent, sessionID, body string) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "https://mcp.example.com"+path, reader)
	req.Header.Set("Authorization", "Bearer "+agent.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set(stdioSessionHeader, sessionID)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

const (
	bindingInitBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	bindingPingBody = `{"jsonrpc":"2.0","id":2,"method":"ping"}`
)

func TestSessionBindingIsolatesAgentsOnSTDIORoute(t *testing.T) {
	script := `while IFS= read -r line; do
id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
case "$line" in
  *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"test","version":"1"}}}\n' "$id" ;;
  *'"method":"ping"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"pid":"%s"}}\n' "$id" "$$" ;;
esac
done`
	server, aliceMac, alicePC, bob := newBindingTestServer(t, config.Route{
		ID:          "tools",
		DisplayName: "Tools",
		Transport:   "stdio",
		PathPrefix:  "/tools",
		Stdio:       &config.RouteStdio{Command: "/bin/sh", Args: []string{"-c", script}},
	})

	// Two terminals sharing alice-mac's login each open their own session.
	terminal1 := mcpRequest(server, http.MethodPost, "/tools/mcp", aliceMac, "", bindingInitBody)
	terminal2 := mcpRequest(server, http.MethodPost, "/tools/mcp", aliceMac, "", bindingInitBody)
	session1 := terminal1.Header().Get(stdioSessionHeader)
	session2 := terminal2.Header().Get(stdioSessionHeader)
	if terminal1.Code != http.StatusOK || terminal2.Code != http.StatusOK || session1 == "" || session2 == "" || session1 == session2 {
		t.Fatalf("expected two separate sessions, got %d %q and %d %q", terminal1.Code, session1, terminal2.Code, session2)
	}

	// Both terminals use their sessions concurrently.
	var wg sync.WaitGroup
	pids := make([]string, 2)
	for i, sessionID := range []string{session1, session2} {
		wg.Add(1)
		go func(i int, sessionID string) {
			defer wg.Done()
			rec := mcpRequest(server, http.MethodPost, "/tools/mcp", aliceMac, sessionID, bindingPingBody)
			if rec.Code != http.StatusOK {
				t.Errorf("terminal %d ping: %d %s", i+1, rec.Code, rec.Body.String())
				return
			}
			var response struct {
				Result struct {
					PID string `json:"pid"`
				} `json:"result"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &response)
			pids[i] = response.Result.PID
		}(i, sessionID)
	}
	wg.Wait()
	if pids[0] == "" || pids[0] == pids[1] {
		t.Fatalf("expected each terminal to reach its own process, got %q", pids)
	}

	// Neither alice's other machine nor bob can use or end the session.
	for _, intruder := range []bindingTestAgent{alicePC, bob} {
		if rec := mcpRequest(server, http.MethodPost, "/tools/mcp", intruder, session1, bindingPingBody); rec.Code != http.StatusNotFound {
			t.Fatalf("%s reached a foreign session: %d %s", intruder.name, rec.Code, rec.Body.String())
		}
		if rec := mcpRequest(server, http.MethodDelete, "/tools/mcp", intruder, session1, ""); rec.Code != http.StatusNotFound {
			t.Fatalf("%s delete of a foreign session: %d", intruder.name, rec.Code)
		}
	}
	if rec := mcpRequest(server, http.MethodPost, "/tools/mcp", aliceMac, session1, bindingPingBody); rec.Code != http.StatusOK {
		t.Fatalf("owner lost the session after foreign attempts: %d %s", rec.Code, rec.Body.String())
	}

	// After the owner ends it, the session is gone with a 404.
	if rec := mcpRequest(server, http.MethodDelete, "/tools/mcp", aliceMac, session1, ""); rec.Code != http.StatusAccepted {
		t.Fatalf("owner delete: %d", rec.Code)
	}
	if rec := mcpRequest(server, http.MethodPost, "/tools/mcp", aliceMac, session1, bindingPingBody); rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", rec.Code)
	}
}

func TestSessionBindingOnHTTPRouteHidesUpstreamSessionFromOtherAgents(t *testing.T) {
	var (
		mu       sync.Mutex
		received []string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, r.Header.Get(stdioSessionHeader))
		mu.Unlock()
		w.Header().Set(stdioSessionHeader, "upstream-session-1")
		writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{}})
	}))
	defer upstream.Close()

	server, aliceMac, alicePC, bob := newBindingTestServer(t, config.Route{
		ID:              "remote",
		DisplayName:     "Remote",
		PathPrefix:      "/remote",
		Upstream:        upstream.URL,
		UpstreamMCPPath: "/mcp",
	})

	init := mcpRequest(server, http.MethodPost, "/remote/mcp", aliceMac, "", bindingInitBody)
	sealed := init.Header().Get(stdioSessionHeader)
	if init.Code != http.StatusOK || !strings.HasPrefix(sealed, "upstream-session-1.") {
		t.Fatalf("expected a sealed upstream session ID, got %d %q", init.Code, sealed)
	}

	if rec := mcpRequest(server, http.MethodPost, "/remote/mcp", aliceMac, sealed, bindingPingBody); rec.Code != http.StatusOK {
		t.Fatalf("owner request: %d %s", rec.Code, rec.Body.String())
	}
	for _, intruder := range []bindingTestAgent{alicePC, bob} {
		for _, sessionID := range []string{sealed, "upstream-session-1"} {
			if rec := mcpRequest(server, http.MethodPost, "/remote/mcp", intruder, sessionID, bindingPingBody); rec.Code != http.StatusNotFound {
				t.Fatalf("%s with %q: expected 404, got %d", intruder.name, sessionID, rec.Code)
			}
		}
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"", "upstream-session-1"}
	if fmt.Sprint(received) != fmt.Sprint(want) {
		t.Fatalf("upstream must only see the owner's requests with the raw ID, got %q", received)
	}
}

func TestSessionBindingKeepsSSEStreaming(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set(stdioSessionHeader, "stream-session")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "event: message\ndata: {\"first\":true}\n\n")
		w.(http.Flusher).Flush()
		<-release
	}))
	defer upstream.Close()
	defer close(release)

	server, aliceMac, _, _ := newBindingTestServer(t, config.Route{
		ID:              "stream",
		DisplayName:     "Stream",
		PathPrefix:      "/stream",
		Upstream:        upstream.URL,
		UpstreamMCPPath: "/mcp",
	})
	gateway := httptest.NewServer(server)
	defer gateway.Close()

	req, _ := http.NewRequest(http.MethodPost, gateway.URL+"/stream/mcp", strings.NewReader(bindingInitBody))
	req.Header.Set("Authorization", "Bearer "+aliceMac.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get(stdioSessionHeader); !strings.HasPrefix(got, "stream-session.") {
		t.Fatalf("expected sealed session on a streaming response, got %q", got)
	}

	// The first event must arrive while the upstream is still streaming.
	lines := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(resp.Body).ReadString('\n')
		lines <- line
	}()
	select {
	case line := <-lines:
		if !strings.HasPrefix(line, "event: message") {
			t.Fatalf("unexpected first line %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("SSE event was buffered instead of streamed")
	}
}
