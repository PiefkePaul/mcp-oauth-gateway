package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
