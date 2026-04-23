package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

func TestMCPRouteOpenAPIAdapterListsAndCallsSTDIO(t *testing.T) {
	script := `while IFS= read -r line; do
case "$line" in
  *'"method":"initialize"'*) printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"test","version":"1"}}}' ;;
  *'"method":"notifications/initialized"'*) ;;
  *'"method":"tools/list"'*) printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo-message","description":"Echo a message","inputSchema":{"type":"object","required":["message"],"properties":{"message":{"type":"string"}}}}]}}' ;;
  *'"method":"tools/call"'*) printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"echo ok"}],"structuredContent":{"ok":true}}}' ;;
esac
done`
	route := config.Route{
		ID:              "echo",
		DisplayName:     "Echo MCP",
		Transport:       "stdio",
		PathPrefix:      "/echo",
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
		t.Fatalf("create stdio bridge: %v", err)
	}
	defer func() { _ = closeFn() }()

	server := newTestServerWithRoutes(t, []config.Route{route})
	spec := server.buildMCPRouteOpenAPISpec(route, []mcpToolDefinition{{
		Name:        "echo-message",
		Description: "Echo a message",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"message": map[string]any{"type": "string"},
			},
		},
	}})
	paths := spec["paths"].(map[string]any)
	if _, ok := paths["/openapi/tools/echo_message"]; !ok {
		t.Fatalf("expected generated OpenAPI path for echo-message, got %#v", paths)
	}

	caller := newMCPRouteCaller(route, handler, &auth.Identity{Email: "user@example.com"}, "")
	defer caller.close(context.Background())
	tools, err := caller.listTools(context.Background())
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if got := strings.Join(sortedMCPToolNames(tools), ","); got != "echo-message" {
		t.Fatalf("unexpected tools: %s", got)
	}
	result, err := caller.callTool(context.Background(), "echo-message", map[string]any{"message": "hi"})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if structured, _ := result["structuredContent"].(map[string]any); structured["ok"] != true {
		t.Fatalf("expected structured content from tool call, got %#v", result)
	}
}

func TestMCPRouteOpenAPISpecEndpointRendersForPublicRoute(t *testing.T) {
	script := `while IFS= read -r line; do
case "$line" in
  *'"method":"initialize"'*) printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"test","version":"1"}}}' ;;
  *'"method":"notifications/initialized"'*) ;;
  *'"method":"tools/list"'*) printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"hello","inputSchema":{"type":"object"}}]}}' ;;
esac
done`
	route := config.Route{
		ID:          "hello",
		DisplayName: "Hello MCP",
		Transport:   "stdio",
		PathPrefix:  "/hello",
		Stdio: &config.RouteStdio{
			Command: "/bin/sh",
			Args:    []string{"-c", script},
		},
	}
	if err := config.NormalizeRoute(&route); err != nil {
		t.Fatalf("normalize route: %v", err)
	}
	server := newTestServerWithRoutes(t, []config.Route{route})

	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/hello/openapi.json", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"/openapi/tools/hello"`) {
		t.Fatalf("expected OpenAPI tool path, got %s", rec.Body.String())
	}

	openWebUIReq := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/hello/openapi.json/openapi.json", nil)
	openWebUIRec := httptest.NewRecorder()
	server.ServeHTTP(openWebUIRec, openWebUIReq)
	if openWebUIRec.Code != http.StatusOK {
		t.Fatalf("expected Open WebUI compatibility path to return 200, got %d: %s", openWebUIRec.Code, openWebUIRec.Body.String())
	}
}

func sortedMCPToolNames(tools []mcpToolDefinition) []string {
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}
