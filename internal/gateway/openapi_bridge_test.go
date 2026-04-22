package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

func TestOpenAPIBridgeListsAndCallsTools(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/42" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("verbose"); got != "true" {
			t.Fatalf("expected verbose query true, got %q", got)
		}
		if got := r.Header.Get("X-MCP-Authenticated-Email"); got != "user@example.com" {
			t.Fatalf("expected authenticated email header, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"42","name":"Alice"}`))
	}))
	defer api.Close()

	specPath := filepath.Join(t.TempDir(), "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(`
openapi: 3.0.3
info:
  title: Test API
  version: 1.0.0
paths:
  /users/{id}:
    get:
      operationId: getUser
      summary: Fetch a user
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
        - name: verbose
          in: query
          schema:
            type: boolean
      responses:
        "200":
          description: ok
`), 0o644); err != nil {
		t.Fatalf("write spec: %v", err)
	}

	route := config.Route{
		ID:              "users",
		DisplayName:     "Users API",
		Transport:       "openapi",
		PathPrefix:      "/users",
		UpstreamMCPPath: "/mcp",
		OpenAPI: &config.RouteOpenAPI{
			SpecPath:       specPath,
			BaseURL:        api.URL,
			TimeoutSeconds: 5,
		},
	}
	if err := config.NormalizeRoute(&route); err != nil {
		t.Fatalf("normalize route: %v", err)
	}
	handler, err := newOpenAPIBridge(route)
	if err != nil {
		t.Fatalf("create bridge: %v", err)
	}

	listReq := httptest.NewRequest(http.MethodPost, "/users/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("tools/list status = %d body=%s", listRec.Code, listRec.Body.String())
	}
	if !strings.Contains(listRec.Body.String(), `"getUser"`) {
		t.Fatalf("expected getUser tool, got %s", listRec.Body.String())
	}

	callReq := httptest.NewRequest(http.MethodPost, "/users/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"getUser","arguments":{"id":"42","verbose":true}}}`))
	callReq = callReq.WithContext(auth.WithIdentity(context.Background(), &auth.Identity{Email: "user@example.com"}))
	callRec := httptest.NewRecorder()
	handler.ServeHTTP(callRec, callReq)
	if callRec.Code != http.StatusOK {
		t.Fatalf("tools/call status = %d body=%s", callRec.Code, callRec.Body.String())
	}
	if !strings.Contains(callRec.Body.String(), `"Alice"`) {
		t.Fatalf("expected API response in tool result, got %s", callRec.Body.String())
	}
}

func TestParseOpenAPIOperationsResolvesRefs(t *testing.T) {
	operations, err := parseOpenAPIOperations([]byte(`
openapi: 3.0.3
paths:
  /widgets:
    post:
      operationId: createWidget
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/Widget'
      responses:
        "200":
          description: ok
components:
  schemas:
    Widget:
      type: object
      required: [name]
      properties:
        name:
          type: string
`))
	if err != nil {
		t.Fatalf("parse operations: %v", err)
	}
	if len(operations) != 1 {
		t.Fatalf("expected one operation, got %d", len(operations))
	}
	bodySchema, ok := operations[0].InputSchema["properties"].(map[string]any)["body"].(map[string]any)
	if !ok || bodySchema["type"] != "object" {
		t.Fatalf("expected resolved body schema, got %#v", operations[0].InputSchema)
	}
}
