package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

const maxMCPOpenAPIRequestBytes = 4 << 20

type mcpToolDefinition struct {
	Name        string
	Description string
	InputSchema map[string]any
}

type mcpRouteCaller struct {
	route       config.Route
	handler     http.Handler
	identity    *auth.Identity
	authHeader  string
	sessionID   string
	initialized bool
	nextID      int
}

func (s *Server) handleRouteOpenAPISpec(w http.ResponseWriter, r *http.Request, route config.Route, handler http.Handler) {
	if !allowsReadMethod(r.Method) {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}

	identity, _ := s.authManager.CurrentIdentity(r)
	if identity == nil {
		if token, err := bearerToken(r.Header.Get("Authorization")); err == nil {
			resourceURL := s.absoluteURL(route.PublicMCPPath())
			if tokenIdentity, err := s.authManager.ValidateAccessToken(token, resourceURL); err == nil {
				identity = tokenIdentity
			} else if route.Access.IsPrivate() || route.Access.EffectiveMode() != "public" {
				s.writeChallenge(w, r, route)
				return
			}
		}
	}
	if identity != nil && !routeAccessAllowed(route, identity) {
		http.Error(w, "you are not allowed to view this MCP OpenAPI spec", http.StatusForbidden)
		return
	}
	if identity == nil && (route.Access.IsPrivate() || route.Access.EffectiveMode() != "public") {
		s.writeChallenge(w, r, route)
		return
	}

	caller := newMCPRouteCaller(route, handler, identity, r.Header.Get("Authorization"))
	defer caller.close(r.Context())

	tools, err := caller.listTools(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error":             "mcp_tools_list_failed",
			"error_description": err.Error(),
		})
		return
	}

	spec := s.buildMCPRouteOpenAPISpec(route, tools)
	writeJSON(w, http.StatusOK, spec)
}

func (s *Server) handleRouteOpenAPIToolCall(w http.ResponseWriter, r *http.Request, route config.Route, handler http.Handler, operationID string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	identity, ok := s.authenticateRouteBearer(w, r, route)
	if !ok {
		return
	}

	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMCPOpenAPIRequestBytes))
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
			"error":             "request_too_large",
			"error_description": err.Error(),
		})
		return
	}
	arguments, err := decodeOpenAPIToolArguments(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_arguments",
			"error_description": err.Error(),
		})
		return
	}

	caller := newMCPRouteCaller(route, handler, identity, r.Header.Get("Authorization"))
	defer caller.close(r.Context())

	tools, err := caller.listTools(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error":             "mcp_tools_list_failed",
			"error_description": err.Error(),
		})
		return
	}
	tool, ok := mcpToolByOperationID(tools, operationID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error":             "unknown_tool",
			"error_description": "no MCP tool matches this OpenAPI operation",
		})
		return
	}

	result, err := caller.callTool(r.Context(), tool.Name, arguments)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error":             "mcp_tool_call_failed",
			"error_description": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) authenticateRouteBearer(w http.ResponseWriter, r *http.Request, route config.Route) (*auth.Identity, bool) {
	token, err := bearerToken(r.Header.Get("Authorization"))
	if err != nil {
		s.writeChallenge(w, r, route)
		return nil, false
	}

	resourceURL := s.absoluteURL(route.PublicMCPPath())
	identity, err := s.authManager.ValidateAccessToken(token, resourceURL)
	if err != nil {
		s.writeChallenge(w, r, route)
		return nil, false
	}
	if !routeAccessAllowed(route, identity) {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":             "forbidden",
			"error_description": "your account is not allowed to use this MCP server",
		})
		return nil, false
	}
	return identity, true
}

func (s *Server) buildMCPRouteOpenAPISpec(route config.Route, tools []mcpToolDefinition) map[string]any {
	paths := make(map[string]any, len(tools))
	operationIDs := mcpToolOperationIDs(tools)
	for _, tool := range tools {
		operationID := operationIDs[tool.Name]
		paths["/openapi/tools/"+operationID] = map[string]any{
			"post": map[string]any{
				"operationId": operationID,
				"summary":     defaultIfEmpty(tool.Description, "Call MCP tool "+tool.Name),
				"description": fmt.Sprintf("Calls MCP tool `%s` on route `%s`.", tool.Name, route.ID),
				"security":    openAPISecurityRequirements(route),
				"x-mcp-tool":  tool.Name,
				"requestBody": map[string]any{
					"required": true,
					"content": map[string]any{
						"application/json": map[string]any{
							"schema": normalizeMCPToolInputSchema(tool.InputSchema),
						},
					},
				},
				"responses": map[string]any{
					"200": map[string]any{
						"description": "MCP tool result",
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": mcpToolResultSchema(),
							},
						},
					},
				},
			},
		}
	}

	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       route.DisplayName + " MCP OpenAPI Adapter",
			"version":     "1.0.0",
			"description": "Generated OpenAPI adapter for MCP route " + route.ID + ".",
		},
		"servers": []map[string]any{
			{"url": s.absoluteURL(route.NormalizedPathPrefix)},
		},
		"security": openAPISecurityRequirements(route),
		"paths":    paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "OAuth2 access token",
				},
				"oauth2": map[string]any{
					"type": "oauth2",
					"flows": map[string]any{
						"authorizationCode": map[string]any{
							"authorizationUrl": s.absoluteURL("/authorize"),
							"tokenUrl":         s.absoluteURL("/token"),
							"scopes":           routeScopesAsMap(route),
						},
					},
				},
			},
		},
	}
}

func newMCPRouteCaller(route config.Route, handler http.Handler, identity *auth.Identity, authHeader string) *mcpRouteCaller {
	return &mcpRouteCaller{
		route:      route,
		handler:    handler,
		identity:   identity,
		authHeader: strings.TrimSpace(authHeader),
	}
}

func (c *mcpRouteCaller) listTools(ctx context.Context) ([]mcpToolDefinition, error) {
	if err := c.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	result, err := c.sendRequest(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var payload struct {
		Tools []struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			InputSchema map[string]any `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(result, &payload); err != nil {
		return nil, fmt.Errorf("decode tools/list result: %w", err)
	}
	tools := make([]mcpToolDefinition, 0, len(payload.Tools))
	for _, tool := range payload.Tools {
		name := strings.TrimSpace(tool.Name)
		if name == "" {
			continue
		}
		tools = append(tools, mcpToolDefinition{
			Name:        name,
			Description: strings.TrimSpace(tool.Description),
			InputSchema: normalizeMCPToolInputSchema(tool.InputSchema),
		})
	}
	return tools, nil
}

func (c *mcpRouteCaller) callTool(ctx context.Context, toolName string, arguments map[string]any) (map[string]any, error) {
	if err := c.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	result, err := c.sendRequest(ctx, "tools/call", map[string]any{
		"name":      toolName,
		"arguments": arguments,
	})
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(result, &payload); err != nil {
		return nil, fmt.Errorf("decode tools/call result: %w", err)
	}
	return payload, nil
}

func (c *mcpRouteCaller) ensureInitialized(ctx context.Context) error {
	if c.initialized {
		return nil
	}
	_, err := c.sendRequest(ctx, "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "mcp-oauth-gateway-openapi-adapter",
			"version": "dev",
		},
	})
	if err != nil {
		return err
	}
	_ = c.sendNotification(ctx, "notifications/initialized", map[string]any{})
	c.initialized = true
	return nil
}

func (c *mcpRouteCaller) sendRequest(ctx context.Context, method string, params any) (json.RawMessage, error) {
	c.nextID++
	id := c.nextID
	request := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}
	if params != nil {
		request["params"] = params
	}

	status, headers, body, err := c.sendRaw(ctx, request)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("MCP HTTP status %d: %s", status, strings.TrimSpace(string(body)))
	}

	responseBody, err := decodeMCPHTTPResponseBody(headers, body)
	if err != nil {
		return nil, err
	}

	var response struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("decode MCP JSON-RPC response: %w", err)
	}
	if response.Error != nil {
		return nil, fmt.Errorf("MCP JSON-RPC error %d: %s", response.Error.Code, response.Error.Message)
	}
	if len(response.Result) == 0 {
		return nil, fmt.Errorf("MCP JSON-RPC response is missing result")
	}
	if sessionID := strings.TrimSpace(headers.Get(stdioSessionHeader)); sessionID != "" {
		c.sessionID = sessionID
	}
	return response.Result, nil
}

func decodeMCPHTTPResponseBody(headers http.Header, body []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(body)
	contentType := strings.ToLower(headers.Get("Content-Type"))
	if !strings.Contains(contentType, "text/event-stream") && !bytes.HasPrefix(trimmed, []byte("event:")) && !bytes.HasPrefix(trimmed, []byte("data:")) {
		return trimmed, nil
	}
	payload, err := firstJSONDataFromSSE(trimmed)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func firstJSONDataFromSSE(body []byte) ([]byte, error) {
	events := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n\n")
	for _, event := range events {
		var dataLines []string
		for _, line := range strings.Split(event, "\n") {
			line = strings.TrimRight(line, "\r")
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			data := strings.TrimPrefix(line, "data:")
			data = strings.TrimPrefix(data, " ")
			dataLines = append(dataLines, data)
		}
		if len(dataLines) == 0 {
			continue
		}
		payload := strings.TrimSpace(strings.Join(dataLines, "\n"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		if strings.HasPrefix(payload, "{") || strings.HasPrefix(payload, "[") {
			return []byte(payload), nil
		}
	}
	return nil, fmt.Errorf("MCP SSE response did not contain JSON data")
}

func (c *mcpRouteCaller) sendNotification(ctx context.Context, method string, params any) error {
	request := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
	}
	if params != nil {
		request["params"] = params
	}
	status, _, body, err := c.sendRaw(ctx, request)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("MCP notification HTTP status %d: %s", status, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *mcpRouteCaller) sendRaw(ctx context.Context, payload any) (int, http.Header, []byte, error) {
	if c.handler == nil {
		return 0, nil, nil, fmt.Errorf("route handler is unavailable")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, nil, err
	}

	req := httptest.NewRequest(http.MethodPost, c.route.PublicMCPPath(), bytes.NewReader(raw)).WithContext(ctx)
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	if c.sessionID != "" {
		req.Header.Set(stdioSessionHeader, c.sessionID)
	}
	if c.authHeader != "" {
		req.Header.Set("Authorization", c.authHeader)
	}
	if c.identity != nil {
		req = req.WithContext(auth.WithIdentity(req.Context(), c.identity))
	}

	rec := httptest.NewRecorder()
	c.handler.ServeHTTP(rec, req)
	return rec.Code, rec.Header(), rec.Body.Bytes(), nil
}

func (c *mcpRouteCaller) close(ctx context.Context) {
	if c.handler == nil || c.sessionID == "" {
		return
	}
	req := httptest.NewRequest(http.MethodDelete, c.route.PublicMCPPath(), nil).WithContext(ctx)
	req.Header.Set(stdioSessionHeader, c.sessionID)
	if c.identity != nil {
		req = req.WithContext(auth.WithIdentity(req.Context(), c.identity))
	}
	rec := httptest.NewRecorder()
	c.handler.ServeHTTP(rec, req)
}

func decodeOpenAPIToolArguments(raw []byte) (map[string]any, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	if nested, ok := payload["arguments"].(map[string]any); ok && len(payload) == 1 {
		return nested, nil
	}
	return payload, nil
}

func mcpToolByOperationID(tools []mcpToolDefinition, operationID string) (mcpToolDefinition, bool) {
	operationIDs := mcpToolOperationIDs(tools)
	for _, tool := range tools {
		if operationIDs[tool.Name] == operationID {
			return tool, true
		}
	}
	return mcpToolDefinition{}, false
}

func mcpToolOperationIDs(tools []mcpToolDefinition) map[string]string {
	used := make(map[string]int, len(tools))
	out := make(map[string]string, len(tools))
	for _, tool := range tools {
		base := mcpToolOperationID(tool.Name)
		used[base]++
		if used[base] == 1 {
			out[tool.Name] = base
			continue
		}
		out[tool.Name] = fmt.Sprintf("%s_%d", base, used[base])
	}
	return out
}

func mcpToolOperationID(name string) string {
	slug := slugIdentifier(name)
	if slug == "" {
		slug = "tool"
	}
	if slug[0] >= '0' && slug[0] <= '9' {
		slug = "tool_" + slug
	}
	return slug
}

func normalizeMCPToolInputSchema(schema map[string]any) map[string]any {
	if len(schema) == 0 {
		return map[string]any{
			"type":                 "object",
			"additionalProperties": true,
		}
	}
	cloned := cloneAnyMap(schema)
	if strings.TrimSpace(stringValue(cloned["type"])) == "" {
		cloned["type"] = "object"
	}
	return cloned
}

func mcpToolResultSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": true,
		"properties": map[string]any{
			"content": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type":                 "object",
					"additionalProperties": true,
				},
			},
			"structuredContent": map[string]any{
				"type":                 "object",
				"additionalProperties": true,
			},
			"isError": map[string]any{"type": "boolean"},
		},
	}
}

func routeScopesAsMap(route config.Route) map[string]string {
	scopes := route.ScopeList()
	out := make(map[string]string, len(scopes))
	for _, scope := range scopes {
		out[scope] = "Access " + route.DisplayName
	}
	return out
}

func openAPISecurityRequirements(route config.Route) []map[string][]string {
	return []map[string][]string{
		{"bearerAuth": {}},
		{"oauth2": route.ScopeList()},
	}
}
