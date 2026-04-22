package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
	"gopkg.in/yaml.v3"
)

const (
	maxOpenAPISpecBytes     = 4 << 20
	maxOpenAPIResponseBytes = 2 << 20
	jsonrpcInvalidParams    = -32602
)

type openAPIBridge struct {
	route            config.Route
	client           *http.Client
	operations       []openAPIOperation
	operationByName  map[string]openAPIOperation
	upstreamBaseURL  *url.URL
	responseByteSize int64
}

type openAPIOperation struct {
	Name        string
	Description string
	Method      string
	Path        string
	InputSchema map[string]any
	Parameters  []openAPIParameter
	RequestBody *openAPIRequestBody
}

type openAPIParameter struct {
	Field       string
	Name        string
	In          string
	Required    bool
	Style       string
	Explode     bool
	ContentType string
	Schema      map[string]any
}

type openAPIRequestBody struct {
	Field       string
	Required    bool
	ContentType string
	Schema      map[string]any
}

func newOpenAPIBridge(route config.Route) (http.Handler, error) {
	if route.OpenAPI == nil {
		return nil, fmt.Errorf("route %q openapi config is required", route.ID)
	}

	timeout := time.Duration(route.OpenAPI.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	raw, err := loadOpenAPISpec(context.Background(), client, *route.OpenAPI)
	if err != nil {
		return nil, fmt.Errorf("load openapi spec for route %q: %w", route.ID, err)
	}

	operations, err := parseOpenAPIOperations(raw)
	if err != nil {
		return nil, fmt.Errorf("parse openapi spec for route %q: %w", route.ID, err)
	}
	if len(operations) == 0 {
		return nil, fmt.Errorf("openapi spec for route %q does not expose any operations", route.ID)
	}

	baseURL, err := url.Parse(route.OpenAPI.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse openapi base_url for route %q: %w", route.ID, err)
	}

	byName := make(map[string]openAPIOperation, len(operations))
	for _, operation := range operations {
		byName[operation.Name] = operation
	}

	return &openAPIBridge{
		route:            route,
		client:           client,
		operations:       operations,
		operationByName:  byName,
		upstreamBaseURL:  baseURL,
		responseByteSize: maxOpenAPIResponseBytes,
	}, nil
}

func loadOpenAPISpec(ctx context.Context, client *http.Client, cfg config.RouteOpenAPI) ([]byte, error) {
	switch {
	case strings.TrimSpace(cfg.SpecPath) != "":
		payload, err := os.ReadFile(cfg.SpecPath)
		if err != nil {
			return nil, err
		}
		if len(payload) > maxOpenAPISpecBytes {
			return nil, fmt.Errorf("spec is larger than %d bytes", maxOpenAPISpecBytes)
		}
		return payload, nil
	case strings.TrimSpace(cfg.SpecURL) != "":
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.SpecURL, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("spec download failed: %s", resp.Status)
		}
		return readLimited(resp.Body, maxOpenAPISpecBytes)
	default:
		return nil, fmt.Errorf("spec_path or spec_url is required")
	}
}

func (b *openAPIBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != b.route.PublicMCPPath() {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodPost:
		b.handlePost(w, r)
	case http.MethodGet:
		b.handleSSE(w, r)
	case http.MethodDelete:
		w.WriteHeader(http.StatusAccepted)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (b *openAPIBridge) handlePost(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxStdioBridgeBodyBytes))
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
			"error":             "request_too_large",
			"error_description": err.Error(),
		})
		return
	}

	messages, batch, err := parseJSONRPCMessages(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_jsonrpc",
			"error_description": err.Error(),
		})
		return
	}

	responses := make([]json.RawMessage, 0, len(messages))
	for _, message := range messages {
		id, hasID := jsonRPCID(message)
		if !hasID {
			continue
		}
		responses = append(responses, b.handleJSONRPCRequest(r.Context(), id, message))
	}

	if len(responses) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if batch {
		_, _ = w.Write(mustMarshalRawArray(responses))
		return
	}
	_, _ = w.Write(responses[0])
}

func (b *openAPIBridge) handleSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	ticker := time.NewTicker(stdioSSEHeartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			_, _ = io.WriteString(w, ": keepalive\n\n")
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}

func (b *openAPIBridge) handleJSONRPCRequest(ctx context.Context, id string, raw []byte) json.RawMessage {
	var request struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(raw, &request); err != nil {
		return buildJSONRPCError(id, jsonrpcInvalidErrorCode, "invalid jsonrpc request")
	}

	switch request.Method {
	case "initialize":
		return buildJSONRPCResult(id, map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities": map[string]any{
				"tools": map[string]any{"listChanged": false},
			},
			"serverInfo": map[string]any{
				"name":    "mcp-oauth-gateway-openapi-" + b.route.ID,
				"version": "dev",
			},
		})
	case "ping":
		return buildJSONRPCResult(id, map[string]any{})
	case "tools/list":
		tools := make([]map[string]any, 0, len(b.operations))
		for _, operation := range b.operations {
			tools = append(tools, map[string]any{
				"name":        operation.Name,
				"description": operation.Description,
				"inputSchema": operation.InputSchema,
			})
		}
		return buildJSONRPCResult(id, map[string]any{"tools": tools})
	case "tools/call":
		result, err := b.callTool(ctx, request.Params)
		if err != nil {
			return buildJSONRPCError(id, jsonrpcInvalidParams, err.Error())
		}
		return buildJSONRPCResult(id, result)
	default:
		return buildJSONRPCError(id, jsonrpcMethodNotFound, "method not found")
	}
}

func (b *openAPIBridge) callTool(ctx context.Context, rawParams json.RawMessage) (map[string]any, error) {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(rawParams, &params); err != nil {
		return nil, fmt.Errorf("invalid tools/call params")
	}
	params.Name = strings.TrimSpace(params.Name)
	if params.Name == "" {
		return nil, fmt.Errorf("tool name is required")
	}
	operation, ok := b.operationByName[params.Name]
	if !ok {
		return nil, fmt.Errorf("unknown tool %q", params.Name)
	}
	if params.Arguments == nil {
		params.Arguments = map[string]any{}
	}

	req, err := b.buildHTTPRequest(ctx, operation, params.Arguments)
	if err != nil {
		return nil, err
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openapi upstream request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, b.responseByteSize+1))
	if err != nil {
		return nil, err
	}
	truncated := int64(len(body)) > b.responseByteSize
	if truncated {
		body = body[:b.responseByteSize]
	}

	text := openAPIResponseText(operation, resp, body, truncated)
	result := map[string]any{
		"content": []map[string]any{
			{
				"type": "text",
				"text": text,
			},
		},
	}
	if resp.StatusCode >= 400 {
		result["isError"] = true
	}
	if structured, ok := parseMaybeJSON(resp.Header.Get("Content-Type"), body); ok && !truncated {
		result["structuredContent"] = structured
	}
	return result, nil
}

func (b *openAPIBridge) buildHTTPRequest(ctx context.Context, operation openAPIOperation, arguments map[string]any) (*http.Request, error) {
	pathValue := operation.Path
	for _, parameter := range operation.Parameters {
		if parameter.In != "path" {
			continue
		}
		value, ok := arguments[parameter.Field]
		if !ok {
			return nil, fmt.Errorf("path parameter %q is required", parameter.Field)
		}
		pathValue = strings.ReplaceAll(pathValue, "{"+parameter.Name+"}", url.PathEscape(valueToString(value)))
	}

	upstreamURL := *b.upstreamBaseURL
	upstreamURL.Path = joinURLPath(upstreamURL.Path, pathValue)
	query := upstreamURL.Query()
	queryStringOverride := ""
	headers := make(http.Header)
	cookies := []http.Cookie{}
	var bodyReader io.Reader = http.NoBody

	for key, value := range b.route.OpenAPI.Headers {
		if strings.TrimSpace(value) != "" {
			headers.Set(key, value)
		}
	}

	if identity := auth.IdentityFromContext(ctx); identity != nil {
		for headerName, templateValue := range b.route.HeaderTemplates() {
			value := expandHeaderTemplate(templateValue, b.route, identity)
			if strings.TrimSpace(value) != "" {
				headers.Set(headerName, value)
			}
		}
	}

	for _, parameter := range operation.Parameters {
		if parameter.In == "path" {
			continue
		}
		value, ok := arguments[parameter.Field]
		if !ok || value == nil {
			if parameter.Required {
				return nil, fmt.Errorf("%s parameter %q is required", parameter.In, parameter.Field)
			}
			continue
		}
		switch parameter.In {
		case "query":
			addOpenAPIQueryValues(query, parameter, value)
		case "querystring":
			encoded, err := encodeOpenAPIQueryString(parameter, value)
			if err != nil {
				return nil, err
			}
			queryStringOverride = encoded
		case "header":
			headers.Set(parameter.Name, serializeOpenAPIParameterValue(parameter, value))
		case "cookie":
			cookies = append(cookies, http.Cookie{
				Name:  parameter.Name,
				Value: serializeOpenAPIParameterValue(parameter, value),
			})
		}
	}
	if queryStringOverride != "" {
		upstreamURL.RawQuery = queryStringOverride
	} else {
		upstreamURL.RawQuery = query.Encode()
	}

	if operation.RequestBody != nil {
		value, exists := arguments[operation.RequestBody.Field]
		if !exists || value == nil {
			if operation.RequestBody.Required {
				return nil, fmt.Errorf("request body %q is required", operation.RequestBody.Field)
			}
		} else {
			payload, contentType, err := marshalOpenAPIRequestBody(value, operation.RequestBody.ContentType)
			if err != nil {
				return nil, err
			}
			bodyReader = bytes.NewReader(payload)
			headers.Set("Content-Type", contentType)
		}
	}

	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(operation.Method), upstreamURL.String(), bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header = headers
	req.Header.Set("Accept", "application/json, text/plain;q=0.9, */*;q=0.8")
	for _, cookie := range cookies {
		req.AddCookie(&cookie)
	}
	return req, nil
}

func marshalOpenAPIRequestBody(value any, contentType string) ([]byte, string, error) {
	contentType = strings.TrimSpace(contentType)
	if contentType == "" {
		contentType = "application/json"
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = contentType
	}
	if mediaType == "text/plain" {
		return []byte(valueToString(value)), contentType, nil
	}
	if mediaType == "application/x-www-form-urlencoded" {
		return []byte(encodeFormValues(value).Encode()), contentType, nil
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, "", fmt.Errorf("request body must be JSON serializable")
	}
	return payload, contentType, nil
}

func addOpenAPIQueryValues(query url.Values, parameter openAPIParameter, value any) {
	switch strings.ToLower(parameter.Style) {
	case "spacedelimited":
		query.Add(parameter.Name, strings.Join(valueToStrings(value), " "))
	case "pipedelimited":
		query.Add(parameter.Name, strings.Join(valueToStrings(value), "|"))
	case "deepobject":
		for key, item := range valueToMap(value) {
			query.Add(parameter.Name+"["+key+"]", valueToString(item))
		}
	default:
		if parameter.Explode {
			for key, item := range valueToMap(value) {
				query.Add(key, valueToString(item))
			}
			if len(valueToMap(value)) != 0 {
				return
			}
			for _, part := range valueToStrings(value) {
				query.Add(parameter.Name, part)
			}
			return
		}
		query.Add(parameter.Name, strings.Join(valueToStrings(value), ","))
	}
}

func encodeOpenAPIQueryString(parameter openAPIParameter, value any) (string, error) {
	if text, ok := value.(string); ok {
		return strings.TrimPrefix(text, "?"), nil
	}
	if parameter.ContentType != "" {
		mediaType, _, err := mime.ParseMediaType(parameter.ContentType)
		if err == nil && mediaType != "application/x-www-form-urlencoded" {
			return "", fmt.Errorf("querystring parameter %q only supports application/x-www-form-urlencoded or raw string", parameter.Field)
		}
	}
	return encodeFormValues(value).Encode(), nil
}

func serializeOpenAPIParameterValue(parameter openAPIParameter, value any) string {
	if strings.EqualFold(parameter.Style, "simple") {
		return strings.Join(valueToStrings(value), ",")
	}
	return strings.Join(valueToStrings(value), ",")
}

func encodeFormValues(value any) url.Values {
	out := url.Values{}
	for key, item := range valueToMap(value) {
		for _, part := range valueToStrings(item) {
			out.Add(key, part)
		}
	}
	if len(out) != 0 {
		return out
	}
	out.Set("value", valueToString(value))
	return out
}

func openAPIResponseText(operation openAPIOperation, resp *http.Response, body []byte, truncated bool) string {
	var builder strings.Builder
	builder.WriteString(strings.ToUpper(operation.Method))
	builder.WriteByte(' ')
	builder.WriteString(operation.Path)
	builder.WriteString(" -> ")
	builder.WriteString(resp.Status)
	if contentType := strings.TrimSpace(resp.Header.Get("Content-Type")); contentType != "" {
		builder.WriteString("\nContent-Type: ")
		builder.WriteString(contentType)
	}
	if len(body) != 0 {
		builder.WriteString("\n\n")
		builder.Write(bytes.TrimSpace(body))
	}
	if truncated {
		builder.WriteString("\n\n[response truncated by gateway]")
	}
	return builder.String()
}

func parseMaybeJSON(contentType string, body []byte) (any, bool) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = contentType
	}
	if mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json") {
		return nil, false
	}
	var parsed any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, false
	}
	return parsed, true
}

func parseOpenAPIOperations(raw []byte) ([]openAPIOperation, error) {
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	version := strings.TrimSpace(stringValue(document["openapi"]))
	if version == "" || !strings.HasPrefix(version, "3.") {
		return nil, fmt.Errorf("only OpenAPI 3.x documents are supported")
	}

	paths := asStringMap(document["paths"])
	if len(paths) == 0 {
		return nil, fmt.Errorf("paths is required")
	}

	pathKeys := make([]string, 0, len(paths))
	for pathKey := range paths {
		pathKeys = append(pathKeys, pathKey)
	}
	sort.Strings(pathKeys)

	methods := []string{"get", "post", "put", "patch", "delete", "options", "head"}
	usedNames := map[string]int{}
	operations := make([]openAPIOperation, 0)
	for _, pathKey := range pathKeys {
		pathItem := asStringMap(paths[pathKey])
		if len(pathItem) == 0 {
			continue
		}
		pathParameters := parseOpenAPIParameters(document, pathItem["parameters"])
		for _, method := range methods {
			operationMap := resolveOpenAPIMap(document, pathItem[method])
			if len(operationMap) == 0 {
				continue
			}
			parameters := append([]openAPIParameter(nil), pathParameters...)
			parameters = append(parameters, parseOpenAPIParameters(document, operationMap["parameters"])...)
			parameters = dedupeOpenAPIParameters(parameters)
			parameters = assignOpenAPIParameterFields(parameters)

			requestBody := parseOpenAPIRequestBody(document, operationMap["requestBody"])
			name := uniqueOpenAPIOperationName(operationMap, method, pathKey, usedNames)
			operations = append(operations, openAPIOperation{
				Name:        name,
				Description: openAPIOperationDescription(operationMap, method, pathKey),
				Method:      method,
				Path:        pathKey,
				InputSchema: buildOpenAPIInputSchema(parameters, requestBody),
				Parameters:  parameters,
				RequestBody: requestBody,
			})
		}
	}
	return operations, nil
}

func parseOpenAPIParameters(root map[string]any, raw any) []openAPIParameter {
	values, ok := raw.([]any)
	if !ok {
		return nil
	}
	parameters := make([]openAPIParameter, 0, len(values))
	for _, value := range values {
		paramMap := resolveOpenAPIMap(root, value)
		name := strings.TrimSpace(stringValue(paramMap["name"]))
		location := strings.ToLower(strings.TrimSpace(stringValue(paramMap["in"])))
		if name == "" || !slices.Contains([]string{"path", "query", "querystring", "header", "cookie"}, location) {
			continue
		}
		if location == "header" && slices.Contains([]string{"accept", "content-type", "authorization"}, strings.ToLower(name)) {
			continue
		}
		required := boolValue(paramMap["required"])
		if location == "path" {
			required = true
		}
		style := strings.TrimSpace(stringValue(paramMap["style"]))
		if style == "" {
			style = defaultOpenAPIParameterStyle(location)
		}
		explode := boolValueWithDefault(paramMap, "explode", style == "form")
		schema, contentType := openAPIParameterSchema(root, paramMap)
		parameters = append(parameters, openAPIParameter{
			Name:        name,
			In:          location,
			Required:    required,
			Style:       style,
			Explode:     explode,
			ContentType: contentType,
			Schema:      schema,
		})
	}
	return parameters
}

func dedupeOpenAPIParameters(parameters []openAPIParameter) []openAPIParameter {
	out := make([]openAPIParameter, 0, len(parameters))
	seen := map[string]int{}
	for _, parameter := range parameters {
		key := strings.ToLower(parameter.In) + "\x00" + parameter.Name
		if idx, exists := seen[key]; exists {
			out[idx] = parameter
			continue
		}
		seen[key] = len(out)
		out = append(out, parameter)
	}
	return out
}

func assignOpenAPIParameterFields(parameters []openAPIParameter) []openAPIParameter {
	counts := map[string]int{}
	for _, parameter := range parameters {
		counts[parameter.Name]++
	}
	for idx := range parameters {
		field := parameters[idx].Name
		if counts[field] > 1 {
			field = parameters[idx].In + "_" + field
		}
		parameters[idx].Field = field
	}
	return parameters
}

func defaultOpenAPIParameterStyle(location string) string {
	switch location {
	case "query", "querystring", "cookie":
		return "form"
	default:
		return "simple"
	}
}

func openAPIParameterSchema(root map[string]any, paramMap map[string]any) (map[string]any, string) {
	if _, ok := paramMap["schema"]; ok {
		return openAPISchema(root, paramMap["schema"], 0), ""
	}
	content := asStringMap(paramMap["content"])
	if len(content) == 0 {
		return map[string]any{"type": "string"}, ""
	}
	contentType := preferredOpenAPIContentType(content)
	mediaMap := asStringMap(content[contentType])
	return openAPISchema(root, mediaMap["schema"], 0), contentType
}

func parseOpenAPIRequestBody(root map[string]any, raw any) *openAPIRequestBody {
	bodyMap := resolveOpenAPIMap(root, raw)
	if len(bodyMap) == 0 {
		return nil
	}
	content := asStringMap(bodyMap["content"])
	if len(content) == 0 {
		return &openAPIRequestBody{
			Field:       "body",
			Required:    boolValue(bodyMap["required"]),
			ContentType: "application/json",
			Schema:      map[string]any{"type": "object"},
		}
	}

	contentType := preferredOpenAPIContentType(content)
	mediaMap := asStringMap(content[contentType])
	return &openAPIRequestBody{
		Field:       "body",
		Required:    boolValue(bodyMap["required"]),
		ContentType: contentType,
		Schema:      openAPISchema(root, mediaMap["schema"], 0),
	}
}

func preferredOpenAPIContentType(content map[string]any) string {
	if _, ok := content["application/json"]; ok {
		return "application/json"
	}
	keys := make([]string, 0, len(content))
	for key := range content {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		mediaType, _, err := mime.ParseMediaType(key)
		if err == nil && strings.HasSuffix(mediaType, "+json") {
			return key
		}
	}
	if len(keys) == 0 {
		return "application/json"
	}
	return keys[0]
}

func buildOpenAPIInputSchema(parameters []openAPIParameter, requestBody *openAPIRequestBody) map[string]any {
	properties := map[string]any{}
	required := []string{}
	for _, parameter := range parameters {
		schema := cloneAnyMap(parameter.Schema)
		if _, ok := schema["description"]; !ok {
			schema["description"] = parameter.In + " parameter " + parameter.Name
		}
		properties[parameter.Field] = schema
		if parameter.Required {
			required = append(required, parameter.Field)
		}
	}
	if requestBody != nil {
		field := requestBody.Field
		if _, exists := properties[field]; exists {
			field = "request_body"
			requestBody.Field = field
		}
		properties[field] = requestBody.Schema
		if requestBody.Required {
			required = append(required, field)
		}
	}
	schema := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}
	if len(required) != 0 {
		schema["required"] = required
	}
	return schema
}

func openAPIOperationDescription(operation map[string]any, method, pathValue string) string {
	for _, key := range []string{"summary", "description"} {
		if value := strings.TrimSpace(stringValue(operation[key])); value != "" {
			return value
		}
	}
	return strings.ToUpper(method) + " " + pathValue
}

func uniqueOpenAPIOperationName(operation map[string]any, method, pathValue string, used map[string]int) string {
	name := slugIdentifier(strings.TrimSpace(stringValue(operation["operationId"])))
	if name == "" {
		name = slugIdentifier(method + "_" + pathValue)
	}
	if name == "" {
		name = "operation"
	}
	used[name]++
	if used[name] == 1 {
		return name
	}
	return fmt.Sprintf("%s_%d", name, used[name])
}

func openAPISchema(root map[string]any, raw any, depth int) map[string]any {
	if depth > 12 {
		return map[string]any{"type": "object"}
	}
	schemaMap := resolveOpenAPIMap(root, raw)
	if len(schemaMap) == 0 {
		return map[string]any{"type": "string"}
	}
	out := make(map[string]any, len(schemaMap))
	for key, value := range schemaMap {
		if key == "$ref" {
			continue
		}
		switch key {
		case "properties":
			props := asStringMap(value)
			next := make(map[string]any, len(props))
			for propName, propValue := range props {
				next[propName] = openAPISchema(root, propValue, depth+1)
			}
			out[key] = next
		case "items":
			out[key] = openAPISchema(root, value, depth+1)
		case "oneOf", "anyOf", "allOf":
			if values, ok := value.([]any); ok {
				items := make([]any, 0, len(values))
				for _, item := range values {
					items = append(items, openAPISchema(root, item, depth+1))
				}
				out[key] = items
			}
		case "additionalProperties":
			if boolVal, ok := value.(bool); ok {
				out[key] = boolVal
			} else {
				out[key] = openAPISchema(root, value, depth+1)
			}
		default:
			out[key] = jsonCompatibleValue(value)
		}
	}
	if len(out) == 0 {
		return map[string]any{"type": "string"}
	}
	return out
}

func resolveOpenAPIMap(root map[string]any, raw any) map[string]any {
	value := raw
	rawMap := asStringMap(raw)
	if ref := strings.TrimSpace(stringValue(rawMap["$ref"])); ref != "" {
		if resolved, ok := resolveOpenAPIRef(root, ref); ok {
			value = resolved
		}
	}
	resolved := asStringMap(value)
	if len(rawMap) > 1 && strings.TrimSpace(stringValue(rawMap["$ref"])) != "" {
		merged := make(map[string]any, len(resolved)+len(rawMap)-1)
		for key, value := range resolved {
			merged[key] = value
		}
		for key, value := range rawMap {
			if key != "$ref" {
				merged[key] = value
			}
		}
		return merged
	}
	return resolved
}

func resolveOpenAPIRef(root map[string]any, ref string) (any, bool) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, false
	}
	current := any(root)
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		currentMap := asStringMap(current)
		if len(currentMap) == 0 {
			return nil, false
		}
		next, ok := currentMap[part]
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}

func asStringMap(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	default:
		return nil
	}
}

func jsonCompatibleValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			out[key] = jsonCompatibleValue(value)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for idx, value := range typed {
			out[idx] = jsonCompatibleValue(value)
		}
		return out
	default:
		return typed
	}
}

func cloneAnyMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(values))
	for key, value := range values {
		cloned[key] = jsonCompatibleValue(value)
	}
	return cloned
}

func valueToString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		payload, err := json.Marshal(typed)
		if err == nil {
			var scalar string
			if json.Unmarshal(payload, &scalar) == nil {
				return scalar
			}
		}
		return strings.Trim(string(mustMarshalJSON(typed)), `"`)
	}
}

func valueToStrings(value any) []string {
	switch typed := value.(type) {
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, valueToString(item))
		}
		return out
	case []string:
		return append([]string(nil), typed...)
	default:
		return []string{valueToString(value)}
	}
}

func valueToMap(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case map[string]string:
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			out[key] = value
		}
		return out
	default:
		return nil
	}
}

func boolValue(value any) bool {
	typed, _ := value.(bool)
	return typed
}

func boolValueWithDefault(values map[string]any, key string, fallback bool) bool {
	value, ok := values[key]
	if !ok {
		return fallback
	}
	typed, ok := value.(bool)
	if !ok {
		return fallback
	}
	return typed
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		if typed == nil {
			return ""
		}
		return fmt.Sprint(typed)
	}
}

func slugIdentifier(value string) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	lastUnderscore := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			builder.WriteRune(r)
			lastUnderscore = false
		default:
			if !lastUnderscore && builder.Len() > 0 {
				builder.WriteByte('_')
				lastUnderscore = true
			}
		}
	}
	return strings.Trim(builder.String(), "_")
}

func mustMarshalJSON(value any) []byte {
	payload, err := json.Marshal(value)
	if err != nil {
		return []byte(fmt.Sprint(value))
	}
	return payload
}

func buildJSONRPCResult(id string, result any) []byte {
	idRaw := json.RawMessage(id)
	payload := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  any             `json:"result"`
	}{
		JSONRPC: "2.0",
		ID:      idRaw,
		Result:  result,
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return buildJSONRPCError(id, jsonrpcInternalErrorCode, "internal bridge error")
	}
	return out
}
