package gateway

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

type dashboardData struct {
	Title             string
	AdminEmail        string
	Notice            string
	Error             string
	CSRFToken         string
	PublicBaseURL     string
	RoutesPath        string
	SelfSignupEnabled bool
	Routes            []dashboardRouteView
	Users             []dashboardUserView
	SelectedRoute     routeFormData
}

type dashboardRouteView struct {
	ID                       string
	DisplayName              string
	PathPrefix               string
	PublicMCPURL             string
	ProtectedMetadataURL     string
	Upstream                 string
	UpstreamMCPPath          string
	MCPHTTPSessionMode       string
	PassAuthorization        bool
	ForwardHeadersCount      int
	UpstreamEnvironmentCount int
}

type dashboardUserView struct {
	ID        string
	Email     string
	IsAdmin   bool
	CreatedAt string
	UpdatedAt string
}

type routeFormData struct {
	OriginalID            string
	ID                    string
	DisplayName           string
	PathPrefix            string
	Upstream              string
	UpstreamMCPPath       string
	ScopesSupported       string
	PassAuthorization     bool
	ResourceDocumentation string
	MCPHTTPSessionMode    string
	ForwardHeaders        string
	UpstreamEnvironment   string
	Notes                 string
}

func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}

	selected := routeFormData{UpstreamMCPPath: "/mcp"}
	if routeID := strings.TrimSpace(r.URL.Query().Get("route")); routeID != "" {
		if route, found := s.routeByID(routeID); found {
			selected = newRouteFormData(route, routeID)
		}
	}

	s.renderAdminDashboard(w, r, identity, selected, strings.TrimSpace(r.URL.Query().Get("notice")), strings.TrimSpace(r.URL.Query().Get("error")), http.StatusOK)
}

func (s *Server) handleAdminRouteSave(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	formData, route, err := parseRouteForm(r)
	if err != nil {
		s.renderAdminDashboard(w, r, identity, formData, "", err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.upsertRoute(formData.OriginalID, route); err != nil {
		s.renderAdminDashboard(w, r, identity, formData, "", err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, adminRedirectURL(route.ID, "Route saved successfully", ""), http.StatusFound)
}

func (s *Server) handleAdminRouteDelete(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	routeID := strings.TrimSpace(r.FormValue("route_id"))
	if routeID == "" {
		s.renderAdminDashboard(w, r, identity, routeFormData{UpstreamMCPPath: "/mcp"}, "", "route_id is required", http.StatusBadRequest)
		return
	}
	if err := s.deleteRoute(routeID); err != nil {
		form := routeFormData{OriginalID: routeID, ID: routeID, UpstreamMCPPath: "/mcp"}
		if route, found := s.routeByID(routeID); found {
			form = newRouteFormData(route, routeID)
		}
		s.renderAdminDashboard(w, r, identity, form, "", err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, adminRedirectURL("", "Route deleted successfully", ""), http.StatusFound)
}

func (s *Server) handleAdminUserCreate(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	_, err := s.authManager.CreateUser(strings.TrimSpace(r.FormValue("email")), r.FormValue("password"), formCheckbox(r, "is_admin"))
	if err != nil {
		s.renderAdminDashboard(w, r, identity, routeFormData{UpstreamMCPPath: "/mcp"}, "", err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, adminRedirectURL("", "User created successfully", ""), http.StatusFound)
}

func (s *Server) handleAdminUserPassword(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	if err := s.authManager.SetUserPassword(strings.TrimSpace(r.FormValue("user_id")), r.FormValue("password")); err != nil {
		s.renderAdminDashboard(w, r, identity, routeFormData{UpstreamMCPPath: "/mcp"}, "", err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, adminRedirectURL("", "User password updated", ""), http.StatusFound)
}

func (s *Server) handleAdminUserDelete(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	if err := s.authManager.DeleteUser(strings.TrimSpace(r.FormValue("user_id"))); err != nil {
		s.renderAdminDashboard(w, r, identity, routeFormData{UpstreamMCPPath: "/mcp"}, "", err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, adminRedirectURL("", "User deleted successfully", ""), http.StatusFound)
}

func (s *Server) handleAdminUserAdmin(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	targetAdmin := formCheckbox(r, "is_admin")
	if err := s.authManager.SetUserAdmin(strings.TrimSpace(r.FormValue("user_id")), targetAdmin); err != nil {
		s.renderAdminDashboard(w, r, identity, routeFormData{UpstreamMCPPath: "/mcp"}, "", err.Error(), http.StatusBadRequest)
		return
	}

	label := "User role updated"
	http.Redirect(w, r, adminRedirectURL("", label, ""), http.StatusFound)
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (*auth.Identity, bool) {
	identity, err := s.authManager.CurrentIdentity(r)
	if err != nil {
		http.Redirect(w, r, "/account/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return nil, false
	}
	if !identity.IsAdmin {
		http.Error(w, "admin access required", http.StatusForbidden)
		return nil, false
	}
	return identity, true
}

func (s *Server) renderAdminDashboard(w http.ResponseWriter, r *http.Request, identity *auth.Identity, selected routeFormData, notice, errText string, status int) {
	csrfToken := s.authManager.EnsureCSRFToken(w, r)
	routes := s.routesSnapshot()
	slices.SortFunc(routes, func(a, b config.Route) int {
		switch {
		case a.NormalizedPathPrefix < b.NormalizedPathPrefix:
			return -1
		case a.NormalizedPathPrefix > b.NormalizedPathPrefix:
			return 1
		default:
			return 0
		}
	})

	users := s.authManager.ListUsers()
	userViews := make([]dashboardUserView, 0, len(users))
	for _, user := range users {
		userViews = append(userViews, dashboardUserView{
			ID:        user.ID,
			Email:     user.Email,
			IsAdmin:   user.IsAdmin,
			CreatedAt: user.CreatedAt.Format("2006-01-02 15:04"),
			UpdatedAt: user.UpdatedAt.Format("2006-01-02 15:04"),
		})
	}

	routeViews := make([]dashboardRouteView, 0, len(routes))
	for _, route := range routes {
		routeViews = append(routeViews, dashboardRouteView{
			ID:                       route.ID,
			DisplayName:              route.DisplayName,
			PathPrefix:               route.NormalizedPathPrefix,
			PublicMCPURL:             s.absoluteURL(route.PublicMCPPath()),
			ProtectedMetadataURL:     s.absoluteURL(route.ProtectedResourceMetadataPath()),
			Upstream:                 route.Upstream,
			UpstreamMCPPath:          route.NormalizedUpstreamPath,
			MCPHTTPSessionMode:       strings.TrimSpace(route.UpstreamEnvironment["MCP_HTTP_SESSION_MODE"]),
			PassAuthorization:        route.PassAuthorization,
			ForwardHeadersCount:      len(route.ForwardHeaders),
			UpstreamEnvironmentCount: countNonSessionEnv(route.UpstreamEnvironment),
		})
	}

	if selected.UpstreamMCPPath == "" {
		selected.UpstreamMCPPath = "/mcp"
	}

	data := dashboardData{
		Title:             s.cfg.AccountPortalTitle + " Admin",
		AdminEmail:        identity.Email,
		Notice:            notice,
		Error:             errText,
		CSRFToken:         csrfToken,
		PublicBaseURL:     s.cfg.PublicBaseURL,
		RoutesPath:        s.cfg.RoutesPath,
		SelfSignupEnabled: s.cfg.AllowSelfSignup,
		Routes:            routeViews,
		Users:             userViews,
		SelectedRoute:     selected,
	}

	renderAdminHTML(w, status, data)
}

func parseRouteForm(r *http.Request) (routeFormData, config.Route, error) {
	formData := routeFormData{
		OriginalID:            strings.TrimSpace(r.FormValue("original_id")),
		ID:                    strings.TrimSpace(r.FormValue("id")),
		DisplayName:           strings.TrimSpace(r.FormValue("display_name")),
		PathPrefix:            strings.TrimSpace(r.FormValue("path_prefix")),
		Upstream:              strings.TrimSpace(r.FormValue("upstream")),
		UpstreamMCPPath:       strings.TrimSpace(r.FormValue("upstream_mcp_path")),
		ScopesSupported:       strings.TrimSpace(r.FormValue("scopes_supported")),
		PassAuthorization:     formCheckbox(r, "pass_authorization_header"),
		ResourceDocumentation: strings.TrimSpace(r.FormValue("resource_documentation")),
		MCPHTTPSessionMode:    strings.TrimSpace(r.FormValue("mcp_http_session_mode")),
		ForwardHeaders:        normalizeMultiline(r.FormValue("forward_headers")),
		UpstreamEnvironment:   normalizeMultiline(r.FormValue("upstream_environment")),
		Notes:                 strings.TrimSpace(r.FormValue("notes")),
	}

	forwardHeaders, err := parseMapTextarea(formData.ForwardHeaders, "header")
	if err != nil {
		return formData, config.Route{}, err
	}
	upstreamEnvironment, err := parseMapTextarea(formData.UpstreamEnvironment, "env")
	if err != nil {
		return formData, config.Route{}, err
	}
	if formData.MCPHTTPSessionMode != "" {
		if upstreamEnvironment == nil {
			upstreamEnvironment = map[string]string{}
		}
		upstreamEnvironment["MCP_HTTP_SESSION_MODE"] = formData.MCPHTTPSessionMode
	}

	route := config.Route{
		ID:                    formData.ID,
		DisplayName:           formData.DisplayName,
		PathPrefix:            formData.PathPrefix,
		Upstream:              formData.Upstream,
		UpstreamMCPPath:       defaultIfEmpty(formData.UpstreamMCPPath, "/mcp"),
		ScopesSupported:       parseCommaList(formData.ScopesSupported),
		PassAuthorization:     formData.PassAuthorization,
		ForwardHeaders:        forwardHeaders,
		UpstreamEnvironment:   upstreamEnvironment,
		ResourceDocumentation: formData.ResourceDocumentation,
		Notes:                 formData.Notes,
	}

	return formData, route, nil
}

func newRouteFormData(route config.Route, originalID string) routeFormData {
	environment := mapToLines(route.UpstreamEnvironment, "env", "MCP_HTTP_SESSION_MODE")
	return routeFormData{
		OriginalID:            originalID,
		ID:                    route.ID,
		DisplayName:           route.DisplayName,
		PathPrefix:            route.NormalizedPathPrefix,
		Upstream:              route.Upstream,
		UpstreamMCPPath:       route.NormalizedUpstreamPath,
		ScopesSupported:       strings.Join(route.ScopesSupported, ", "),
		PassAuthorization:     route.PassAuthorization,
		ResourceDocumentation: route.ResourceDocumentation,
		MCPHTTPSessionMode:    strings.TrimSpace(route.UpstreamEnvironment["MCP_HTTP_SESSION_MODE"]),
		ForwardHeaders:        mapToLines(route.ForwardHeaders, "header"),
		UpstreamEnvironment:   environment,
		Notes:                 route.Notes,
	}
}

func parseMapTextarea(raw string, mode string) (map[string]string, error) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	values := make(map[string]string)
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		key, value, ok := splitKeyValueLine(line, mode)
		if !ok {
			return nil, fmt.Errorf("invalid %s entry on line %d", mode, idx+1)
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if len(values) == 0 {
		return nil, nil
	}
	return values, nil
}

func splitKeyValueLine(line, mode string) (string, string, bool) {
	if mode == "env" {
		if key, value, ok := strings.Cut(line, "="); ok && strings.TrimSpace(key) != "" {
			return key, value, true
		}
	}
	if key, value, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(key) != "" {
		return key, value, true
	}
	if mode == "header" {
		if key, value, ok := strings.Cut(line, "="); ok && strings.TrimSpace(key) != "" {
			return key, value, true
		}
	}
	return "", "", false
}

func parseCommaList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func mapToLines(values map[string]string, mode string, ignoredKeys ...string) string {
	if len(values) == 0 {
		return ""
	}
	ignored := make(map[string]struct{}, len(ignoredKeys))
	for _, key := range ignoredKeys {
		ignored[key] = struct{}{}
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		if _, skip := ignored[key]; skip {
			continue
		}
		keys = append(keys, key)
	}
	slices.Sort(keys)

	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		separator := ": "
		if mode == "env" {
			separator = "="
		}
		lines = append(lines, key+separator+values[key])
	}
	return strings.Join(lines, "\n")
}

func formCheckbox(r *http.Request, field string) bool {
	value := strings.ToLower(strings.TrimSpace(r.FormValue(field)))
	return value == "on" || value == "true" || value == "1" || value == "yes"
}

func normalizeMultiline(raw string) string {
	return strings.TrimSpace(strings.ReplaceAll(raw, "\r\n", "\n"))
}

func defaultIfEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func adminRedirectURL(routeID, notice, errText string) string {
	query := url.Values{}
	if routeID != "" {
		query.Set("route", routeID)
	}
	if notice != "" {
		query.Set("notice", notice)
	}
	if errText != "" {
		query.Set("error", errText)
	}
	if encoded := query.Encode(); encoded != "" {
		return "/admin?" + encoded
	}
	return "/admin"
}

func countNonSessionEnv(values map[string]string) int {
	count := 0
	for key := range values {
		if key == "MCP_HTTP_SESSION_MODE" {
			continue
		}
		count++
	}
	return count
}

func renderAdminHTML(w http.ResponseWriter, status int, data dashboardData) {
	t := template.Must(template.New("admin").Parse(adminDashboardTemplate))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_ = t.Execute(w, data)
}

const adminDashboardTemplate = `
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f4f7fb;
      --card: #ffffff;
      --border: #dbe3ef;
      --ink: #112033;
      --muted: #5d6a7b;
      --accent: #123f73;
      --accent-soft: #e9f1fb;
      --danger: #8c1d1d;
      --success: #14623d;
      font-family: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background:
        radial-gradient(circle at top left, rgba(18,63,115,0.08), transparent 32%),
        linear-gradient(180deg, #f8fbff 0%, var(--bg) 100%);
      color: var(--ink);
    }
    main {
      max-width: 76rem;
      margin: 0 auto;
      padding: 2rem 1rem 3rem;
    }
    header {
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      align-items: flex-start;
      margin-bottom: 1.5rem;
    }
    h1, h2, h3 { margin: 0; }
    h1 { font-size: 2rem; }
    h2 { font-size: 1.15rem; margin-bottom: 0.75rem; }
    h3 { font-size: 0.95rem; }
    p { margin: 0; }
    .muted { color: var(--muted); }
    .pill {
      display: inline-block;
      background: var(--accent-soft);
      color: var(--accent);
      border-radius: 999px;
      padding: 0.25rem 0.65rem;
      font-size: 0.82rem;
      font-weight: 700;
    }
    .top-actions {
      display: flex;
      gap: 0.75rem;
      align-items: center;
      flex-wrap: wrap;
    }
    .link-button, button {
      appearance: none;
      border: none;
      background: var(--accent);
      color: white;
      border-radius: 12px;
      padding: 0.75rem 1rem;
      font: inherit;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }
    button.secondary, .link-button.secondary {
      background: #ecf1f8;
      color: var(--ink);
    }
    button.danger {
      background: #8c1d1d;
    }
    .notice, .error {
      margin-bottom: 1rem;
      padding: 0.9rem 1rem;
      border-radius: 14px;
      border: 1px solid var(--border);
    }
    .notice {
      background: #edf8f1;
      color: var(--success);
      border-color: #b7e1c6;
    }
    .error {
      background: #fff0f0;
      color: var(--danger);
      border-color: #f0c3c3;
    }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
      gap: 1rem;
      margin-bottom: 1rem;
    }
    .summary-card, section {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 18px;
      box-shadow: 0 18px 45px rgba(18,32,51,0.06);
    }
    .summary-card {
      padding: 1rem 1.1rem;
    }
    .summary-card strong {
      display: block;
      font-size: 1.4rem;
      margin-top: 0.4rem;
    }
    .grid {
      display: grid;
      grid-template-columns: 1.15fr 1fr;
      gap: 1rem;
      align-items: start;
    }
    section {
      padding: 1rem 1.1rem;
    }
    .route-list {
      display: grid;
      gap: 0.85rem;
    }
    .route-card {
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 0.95rem;
      background: linear-gradient(180deg, #fff, #f9fbfe);
    }
    .route-meta, .user-meta {
      display: grid;
      gap: 0.2rem;
      margin-top: 0.5rem;
      font-size: 0.92rem;
    }
    .route-actions, .inline-actions {
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
      margin-top: 0.85rem;
    }
    label {
      display: block;
      font-size: 0.9rem;
      font-weight: 700;
      margin-bottom: 0.35rem;
    }
    input[type="text"], input[type="url"], input[type="email"], input[type="password"], textarea {
      width: 100%;
      border: 1px solid #c6d1df;
      border-radius: 12px;
      padding: 0.75rem 0.85rem;
      font: inherit;
      background: #fff;
      color: var(--ink);
    }
    textarea {
      min-height: 7.5rem;
      resize: vertical;
      font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
      font-size: 0.9rem;
    }
    .field-grid {
      display: grid;
      gap: 0.85rem;
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    .full {
      grid-column: 1 / -1;
    }
    .checkbox {
      display: flex;
      gap: 0.6rem;
      align-items: center;
      border: 1px dashed #cad5e4;
      border-radius: 14px;
      padding: 0.8rem 0.9rem;
      background: #fbfdff;
    }
    .checkbox input {
      width: auto;
      margin: 0;
    }
    .form-actions {
      display: flex;
      gap: 0.6rem;
      flex-wrap: wrap;
      margin-top: 1rem;
    }
    .users {
      display: grid;
      gap: 0.8rem;
    }
    .user-card {
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 0.95rem;
      background: #fff;
    }
    .small-form {
      display: grid;
      gap: 0.5rem;
      margin-top: 0.85rem;
    }
    code {
      background: #f0f4f9;
      padding: 0.12rem 0.35rem;
      border-radius: 6px;
      word-break: break-all;
    }
    .helper {
      font-size: 0.88rem;
      color: var(--muted);
      margin-top: 0.35rem;
    }
    @media (max-width: 980px) {
      .grid { grid-template-columns: 1fr; }
      .field-grid { grid-template-columns: 1fr; }
      header { flex-direction: column; }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <span class="pill">Admin Dashboard</span>
        <h1>{{.Title}}</h1>
        <p class="muted">Signed in as <strong>{{.AdminEmail}}</strong>. Manage protected MCP routes, deployment metadata and gateway users from one place.</p>
      </div>
      <div class="top-actions">
        <a class="link-button secondary" href="/account">Account</a>
        <form method="post" action="/account/logout">
          <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
          <button type="submit" class="secondary">Sign out</button>
        </form>
      </div>
    </header>

    {{if .Notice}}<div class="notice">{{.Notice}}</div>{{end}}
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}

    <div class="summary">
      <div class="summary-card">
        <span class="muted">Public Base URL</span>
        <strong>{{.PublicBaseURL}}</strong>
      </div>
      <div class="summary-card">
        <span class="muted">Routes Config File</span>
        <strong>{{.RoutesPath}}</strong>
      </div>
      <div class="summary-card">
        <span class="muted">Self-Signup</span>
        <strong>{{if .SelfSignupEnabled}}Enabled{{else}}Disabled{{end}}</strong>
      </div>
      <div class="summary-card">
        <span class="muted">Managed Routes / Users</span>
        <strong>{{len .Routes}} / {{len .Users}}</strong>
      </div>
    </div>

    <div class="grid">
      <section>
        <h2>MCP Routes</h2>
        <p class="muted">Each route becomes a public MCP endpoint under <code>{{.PublicBaseURL}}/&lt;route&gt;/mcp</code>. Upstream environment metadata is stored here for planning and exports, but the gateway does not start containers for you.</p>
        <div class="route-list" style="margin-top: 1rem;">
          {{if .Routes}}
            {{range .Routes}}
              <article class="route-card">
                <div style="display:flex; justify-content:space-between; gap:1rem; align-items:flex-start;">
                  <div>
                    <h3>{{.DisplayName}}</h3>
                    <p class="muted"><code>{{.ID}}</code> at <code>{{.PathPrefix}}</code></p>
                  </div>
                  {{if .MCPHTTPSessionMode}}<span class="pill">{{.MCPHTTPSessionMode}}</span>{{end}}
                </div>
                <div class="route-meta">
                  <span>Public MCP: <code>{{.PublicMCPURL}}</code></span>
                  <span>Protected metadata: <code>{{.ProtectedMetadataURL}}</code></span>
                  <span>Upstream: <code>{{.Upstream}}</code><code>{{.UpstreamMCPPath}}</code></span>
                  <span>Forward headers: {{.ForwardHeadersCount}} | Extra env vars: {{.UpstreamEnvironmentCount}} | Pass inbound Authorization: {{if .PassAuthorization}}yes{{else}}no{{end}}</span>
                </div>
                <div class="route-actions">
                  <a class="link-button secondary" href="/admin?route={{.ID}}">Edit Route</a>
                </div>
              </article>
            {{end}}
          {{else}}
            <article class="route-card">
              <p>No MCP routes have been configured yet.</p>
            </article>
          {{end}}
        </div>
      </section>

      <section>
        <h2>{{if .SelectedRoute.OriginalID}}Edit Route{{else}}Create Route{{end}}</h2>
        <p class="muted">Use one form to manage routing, public metadata, forwarded headers and upstream deployment hints like <code>MCP_HTTP_SESSION_MODE</code>.</p>
        <form method="post" action="/admin/routes/save" style="margin-top: 1rem;">
          <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
          <input type="hidden" name="original_id" value="{{.SelectedRoute.OriginalID}}">
          <div class="field-grid">
            <div>
              <label for="id">Route ID</label>
              <input id="id" name="id" type="text" value="{{.SelectedRoute.ID}}" required>
            </div>
            <div>
              <label for="display_name">Display Name</label>
              <input id="display_name" name="display_name" type="text" value="{{.SelectedRoute.DisplayName}}">
            </div>
            <div>
              <label for="path_prefix">Path Prefix</label>
              <input id="path_prefix" name="path_prefix" type="text" value="{{.SelectedRoute.PathPrefix}}" placeholder="/n8n" required>
            </div>
            <div>
              <label for="scopes_supported">Scopes</label>
              <input id="scopes_supported" name="scopes_supported" type="text" value="{{.SelectedRoute.ScopesSupported}}" placeholder="mcp">
            </div>
            <div class="full">
              <label for="upstream">Upstream Base URL</label>
              <input id="upstream" name="upstream" type="url" value="{{.SelectedRoute.Upstream}}" placeholder="http://n8n-mcp:8080" required>
            </div>
            <div>
              <label for="upstream_mcp_path">Upstream MCP Path</label>
              <input id="upstream_mcp_path" name="upstream_mcp_path" type="text" value="{{.SelectedRoute.UpstreamMCPPath}}" placeholder="/mcp">
            </div>
            <div>
              <label for="mcp_http_session_mode">MCP_HTTP_SESSION_MODE</label>
              <input id="mcp_http_session_mode" name="mcp_http_session_mode" type="text" value="{{.SelectedRoute.MCPHTTPSessionMode}}" placeholder="stateful or stateless">
            </div>
            <div class="full">
              <label for="resource_documentation">Resource Documentation URL</label>
              <input id="resource_documentation" name="resource_documentation" type="url" value="{{.SelectedRoute.ResourceDocumentation}}" placeholder="https://github.com/your-server/docs">
            </div>
            <div class="full checkbox">
              <input id="pass_authorization_header" name="pass_authorization_header" type="checkbox" {{if .SelectedRoute.PassAuthorization}}checked{{end}}>
              <div>
                <label for="pass_authorization_header" style="margin:0;">Pass inbound Authorization header through to the upstream server</label>
                <p class="helper">Leave this off when the gateway should replace auth with static forwarded headers or internal secrets.</p>
              </div>
            </div>
            <div class="full">
              <label for="forward_headers">Forward Headers</label>
              <textarea id="forward_headers" name="forward_headers" placeholder="Authorization: Bearer internal-token&#10;X-MCP-User: {email}">{{.SelectedRoute.ForwardHeaders}}</textarea>
              <p class="helper">One header per line. Use <code>Header: value</code>. Leave empty to use the default authenticated user headers.</p>
            </div>
            <div class="full">
              <label for="upstream_environment">Upstream Environment Metadata</label>
              <textarea id="upstream_environment" name="upstream_environment" placeholder="AUTH_TOKEN=replace-me&#10;PORT=8080">{{.SelectedRoute.UpstreamEnvironment}}</textarea>
              <p class="helper">Stored as deployment metadata for this MCP service. The gateway does not inject these values into Docker automatically.</p>
            </div>
            <div class="full">
              <label for="notes">Notes</label>
              <textarea id="notes" name="notes" placeholder="Optional deployment notes, onboarding hints, reverse proxy requirements...">{{.SelectedRoute.Notes}}</textarea>
            </div>
          </div>
          <div class="form-actions">
            <button type="submit">Save Route</button>
            <a class="link-button secondary" href="/admin">New Route</a>
          </div>
        </form>
        {{if .SelectedRoute.OriginalID}}
          <form method="post" action="/admin/routes/delete">
            <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
            <input type="hidden" name="route_id" value="{{.SelectedRoute.OriginalID}}">
            <div class="form-actions">
              <button type="submit" class="danger">Delete Route</button>
            </div>
          </form>
        {{end}}
      </section>
    </div>

    <div class="grid" style="margin-top: 1rem;">
      <section>
        <h2>Users</h2>
        <p class="muted">Manage who can log in and who can administer the gateway. At least one admin account must remain.</p>
        <div class="users" style="margin-top: 1rem;">
          {{range .Users}}
            <article class="user-card">
              <div style="display:flex; justify-content:space-between; gap:1rem; align-items:flex-start;">
                <div>
                  <h3>{{.Email}}</h3>
                  <div class="user-meta">
                    <span>ID: <code>{{.ID}}</code></span>
                    <span>Created: {{.CreatedAt}}</span>
                    <span>Updated: {{.UpdatedAt}}</span>
                  </div>
                </div>
                {{if .IsAdmin}}<span class="pill">Admin</span>{{end}}
              </div>

              <form method="post" action="/admin/users/admin" class="small-form">
                <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                <input type="hidden" name="user_id" value="{{.ID}}">
                <input type="hidden" name="is_admin" value="{{if .IsAdmin}}false{{else}}true{{end}}">
                <button type="submit" class="secondary">{{if .IsAdmin}}Remove Admin Role{{else}}Grant Admin Role{{end}}</button>
              </form>

              <form method="post" action="/admin/users/password" class="small-form">
                <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                <input type="hidden" name="user_id" value="{{.ID}}">
                <label for="password_{{.ID}}">Reset Password</label>
                <input id="password_{{.ID}}" name="password" type="password" minlength="10" placeholder="New password" required>
                <button type="submit" class="secondary">Update Password</button>
              </form>

              <form method="post" action="/admin/users/delete" class="small-form">
                <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                <input type="hidden" name="user_id" value="{{.ID}}">
                <button type="submit" class="danger">Delete User</button>
              </form>
            </article>
          {{end}}
        </div>
      </section>

      <section>
        <h2>Create User</h2>
        <p class="muted">Create gateway users directly, even when public self-signup is disabled.</p>
        <form method="post" action="/admin/users/create" style="margin-top: 1rem;">
          <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
          <div class="field-grid">
            <div class="full">
              <label for="user_email">Email</label>
              <input id="user_email" name="email" type="email" required>
            </div>
            <div class="full">
              <label for="user_password">Password</label>
              <input id="user_password" name="password" type="password" minlength="10" required>
            </div>
            <div class="full checkbox">
              <input id="user_is_admin" name="is_admin" type="checkbox">
              <div>
                <label for="user_is_admin" style="margin:0;">Grant admin permissions immediately</label>
                <p class="helper">Admins can manage routes and other users in this dashboard.</p>
              </div>
            </div>
          </div>
          <div class="form-actions">
            <button type="submit">Create User</button>
          </div>
        </form>
      </section>
    </div>
  </main>
</body>
</html>
`
