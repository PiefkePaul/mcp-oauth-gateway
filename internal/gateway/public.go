package gateway

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/webui"
)

type publicDashboardData struct {
	Title             string
	PublicBaseURL     string
	OAuthIssuerURL    string
	DocsURL           string
	AccountURL        string
	LoginURL          string
	RegisterURL       string
	AdminURL          string
	SelfSignupEnabled bool
	SignedInEmail     string
	IsAdmin           bool
	Routes            []publicRouteView
}

type publicRouteView struct {
	ID              string
	DisplayName     string
	Description     string
	MCPURL          string
	OpenAPIURL      string
	DocsURL         string
	InfoURL         string
	MetadataURL     string
	ResourceDocsURL string
	Scopes          string
	AccessLabel     string
	SessionMode     string
}

func (s *Server) renderPublicDashboard(w http.ResponseWriter, r *http.Request) {
	identity, _ := s.authManager.CurrentIdentity(r)
	data := s.newPublicDashboardData(r, identity)
	renderPublicHTML(w, http.StatusOK, publicDashboardTemplate, data)
}

func (s *Server) handleDocsIndex(w http.ResponseWriter, r *http.Request) {
	if !allowsReadMethod(r.Method) {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	identity, _ := s.authManager.CurrentIdentity(r)
	data := s.newPublicDashboardData(r, identity)
	renderPublicHTML(w, http.StatusOK, docsIndexTemplate, data)
}

func (s *Server) handleRouteDocs(w http.ResponseWriter, r *http.Request, route config.Route) {
	if !allowsReadMethod(r.Method) {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}

	identity, _ := s.authManager.CurrentIdentity(r)
	if route.Access.IsPrivate() {
		if identity == nil {
			http.Redirect(w, r, "/account/login?next="+r.URL.EscapedPath(), http.StatusFound)
			return
		}
		if !routeAccessAllowed(route, identity) {
			http.Error(w, "you are not allowed to view this MCP documentation", http.StatusForbidden)
			return
		}
	}

	data := map[string]any{
		"Title":             route.DisplayName + " Docs",
		"GatewayTitle":      s.cfg.AccountPortalTitle,
		"PublicBaseURL":     s.baseURL(r),
		"OAuthIssuerURL":    s.absoluteURL("/.well-known/oauth-authorization-server"),
		"DocsURL":           s.absoluteURL("/docs"),
		"AccountURL":        s.absoluteURL("/account"),
		"LoginURL":          s.absoluteURL("/account/login"),
		"RegisterURL":       s.absoluteURL("/account/register"),
		"AdminURL":          s.absoluteURL("/admin"),
		"SelfSignupEnabled": s.cfg.AllowSelfSignup,
		"Route":             publicRouteFromConfig(s, route),
	}
	if identity != nil {
		data["SignedInEmail"] = identity.Email
		data["IsAdmin"] = identity.IsAdmin
	}
	renderPublicHTML(w, http.StatusOK, routeDocsTemplate, data)
}

func (s *Server) newPublicDashboardData(r *http.Request, identity *auth.Identity) publicDashboardData {
	routes := s.routesSnapshot()
	views := make([]publicRouteView, 0, len(routes))
	for _, route := range routes {
		if !routeVisibleInPublicCatalog(route) {
			continue
		}
		views = append(views, publicRouteFromConfig(s, route))
	}

	data := publicDashboardData{
		Title:             s.cfg.AccountPortalTitle,
		PublicBaseURL:     s.baseURL(r),
		OAuthIssuerURL:    s.absoluteURL("/.well-known/oauth-authorization-server"),
		DocsURL:           s.absoluteURL("/docs"),
		AccountURL:        s.absoluteURL("/account"),
		LoginURL:          s.absoluteURL("/account/login"),
		RegisterURL:       s.absoluteURL("/account/register"),
		AdminURL:          s.absoluteURL("/admin"),
		SelfSignupEnabled: s.cfg.AllowSelfSignup,
		Routes:            views,
	}
	if identity != nil {
		data.SignedInEmail = identity.Email
		data.IsAdmin = identity.IsAdmin
	}
	return data
}

func publicRouteFromConfig(s *Server, route config.Route) publicRouteView {
	accessLabel := "Alle angemeldeten Nutzer"
	switch route.Access.EffectiveMode() {
	case "admin":
		accessLabel = "Nur Admins"
	case "restricted":
		accessLabel = "Eingeschraenkt"
	}

	return publicRouteView{
		ID:              route.ID,
		DisplayName:     route.DisplayName,
		Description:     route.Notes,
		MCPURL:          s.absoluteURL(route.PublicMCPPath()),
		OpenAPIURL:      s.absoluteURL(route.PublicOpenAPISpecPath()),
		DocsURL:         s.absoluteURL(route.PublicDocsPath()),
		InfoURL:         s.absoluteURL(route.PublicInfoPath()),
		MetadataURL:     s.absoluteURL(route.ProtectedResourceMetadataPath()),
		ResourceDocsURL: route.ResourceDocumentation,
		Scopes:          strings.Join(route.ScopeList(), ", "),
		AccessLabel:     accessLabel,
		SessionMode:     strings.TrimSpace(route.UpstreamEnvironment["MCP_HTTP_SESSION_MODE"]),
	}
}

func renderPublicHTML(w http.ResponseWriter, status int, tmpl string, data any) {
	t := template.Must(template.New("public").Parse(publicLayoutTemplate + tmpl))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_ = t.Execute(w, data)
}

const publicLayoutTemplate = `
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  ` + webui.GoogleFonts + `
  ` + webui.Style + `
</head>
<body>
  <div class="topbar">
    <a class="wordmark" href="/"><span class="mark">GW</span> {{.Title}}</a>
    <nav>
      <a class="navlink" href="/docs">Docs</a>
      {{if .SignedInEmail}}
        <a class="navlink" href="/account">{{.SignedInEmail}}</a>
        {{if .IsAdmin}}<a class="btn btn-sm" href="/admin">Admin</a>{{end}}
      {{else}}
        <a class="navlink" href="/account/login">Anmelden</a>
        {{if .SelfSignupEnabled}}<a class="btn btn-primary btn-sm" href="/account/register">Registrieren</a>{{end}}
      {{end}}
    </nav>
  </div>
  <div class="page">
    {{template "body" .}}
  </div>
</body>
</html>
`

const publicDashboardTemplate = `
{{define "body"}}
<div class="page-head">
  <div>
    <span class="eyebrow">MCP OAuth Gateway</span>
    <h1>{{.Title}}</h1>
    <p class="muted" style="margin-top:.4rem;">Zentraler OAuth-Einstieg fuer deine per Streamable HTTP erreichbaren MCP-Server.</p>
  </div>
</div>

<div class="split" style="margin-bottom:1.6rem;">
  <div class="panel">
    <div class="panel-head"><h2>Client-Einrichtung</h2></div>
    <div class="panel-body kv-mini" style="font-size:.88rem;">
      <span>Auth: <code>OAuth</code></span>
      <span>Issuer: <code>{{.OAuthIssuerURL}}</code></span>
      <span>Client-ID/Secret: leer lassen, wenn dein Client Dynamic Registration unterstuetzt.</span>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head"><h2>Katalog</h2></div>
    <div class="panel-body">
      <p class="muted">Hier erscheinen MCP-Server, die nicht als privat markiert sind. Die Nutzung kann trotzdem auf Gruppen oder Nutzer eingeschraenkt sein.</p>
    </div>
  </div>
</div>

<div class="toolbar" style="margin-bottom:1rem;">
  <h2>Server</h2>
  <span class="hint">{{len .Routes}} oeffentlich sichtbar</span>
</div>
<div class="catalog">
  {{if .Routes}}
    {{range .Routes}}
      <article class="route-card">
        <div class="cluster" style="justify-content:space-between; align-items:flex-start;">
          <div>
            <h3>{{.DisplayName}}</h3>
            <div class="path">{{.ID}}</div>
          </div>
          <span class="pill pill-neutral">{{.AccessLabel}}</span>
        </div>
        {{if .Description}}<p class="muted" style="font-size:.86rem;">{{.Description}}</p>{{end}}
        <div class="kv-mini">
          <span><span class="k">MCP URL</span> <code>{{.MCPURL}}</code></span>
          <span><span class="k">OpenAPI Adapter</span> <code>{{.OpenAPIURL}}</code></span>
          <span><span class="k">Scopes</span> <code>{{.Scopes}}</code></span>
          {{if .SessionMode}}<span><span class="k">Session Mode</span> <code>{{.SessionMode}}</code></span>{{end}}
        </div>
        <div class="cluster">
          <a class="btn btn-sm" href="{{.DocsURL}}">Docs ansehen</a>
          {{if .ResourceDocsURL}}<a class="btn btn-ghost btn-sm" href="{{.ResourceDocsURL}}">Projekt-Doku</a>{{end}}
        </div>
      </article>
    {{end}}
  {{else}}
    <div class="empty" style="grid-column:1/-1;">
      <strong>Noch keine oeffentlichen MCP-Server</strong>
      <p class="muted">Admins koennen Routen im Dashboard anlegen und entscheiden, welche davon im Katalog sichtbar sind.</p>
    </div>
  {{end}}
</div>
{{end}}
`

const docsIndexTemplate = `
{{define "body"}}
<div class="page-head">
  <div>
    <span class="eyebrow">Gateway Docs</span>
    <h1>{{.Title}} Docs</h1>
    <p class="muted" style="margin-top:.4rem;">Einrichtung, OAuth-Endpunkte und die oeffentlichen MCP-Routen auf einen Blick.</p>
  </div>
</div>
<div class="panel" style="margin-bottom:1.4rem;">
  <div class="panel-head"><h2>OAuth-Konfiguration</h2></div>
  <div class="panel-body kv-mini" style="font-size:.88rem;">
    <span>Authorization Server Metadata: <code>{{.OAuthIssuerURL}}</code></span>
    <span>Auth-Typ im Client: <code>OAuth</code></span>
    <span>Client-ID und Client-Secret: optional leer lassen, sofern der Client Dynamic Client Registration nutzt.</span>
  </div>
</div>
<div class="catalog">
  {{range .Routes}}
    <article class="route-card">
      <h3>{{.DisplayName}}</h3>
      <div class="kv-mini">
        <span><span class="k">Remote MCP URL</span> <code>{{.MCPURL}}</code></span>
        <span><span class="k">OpenAPI Spec</span> <code>{{.OpenAPIURL}}</code></span>
        <span><span class="k">Protected Resource Metadata</span> <code>{{.MetadataURL}}</code></span>
        <span><span class="k">Route Info JSON</span> <code>{{.InfoURL}}</code></span>
      </div>
      <div class="cluster">
        <a class="btn btn-sm" href="{{.DocsURL}}">Route Docs</a>
        {{if .ResourceDocsURL}}<a class="btn btn-ghost btn-sm" href="{{.ResourceDocsURL}}">Externe Doku</a>{{end}}
      </div>
    </article>
  {{end}}
</div>
{{end}}
`

const routeDocsTemplate = `
{{define "body"}}
<div class="page-head">
  <div>
    <span class="eyebrow">MCP Route Docs</span>
    <h1>{{.Route.DisplayName}}</h1>
    <p class="muted" style="margin-top:.4rem;">Alles, was du zum Einbinden dieses MCP-Servers brauchst.</p>
  </div>
  <nav class="cluster">
    <a class="btn btn-ghost btn-sm" href="/docs">Alle Docs</a>
    <a class="btn btn-ghost btn-sm" href="/">Katalog</a>
  </nav>
</div>
<div class="split">
  <div class="panel">
    <div class="panel-head"><h2>Einbindung</h2></div>
    <div class="panel-body stack-sm">
      <div><div class="hint">Remote MCP Server URL</div><code>{{.Route.MCPURL}}</code></div>
      <div><div class="hint">OpenAPI Adapter URL</div><code>{{.Route.OpenAPIURL}}</code></div>
      <div><div class="hint">Authentifizierung</div><code>OAuth</code></div>
      <div><div class="hint">OAuth Issuer</div><code>{{.OAuthIssuerURL}}</code></div>
      <div><div class="hint">Protected Resource Metadata</div><code>{{.Route.MetadataURL}}</code></div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head"><h2>Route-Daten</h2></div>
    <div class="panel-body stack-sm">
      <div class="kv-mini">
        <span><span class="k">ID</span> <code>{{.Route.ID}}</code></span>
        <span><span class="k">Scopes</span> <code>{{.Route.Scopes}}</code></span>
        <span><span class="k">Zugriff</span> <code>{{.Route.AccessLabel}}</code></span>
        {{if .Route.SessionMode}}<span><span class="k">Session Mode</span> <code>{{.Route.SessionMode}}</code></span>{{end}}
      </div>
      {{if .Route.Description}}<p>{{.Route.Description}}</p>{{end}}
      {{if .Route.ResourceDocsURL}}<a class="btn btn-sm" href="{{.Route.ResourceDocsURL}}">Projekt-Dokumentation oeffnen</a>{{end}}
    </div>
  </div>
</div>
{{end}}
`
