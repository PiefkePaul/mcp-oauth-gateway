package gateway

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
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
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
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
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f2ea;
      --panel: #fffaf0;
      --card: #fffefd;
      --ink: #1f2522;
      --muted: #68706a;
      --line: #ded4c2;
      --accent: #0f5b4d;
      --accent-2: #c45f33;
      --soft: #e7f1dc;
      font-family: "Aptos", "Trebuchet MS", system-ui, sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--ink);
      background:
        radial-gradient(circle at 8% 0%, rgba(196,95,51,0.16), transparent 28rem),
        radial-gradient(circle at 88% 8%, rgba(15,91,77,0.14), transparent 30rem),
        linear-gradient(135deg, #fffaf0 0%, var(--bg) 52%, #edf3e7 100%);
      min-height: 100vh;
    }
    main { max-width: 78rem; margin: 0 auto; padding: 2rem 1rem 4rem; }
    header { display: flex; justify-content: space-between; gap: 1rem; align-items: flex-start; margin-bottom: 1.5rem; }
    h1, h2, h3 { margin: 0; letter-spacing: -0.02em; }
    h1 { font-size: clamp(2.2rem, 6vw, 4.6rem); line-height: 0.95; max-width: 12ch; }
    h2 { font-size: 1.35rem; }
    h3 { font-size: 1.02rem; }
    p { margin: 0; }
    a { color: var(--accent); }
    code {
      background: #f0eadf;
      border: 1px solid #e2d8c8;
      border-radius: 8px;
      padding: 0.14rem 0.38rem;
      word-break: break-all;
    }
    .muted { color: var(--muted); }
    .hero {
      background: rgba(255,250,240,0.78);
      border: 1px solid rgba(222,212,194,0.9);
      border-radius: 28px;
      padding: clamp(1.25rem, 4vw, 2rem);
      box-shadow: 0 24px 80px rgba(67,48,24,0.10);
      backdrop-filter: blur(8px);
    }
    .actions { display: flex; flex-wrap: wrap; gap: 0.6rem; align-items: center; }
    .button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border-radius: 999px;
      padding: 0.72rem 1rem;
      background: var(--accent);
      color: white;
      text-decoration: none;
      font-weight: 700;
      border: 1px solid transparent;
    }
    .button.secondary { background: #fffaf0; color: var(--ink); border-color: var(--line); }
    .pill {
      display: inline-flex;
      width: fit-content;
      border-radius: 999px;
      background: var(--soft);
      color: #275044;
      padding: 0.25rem 0.62rem;
      font-size: 0.82rem;
      font-weight: 800;
    }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(18rem, 1fr)); gap: 1rem; }
    .route-card, .panel {
      background: rgba(255,254,253,0.88);
      border: 1px solid var(--line);
      border-radius: 22px;
      padding: 1rem;
      box-shadow: 0 16px 45px rgba(67,48,24,0.08);
    }
    .route-card { display: grid; gap: 0.8rem; }
    .meta { display: grid; gap: 0.35rem; font-size: 0.94rem; }
    .stack { display: grid; gap: 1rem; }
    .two { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; align-items: start; }
    .copybox { display: grid; gap: 0.35rem; }
    .copybox strong { font-size: 0.85rem; color: var(--muted); }
    @media (max-width: 860px) {
      header, .two { grid-template-columns: 1fr; flex-direction: column; }
      .actions { width: 100%; }
      .button { width: 100%; }
    }
  </style>
</head>
<body>
  <main>
    {{template "body" .}}
  </main>
</body>
</html>
`

const publicDashboardTemplate = `
{{define "body"}}
<section class="hero">
  <header>
    <div class="stack">
      <span class="pill">MCP OAuth Gateway</span>
      <h1>{{.Title}}</h1>
      <p class="muted">Zentraler OAuth-Einstieg fuer deine per Streamable HTTP erreichbaren MCP-Server.</p>
    </div>
    <nav class="actions">
      <a class="button secondary" href="/docs">Docs</a>
      {{if .SignedInEmail}}
        <a class="button secondary" href="/account">{{.SignedInEmail}}</a>
        {{if .IsAdmin}}<a class="button" href="/admin">Admin</a>{{end}}
      {{else}}
        <a class="button secondary" href="/account/login">Anmelden</a>
        {{if .SelfSignupEnabled}}<a class="button" href="/account/register">Registrieren</a>{{end}}
      {{end}}
    </nav>
  </header>
  <div class="two">
    <div class="panel">
      <h2>Client-Einrichtung</h2>
      <div class="meta" style="margin-top:.75rem;">
        <span>Auth: <code>OAuth</code></span>
        <span>Issuer: <code>{{.OAuthIssuerURL}}</code></span>
        <span>Client-ID/Secret: leer lassen, wenn dein Client Dynamic Registration unterstuetzt.</span>
      </div>
    </div>
    <div class="panel">
      <h2>Katalog</h2>
      <p class="muted" style="margin-top:.75rem;">Hier erscheinen MCP-Server, die nicht als privat markiert sind. Die Nutzung kann trotzdem auf Gruppen oder Nutzer eingeschraenkt sein.</p>
    </div>
  </div>
</section>

<section style="margin-top:1rem;">
  <div class="grid">
    {{if .Routes}}
      {{range .Routes}}
        <article class="route-card">
          <div style="display:flex; justify-content:space-between; gap:.75rem; align-items:flex-start;">
            <div>
              <h3>{{.DisplayName}}</h3>
              <p class="muted"><code>{{.ID}}</code></p>
            </div>
            <span class="pill">{{.AccessLabel}}</span>
          </div>
          {{if .Description}}<p>{{.Description}}</p>{{end}}
          <div class="meta">
            <span>MCP URL: <code>{{.MCPURL}}</code></span>
            <span>OpenAPI Adapter: <code>{{.OpenAPIURL}}</code></span>
            <span>Scopes: <code>{{.Scopes}}</code></span>
            {{if .SessionMode}}<span>Session Mode: <code>{{.SessionMode}}</code></span>{{end}}
          </div>
          <div class="actions">
            <a class="button" href="{{.DocsURL}}">Docs ansehen</a>
            {{if .ResourceDocsURL}}<a class="button secondary" href="{{.ResourceDocsURL}}">Projekt-Doku</a>{{end}}
          </div>
        </article>
      {{end}}
    {{else}}
      <article class="route-card">
        <h3>Noch keine oeffentlichen MCP-Server</h3>
        <p class="muted">Admins koennen Routen im Dashboard anlegen und entscheiden, welche davon im Katalog sichtbar sind.</p>
      </article>
    {{end}}
  </div>
</section>
{{end}}
`

const docsIndexTemplate = `
{{define "body"}}
<section class="hero">
  <header>
    <div class="stack">
      <span class="pill">Gateway Docs</span>
      <h1>{{.Title}} Docs</h1>
      <p class="muted">Einrichtung, OAuth-Endpunkte und die oeffentlichen MCP-Routen auf einen Blick.</p>
    </div>
    <nav class="actions">
      <a class="button secondary" href="/">Katalog</a>
      {{if .SignedInEmail}}<a class="button secondary" href="/account">{{.SignedInEmail}}</a>{{else}}<a class="button" href="/account/login">Anmelden</a>{{end}}
    </nav>
  </header>
</section>
<section class="stack" style="margin-top:1rem;">
  <div class="panel">
    <h2>OAuth-Konfiguration</h2>
    <div class="meta" style="margin-top:.75rem;">
      <span>Authorization Server Metadata: <code>{{.OAuthIssuerURL}}</code></span>
      <span>Auth-Typ im Client: <code>OAuth</code></span>
      <span>Client-ID und Client-Secret: optional leer lassen, sofern der Client Dynamic Client Registration nutzt.</span>
    </div>
  </div>
  <div class="grid">
    {{range .Routes}}
      <article class="route-card">
        <h3>{{.DisplayName}}</h3>
        <div class="meta">
          <span>Remote MCP URL: <code>{{.MCPURL}}</code></span>
          <span>OpenAPI Spec: <code>{{.OpenAPIURL}}</code></span>
          <span>Protected Resource Metadata: <code>{{.MetadataURL}}</code></span>
          <span>Route Info JSON: <code>{{.InfoURL}}</code></span>
        </div>
        <div class="actions">
          <a class="button" href="{{.DocsURL}}">Route Docs</a>
          {{if .ResourceDocsURL}}<a class="button secondary" href="{{.ResourceDocsURL}}">Externe Doku</a>{{end}}
        </div>
      </article>
    {{end}}
  </div>
</section>
{{end}}
`

const routeDocsTemplate = `
{{define "body"}}
<section class="hero">
  <header>
    <div class="stack">
      <span class="pill">MCP Route Docs</span>
      <h1>{{.Route.DisplayName}}</h1>
      <p class="muted">Alles, was du zum Einbinden dieses MCP-Servers brauchst.</p>
    </div>
    <nav class="actions">
      <a class="button secondary" href="/docs">Alle Docs</a>
      <a class="button secondary" href="/">Katalog</a>
      {{if .SignedInEmail}}<a class="button secondary" href="/account">{{.SignedInEmail}}</a>{{else}}<a class="button" href="/account/login">Anmelden</a>{{end}}
    </nav>
  </header>
</section>
<section class="two" style="margin-top:1rem;">
  <div class="panel stack">
    <h2>Einbindung</h2>
    <div class="copybox">
      <strong>Remote MCP Server URL</strong>
      <code>{{.Route.MCPURL}}</code>
    </div>
    <div class="copybox">
      <strong>OpenAPI Adapter URL</strong>
      <code>{{.Route.OpenAPIURL}}</code>
    </div>
    <div class="copybox">
      <strong>Authentifizierung</strong>
      <code>OAuth</code>
    </div>
    <div class="copybox">
      <strong>OAuth Issuer</strong>
      <code>{{.OAuthIssuerURL}}</code>
    </div>
    <div class="copybox">
      <strong>Protected Resource Metadata</strong>
      <code>{{.Route.MetadataURL}}</code>
    </div>
  </div>
  <div class="panel stack">
    <h2>Route-Daten</h2>
    <div class="meta">
      <span>ID: <code>{{.Route.ID}}</code></span>
      <span>Scopes: <code>{{.Route.Scopes}}</code></span>
      <span>Zugriff: <code>{{.Route.AccessLabel}}</code></span>
      {{if .Route.SessionMode}}<span>Session Mode: <code>{{.Route.SessionMode}}</code></span>{{end}}
    </div>
    {{if .Route.Description}}<p>{{.Route.Description}}</p>{{end}}
    {{if .Route.ResourceDocsURL}}<a class="button" href="{{.Route.ResourceDocsURL}}">Projekt-Dokumentation oeffnen</a>{{end}}
  </div>
</section>
{{end}}
`
