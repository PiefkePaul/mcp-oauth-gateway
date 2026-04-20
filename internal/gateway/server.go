package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

type Server struct {
	cfg         *config.Config
	authManager *auth.Manager
	mu          sync.RWMutex
	routes      []config.Route
	runtime     map[string]routeRuntime
}

func New(cfg *config.Config, authManager *auth.Manager) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if authManager == nil {
		return nil, fmt.Errorf("auth manager is required")
	}

	server := &Server{
		cfg:         cfg,
		authManager: authManager,
		runtime:     make(map[string]routeRuntime, len(cfg.Routes)),
	}
	if err := server.replaceRoutes(cfg.Routes); err != nil {
		return nil, err
	}

	return server, nil
}

func Run(cfg *config.Config) error {
	authManager, err := auth.NewManager(auth.Config{
		StorePath:            cfg.Auth.StorePath,
		MasterKey:            cfg.Auth.MasterKey,
		AccessTokenTTL:       cfg.Auth.AccessTokenTTL,
		RefreshTokenTTL:      cfg.Auth.RefreshTokenTTL,
		AuthorizationCodeTTL: cfg.Auth.AuthorizationCodeTTL,
		SessionTTL:           cfg.Auth.SessionTTL,
		PublicBaseURL:        cfg.PublicBaseURL,
		PortalTitle:          cfg.AccountPortalTitle,
		AllowSelfSignup:      cfg.AllowSelfSignup,
		BootstrapEmail:       cfg.BootstrapEmail,
		BootstrapPassword:    cfg.BootstrapPassword,
		AllowedEmails:        cfg.AllowedEmails,
		AllowedEmailDomains:  cfg.AllowedEmailDomains,
	})
	if err != nil {
		return err
	}

	handler, err := New(cfg, authManager)
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	log.Printf(
		"starting mcp-oauth-gateway listen=%s public_base_url=%s routes=%d",
		cfg.ListenAddr,
		cfg.PublicBaseURL,
		len(cfg.Routes),
	)

	return httpServer.ListenAndServe()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		s.handleIndex(w, r)
		return
	case "/healthz":
		s.handleHealthz(w, r)
		return
	case "/.well-known/oauth-authorization-server":
		s.authManager.HandleAuthorizationServerMetadata(w, r)
		return
	case "/.well-known/openid-configuration":
		s.authManager.HandleOpenIDConfiguration(w, r)
		return
	case "/register":
		s.authManager.HandleClientRegistration(w, r)
		return
	case "/authorize":
		s.authManager.HandleAuthorize(w, r)
		return
	case "/token":
		s.authManager.HandleToken(w, r)
		return
	case "/account":
		s.authManager.HandleAccount(w, r)
		return
	case "/account/login":
		s.authManager.HandleAccountLogin(w, r)
		return
	case "/account/logout":
		s.authManager.HandleAccountLogout(w, r)
		return
	case "/account/register":
		s.authManager.HandleAccountRegister(w, r)
		return
	case "/admin":
		s.handleAdminDashboard(w, r)
		return
	case "/admin/routes/save":
		s.handleAdminRouteSave(w, r)
		return
	case "/admin/routes/delete":
		s.handleAdminRouteDelete(w, r)
		return
	case "/admin/users/create":
		s.handleAdminUserCreate(w, r)
		return
	case "/admin/users/password":
		s.handleAdminUserPassword(w, r)
		return
	case "/admin/users/delete":
		s.handleAdminUserDelete(w, r)
		return
	case "/admin/users/admin":
		s.handleAdminUserAdmin(w, r)
		return
	}

	if route, ok := s.routeByProtectedMetadataPath(r.URL.Path); ok {
		s.handleProtectedResourceMetadata(w, r, route)
		return
	}

	if route, proxy, ok := s.routeByProxyPath(r.URL.Path); ok {
		s.handleProxy(w, r, route, proxy)
		return
	}

	if route, ok := s.routeByInfoPath(r.URL.Path); ok {
		s.handleRouteInfo(w, r, route)
		return
	}

	http.NotFound(w, r)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if !allowsReadMethod(r.Method) {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}

	routesSnapshot := s.routesSnapshot()
	routes := make([]map[string]any, 0, len(routesSnapshot))
	for i := range routesSnapshot {
		route := routesSnapshot[i]
		payload := map[string]any{
			"id":                              route.ID,
			"display_name":                    route.DisplayName,
			"route_info_url":                  s.absoluteURL(route.PublicInfoPath()),
			"mcp_url":                         s.absoluteURL(route.PublicMCPPath()),
			"protected_resource_metadata_url": s.absoluteURL(route.ProtectedResourceMetadataPath()),
			"scopes_supported":                route.ScopeList(),
			"upstream":                        route.Upstream,
		}
		if strings.TrimSpace(route.ResourceDocumentation) != "" {
			payload["resource_documentation"] = route.ResourceDocumentation
		}
		routes = append(routes, payload)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"service":                           "mcp-oauth-gateway",
		"public_base_url":                   s.baseURL(r),
		"authorization_server_metadata_url": s.absoluteURL("/.well-known/oauth-authorization-server"),
		"openid_configuration_url":          s.absoluteURL("/.well-known/openid-configuration"),
		"dynamic_client_registration_url":   s.absoluteURL("/register"),
		"authorization_endpoint":            s.absoluteURL("/authorize"),
		"token_endpoint":                    s.absoluteURL("/token"),
		"account_portal_url":                s.absoluteURL("/account"),
		"admin_dashboard_url":               s.absoluteURL("/admin"),
		"self_signup_enabled":               s.cfg.AllowSelfSignup,
		"bootstrap_user_configured":         s.cfg.BootstrapEmail != "",
		"routes":                            routes,
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if !allowsReadMethod(r.Method) {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"routes": len(s.cfg.Routes),
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleRouteInfo(w http.ResponseWriter, r *http.Request, route config.Route) {
	if !allowsReadMethod(r.Method) {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}

	payload := map[string]any{
		"id":                              route.ID,
		"display_name":                    route.DisplayName,
		"path_prefix":                     route.NormalizedPathPrefix,
		"mcp_url":                         s.absoluteURL(route.PublicMCPPath()),
		"protected_resource_metadata_url": s.absoluteURL(route.ProtectedResourceMetadataPath()),
		"authorization_server_url":        s.absoluteURL("/.well-known/oauth-authorization-server"),
		"account_portal_url":              s.absoluteURL("/account"),
		"scopes_supported":                route.ScopeList(),
		"upstream":                        route.Upstream,
	}
	if strings.TrimSpace(route.ResourceDocumentation) != "" {
		payload["resource_documentation"] = route.ResourceDocumentation
	}

	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request, route config.Route) {
	resourceURL := s.absoluteURL(route.PublicMCPPath())
	s.authManager.WriteProtectedResourceMetadata(
		w,
		r,
		resourceURL,
		route.ScopeList(),
		[]string{s.baseURL(r)},
		route.ResourceDocumentation,
	)
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request, route config.Route, proxy *httputil.ReverseProxy) {
	token, err := bearerToken(r.Header.Get("Authorization"))
	if err != nil {
		s.writeChallenge(w, r, route)
		return
	}

	resourceURL := s.absoluteURL(route.PublicMCPPath())
	identity, err := s.authManager.ValidateAccessToken(token, resourceURL)
	if err != nil {
		s.writeChallenge(w, r, route)
		return
	}

	if proxy == nil {
		http.Error(w, "route proxy is unavailable", http.StatusInternalServerError)
		return
	}

	ctx := auth.WithIdentity(r.Context(), identity)
	proxy.ServeHTTP(w, r.WithContext(ctx))
}

func (s *Server) writeChallenge(w http.ResponseWriter, r *http.Request, route config.Route) {
	metadataURL := s.absoluteURL(route.ProtectedResourceMetadataPath())
	scope := strings.Join(route.ScopeList(), " ")

	w.Header().Set("WWW-Authenticate", s.authManager.ChallengeHeader(metadataURL, scope))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusUnauthorized, map[string]any{
		"error":             "unauthorized",
		"error_description": "a valid bearer token for this MCP resource is required",
	})
}

func (s *Server) absoluteURL(path string) string {
	return strings.TrimRight(s.cfg.PublicBaseURL, "/") + path
}

func (s *Server) baseURL(r *http.Request) string {
	if strings.TrimSpace(s.cfg.PublicBaseURL) != "" {
		return strings.TrimRight(s.cfg.PublicBaseURL, "/")
	}
	return strings.TrimRight(auth.BaseURLFromRequest(r), "/")
}

func newReverseProxy(route config.Route) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(route.Upstream)
	if err != nil {
		return nil, fmt.Errorf("parse route %q upstream: %w", route.ID, err)
	}

	upstreamBasePath := joinURLPath(target.Path, route.NormalizedUpstreamPath)
	publicBasePath := route.PublicMCPPath()

	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.URL.User = target.User
			pr.Out.Host = target.Host
			pr.Out.URL.Path = rewriteUpstreamPath(pr.In.URL.Path, publicBasePath, upstreamBasePath)
			pr.Out.URL.RawPath = ""
			pr.Out.URL.RawQuery = joinRawQuery(target.RawQuery, pr.In.URL.RawQuery)

			pr.Out.Header["X-Forwarded-For"] = pr.In.Header["X-Forwarded-For"]
			pr.SetXForwarded()
			if forwardedHost := strings.TrimSpace(pr.In.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
				pr.Out.Header.Set("X-Forwarded-Host", forwardedHost)
			}
			if forwardedProto := strings.TrimSpace(pr.In.Header.Get("X-Forwarded-Proto")); forwardedProto != "" {
				pr.Out.Header.Set("X-Forwarded-Proto", forwardedProto)
			}
			pr.Out.Header.Set("X-Forwarded-Prefix", route.NormalizedPathPrefix)

			if !route.PassAuthorization {
				pr.Out.Header.Del("Authorization")
			}

			identity := auth.IdentityFromContext(pr.In.Context())
			if identity != nil {
				for headerName, templateValue := range route.HeaderTemplates() {
					value := expandHeaderTemplate(templateValue, route, identity)
					if strings.TrimSpace(value) == "" {
						pr.Out.Header.Del(headerName)
						continue
					}
					pr.Out.Header.Set(headerName, value)
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("gateway proxy error route=%s path=%s err=%v", route.ID, r.URL.Path, err)
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error":             "bad_gateway",
				"error_description": "the upstream MCP server could not be reached",
			})
		},
	}, nil
}

func rewriteUpstreamPath(requestPath, publicBasePath, upstreamBasePath string) string {
	if requestPath == publicBasePath {
		return upstreamBasePath
	}
	suffix := strings.TrimPrefix(requestPath, publicBasePath)
	return joinURLPath(upstreamBasePath, suffix)
}

func joinURLPath(base, suffix string) string {
	switch {
	case base == "":
		base = "/"
	case !strings.HasPrefix(base, "/"):
		base = "/" + base
	}

	if suffix == "" {
		return base
	}
	if !strings.HasPrefix(suffix, "/") {
		suffix = "/" + suffix
	}
	if base == "/" {
		return suffix
	}
	return strings.TrimRight(base, "/") + suffix
}

func joinRawQuery(baseQuery, requestQuery string) string {
	switch {
	case baseQuery == "":
		return requestQuery
	case requestQuery == "":
		return baseQuery
	default:
		return baseQuery + "&" + requestQuery
	}
}

func expandHeaderTemplate(templateValue string, route config.Route, identity *auth.Identity) string {
	replacer := strings.NewReplacer(
		"{email}", identity.Email,
		"{route_id}", route.ID,
		"{route_path}", route.NormalizedPathPrefix,
		"{user_id}", identity.UserID,
	)
	return replacer.Replace(templateValue)
}

func bearerToken(headerValue string) (string, error) {
	fields := strings.Fields(strings.TrimSpace(headerValue))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || strings.TrimSpace(fields[1]) == "" {
		return "", errors.New("missing bearer token")
	}
	return fields[1], nil
}

func matchesExactOrChildPath(requestPath, prefix string) bool {
	if requestPath == prefix {
		return true
	}
	if !strings.HasPrefix(requestPath, prefix) {
		return false
	}
	if len(requestPath) == len(prefix) {
		return true
	}
	return requestPath[len(prefix)] == '/'
}

func allowsReadMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if status == http.StatusNoContent {
		return
	}
	_ = json.NewEncoder(w).Encode(payload)
}
