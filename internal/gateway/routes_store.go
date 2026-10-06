package gateway

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

type routeRuntime struct {
	Route   config.Route
	Handler http.Handler
	Close   func() error
	// Revalidate closes sessions whose agent lost access, if the transport
	// keeps sessions of its own.
	Revalidate func()
}

func (s *Server) replaceRoutes(routes []config.Route) error {
	runtimes, err := s.buildRouteRuntime(routes)
	if err != nil {
		return err
	}

	s.mu.Lock()
	oldRuntimes := s.runtime
	s.routes = cloneRoutes(routes)
	s.runtime = runtimes
	s.cfg.Routes = cloneRoutes(routes)
	s.mu.Unlock()
	closeRouteRuntimes(oldRuntimes)
	s.mcpSessions.closeAll()
	return nil
}

func (s *Server) routesSnapshot() []config.Route {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRoutes(s.routes)
}

func (s *Server) routeByID(routeID string) (config.Route, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, route := range s.routes {
		if route.ID == routeID {
			return route, true
		}
	}
	return config.Route{}, false
}

func (s *Server) routeByProxyPath(requestPath string) (config.Route, http.Handler, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, route := range s.routes {
		if matchesExactOrChildPath(requestPath, route.PublicMCPPath()) {
			runtime, ok := s.runtime[route.ID]
			if !ok {
				return config.Route{}, nil, false
			}
			return runtime.Route, runtime.Handler, true
		}
	}
	return config.Route{}, nil, false
}

func (s *Server) routeByInfoPath(requestPath string) (config.Route, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, route := range s.routes {
		if requestPath == route.PublicInfoPath() {
			return route, true
		}
	}
	return config.Route{}, false
}

func (s *Server) routeByDocsPath(requestPath string) (config.Route, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, route := range s.routes {
		if requestPath == route.PublicDocsPath() {
			return route, true
		}
	}
	return config.Route{}, false
}

func (s *Server) routeByOpenAPISpecPath(requestPath string) (config.Route, http.Handler, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, route := range s.routes {
		specPath := route.PublicOpenAPISpecPath()
		// Open WebUI treats the configured OpenAPI URL as a base and appends
		// /openapi.json during connection checks. Accept both forms so users can
		// paste either the route base URL or the generated spec URL.
		if requestPath == specPath || requestPath == joinURLPath(specPath, "openapi.json") {
			runtime, ok := s.runtime[route.ID]
			if !ok {
				return config.Route{}, nil, false
			}
			return runtime.Route, runtime.Handler, true
		}
	}
	return config.Route{}, nil, false
}

func (s *Server) routeByOpenAPIToolPath(requestPath string) (config.Route, http.Handler, string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, route := range s.routes {
		prefix := route.PublicOpenAPIToolPathPrefix()
		if !matchesExactOrChildPath(requestPath, prefix) || requestPath == prefix {
			continue
		}
		runtime, ok := s.runtime[route.ID]
		if !ok {
			return config.Route{}, nil, "", false
		}
		operationID := strings.TrimPrefix(requestPath, prefix+"/")
		if operationID == "" || strings.Contains(operationID, "/") {
			return config.Route{}, nil, "", false
		}
		return runtime.Route, runtime.Handler, operationID, true
	}
	return config.Route{}, nil, "", false
}

func (s *Server) routeByProtectedMetadataPath(requestPath string) (config.Route, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, route := range s.routes {
		if requestPath == route.ProtectedResourceMetadataPath() {
			return route, true
		}
	}
	return config.Route{}, false
}

func (s *Server) upsertRoute(originalID string, route config.Route) error {
	if err := config.NormalizeRoute(&route); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	nextRoutes := cloneRoutes(s.routes)
	replaced := false
	for i := range nextRoutes {
		if nextRoutes[i].ID == originalID && originalID != "" {
			nextRoutes[i] = route
			replaced = true
			break
		}
	}
	if !replaced {
		nextRoutes = append(nextRoutes, route)
	}

	return s.persistRoutesLocked(nextRoutes)
}

func (s *Server) validateUpsertRoute(originalID string, route config.Route) error {
	if err := config.NormalizeRoute(&route); err != nil {
		return err
	}

	s.mu.RLock()
	nextRoutes := cloneRoutes(s.routes)
	s.mu.RUnlock()

	replaced := false
	for i := range nextRoutes {
		if nextRoutes[i].ID == originalID && originalID != "" {
			nextRoutes[i] = route
			replaced = true
			break
		}
	}
	if !replaced {
		nextRoutes = append(nextRoutes, route)
	}
	if err := config.ValidateRoutes(nextRoutes); err != nil {
		return err
	}
	// Build the runtimes only to validate them; close them again so probe
	// STDIO bridges do not keep their sweep loops running.
	runtimes, err := s.buildRouteRuntime(nextRoutes)
	if err != nil {
		return err
	}
	closeRouteRuntimes(runtimes)
	return nil
}

func (s *Server) deleteRoute(routeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	nextRoutes := make([]config.Route, 0, len(s.routes))
	found := false
	for _, route := range s.routes {
		if route.ID == routeID {
			found = true
			continue
		}
		nextRoutes = append(nextRoutes, route)
	}
	if !found {
		return fmt.Errorf("route not found")
	}

	return s.persistRoutesLocked(nextRoutes)
}

func (s *Server) replacePersistedRoutes(routes []config.Route) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.persistRoutesLocked(routes)
}

func (s *Server) persistRoutesLocked(routes []config.Route) error {
	cloned := cloneRoutes(routes)
	if err := config.ValidateRoutes(cloned); err != nil {
		return err
	}

	runtimes, err := s.buildRouteRuntime(cloned)
	if err != nil {
		return err
	}

	if err := config.SaveRoutesFile(s.cfg.RoutesPath, cloned); err != nil {
		closeRouteRuntimes(runtimes)
		return err
	}

	oldRuntimes := s.runtime
	s.routes = cloned
	s.runtime = runtimes
	s.cfg.Routes = cloneRoutes(cloned)
	closeRouteRuntimes(oldRuntimes)
	s.mcpSessions.closeAll()
	return nil
}

func (s *Server) buildRouteRuntime(routes []config.Route) (map[string]routeRuntime, error) {
	runtimes := make(map[string]routeRuntime, len(routes))
	for _, route := range cloneRoutes(routes) {
		var (
			handler    http.Handler
			closeFn    func() error
			revalidate func()
			err        error
		)
		switch route.Transport {
		case "stdio":
			routeID := route.ID
			var bridge *stdioBridge
			bridge, err = newStdioBridgeWithOptions(route, s.resolveStdioSecrets, stdioBridgeOptions{
				IdleTimeout: s.cfg.StdioSessions.IdleTimeout,
				MaxPerAgent: s.cfg.StdioSessions.MaxSessionsPerUser,
				MaxPerRoute: s.cfg.StdioSessions.MaxSessionsRoute,
				Authorize: func(identity *auth.Identity) bool {
					return s.sessionStillAuthorized(routeID, identity)
				},
			})
			if bridge != nil {
				handler, closeFn, revalidate = bridge, bridge.Close, bridge.sweep
			}
		case "openapi":
			handler, err = newOpenAPIBridge(route)
		default:
			handler, err = s.newReverseProxy(route)
		}
		if err != nil {
			closeRouteRuntimes(runtimes)
			return nil, err
		}
		runtimes[route.ID] = routeRuntime{
			Route:      route,
			Handler:    newSessionBinding(route.ID, s.authManager.DeriveKey(sessionBindingKeyLabel), handler),
			Close:      closeFn,
			Revalidate: revalidate,
		}
	}
	return runtimes, nil
}

// sessionStillAuthorized reports whether the agent behind identity may still
// use the route: the user and credential still exist and the route's
// current access rules still admit the user.
func (s *Server) sessionStillAuthorized(routeID string, identity *auth.Identity) bool {
	fresh, ok := s.authManager.RevalidateIdentity(identity)
	if !ok {
		return false
	}
	route, ok := s.routeByID(routeID)
	if !ok {
		return false
	}
	return routeAccessAllowed(route, fresh)
}

// revalidateSessions closes sessions whose agent lost access. It runs after
// user, group or credential changes.
func (s *Server) revalidateSessions() {
	s.mu.RLock()
	revalidators := make([]func(), 0, len(s.runtime))
	for _, runtime := range s.runtime {
		if runtime.Revalidate != nil {
			revalidators = append(revalidators, runtime.Revalidate)
		}
	}
	s.mu.RUnlock()
	for _, revalidate := range revalidators {
		revalidate()
	}
}

func (s *Server) resolveStdioSecrets(route config.Route) (map[string]string, error) {
	if route.Stdio == nil || len(route.Stdio.EnvSecretRefs) == 0 {
		return nil, nil
	}
	return s.authManager.ResolveRouteEnvSecretRefs(route.ID, route.Stdio.EnvSecretRefs)
}

func closeRouteRuntimes(runtimes map[string]routeRuntime) {
	for _, runtime := range runtimes {
		if runtime.Close != nil {
			_ = runtime.Close()
		}
	}
}

func cloneRoutes(routes []config.Route) []config.Route {
	if len(routes) == 0 {
		return []config.Route{}
	}

	cloned := make([]config.Route, len(routes))
	for i := range routes {
		cloned[i] = routes[i]
		if routes[i].ScopesSupported != nil {
			cloned[i].ScopesSupported = append([]string(nil), routes[i].ScopesSupported...)
		}
		if routes[i].ForwardHeaders != nil {
			cloned[i].ForwardHeaders = make(map[string]string, len(routes[i].ForwardHeaders))
			for key, value := range routes[i].ForwardHeaders {
				cloned[i].ForwardHeaders[key] = value
			}
		}
		if routes[i].UpstreamEnvironment != nil {
			cloned[i].UpstreamEnvironment = make(map[string]string, len(routes[i].UpstreamEnvironment))
			for key, value := range routes[i].UpstreamEnvironment {
				cloned[i].UpstreamEnvironment[key] = value
			}
		}
		cloned[i].Access = config.RouteAccess{
			Visibility:    routes[i].Access.Visibility,
			Mode:          routes[i].Access.Mode,
			AllowedUsers:  append([]string(nil), routes[i].Access.AllowedUsers...),
			AllowedGroups: append([]string(nil), routes[i].Access.AllowedGroups...),
			DeniedUsers:   append([]string(nil), routes[i].Access.DeniedUsers...),
			DeniedGroups:  append([]string(nil), routes[i].Access.DeniedGroups...),
		}
		if routes[i].Deployment != nil {
			cloned[i].Deployment = &config.RouteDeployment{
				Type:          routes[i].Deployment.Type,
				Managed:       routes[i].Deployment.Managed,
				Image:         routes[i].Deployment.Image,
				ContainerName: routes[i].Deployment.ContainerName,
				InternalPort:  routes[i].Deployment.InternalPort,
				Networks:      append([]string(nil), routes[i].Deployment.Networks...),
				RestartPolicy: routes[i].Deployment.RestartPolicy,
			}
		}
		if routes[i].Stdio != nil {
			cloned[i].Stdio = &config.RouteStdio{
				Command:       routes[i].Stdio.Command,
				Args:          append([]string(nil), routes[i].Stdio.Args...),
				EnvSecretRefs: cloneStringMap(routes[i].Stdio.EnvSecretRefs),
				WorkingDir:    routes[i].Stdio.WorkingDir,
			}
			if routes[i].Stdio.Env != nil {
				cloned[i].Stdio.Env = make(map[string]string, len(routes[i].Stdio.Env))
				for key, value := range routes[i].Stdio.Env {
					cloned[i].Stdio.Env[key] = value
				}
			}
		}
		if routes[i].OpenAPI != nil {
			cloned[i].OpenAPI = &config.RouteOpenAPI{
				SpecPath:       routes[i].OpenAPI.SpecPath,
				SpecURL:        routes[i].OpenAPI.SpecURL,
				BaseURL:        routes[i].OpenAPI.BaseURL,
				Headers:        cloneStringMap(routes[i].OpenAPI.Headers),
				TimeoutSeconds: routes[i].OpenAPI.TimeoutSeconds,
			}
		}
	}
	return cloned
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
