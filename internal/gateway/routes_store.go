package gateway

import (
	"fmt"
	"net/http/httputil"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

type routeRuntime struct {
	Route config.Route
	Proxy *httputil.ReverseProxy
}

func (s *Server) replaceRoutes(routes []config.Route) error {
	runtimes, err := buildRouteRuntime(routes)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes = cloneRoutes(routes)
	s.runtime = runtimes
	s.cfg.Routes = cloneRoutes(routes)
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

func (s *Server) routeByProxyPath(requestPath string) (config.Route, *httputil.ReverseProxy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, route := range s.routes {
		if matchesExactOrChildPath(requestPath, route.PublicMCPPath()) {
			runtime, ok := s.runtime[route.ID]
			if !ok {
				return config.Route{}, nil, false
			}
			return runtime.Route, runtime.Proxy, true
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

func (s *Server) persistRoutesLocked(routes []config.Route) error {
	cloned := cloneRoutes(routes)
	if err := config.ValidateRoutes(cloned); err != nil {
		return err
	}

	runtimes, err := buildRouteRuntime(cloned)
	if err != nil {
		return err
	}

	if err := config.SaveRoutesFile(s.cfg.RoutesPath, cloned); err != nil {
		return err
	}

	s.routes = cloned
	s.runtime = runtimes
	s.cfg.Routes = cloneRoutes(cloned)
	return nil
}

func buildRouteRuntime(routes []config.Route) (map[string]routeRuntime, error) {
	runtimes := make(map[string]routeRuntime, len(routes))
	for _, route := range cloneRoutes(routes) {
		proxy, err := newReverseProxy(route)
		if err != nil {
			return nil, err
		}
		runtimes[route.ID] = routeRuntime{
			Route: route,
			Proxy: proxy,
		}
	}
	return runtimes, nil
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
	}
	return cloned
}
