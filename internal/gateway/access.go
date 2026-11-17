package gateway

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

func (s *Server) authorizeResourceAccess(identity *auth.Identity, resource string) error {
	if s.isGatewayWideResource(resource) {
		return nil
	}
	route, ok := s.routeByResourceURL(resource)
	if !ok {
		return fmt.Errorf("unknown MCP resource")
	}
	if !routeAccessAllowed(route, identity) {
		return fmt.Errorf("your account is not allowed to use this MCP server")
	}
	return nil
}

// listAccessibleResources returns the MCP servers identity may use, for the
// choice on the consent page when a client names no resource.
func (s *Server) listAccessibleResources(identity *auth.Identity) []auth.ResourceOption {
	options := []auth.ResourceOption{}
	for _, route := range s.routesSnapshot() {
		if !routeAccessAllowed(route, identity) {
			continue
		}
		name := strings.TrimSpace(route.DisplayName)
		if name == "" {
			name = route.ID
		}
		options = append(options, auth.ResourceOption{URL: s.absoluteURL(route.PublicMCPPath()), Name: name})
	}
	slices.SortFunc(options, func(a, b auth.ResourceOption) int {
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return options
}

func (s *Server) isGatewayWideResource(resource string) bool {
	baseURL := strings.TrimSpace(s.cfg.PublicBaseURL)
	return baseURL != "" && normalizeAbsoluteURL(resource) == normalizeAbsoluteURL(baseURL)
}

func (s *Server) routeByResourceURL(resource string) (config.Route, bool) {
	normalizedResource := normalizeAbsoluteURL(resource)
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, route := range s.routes {
		if normalizeAbsoluteURL(s.absoluteURL(route.PublicMCPPath())) == normalizedResource {
			return route, true
		}
	}
	return config.Route{}, false
}

func routeAccessAllowed(route config.Route, identity *auth.Identity) bool {
	if identity == nil {
		return false
	}

	access := route.Access
	if containsFold(access.DeniedUsers, identity.Email) || intersectsFold(access.DeniedGroups, identity.GroupNames) {
		return false
	}
	if identity.IsAdmin {
		return true
	}

	switch access.EffectiveMode() {
	case "public":
		return true
	case "admin":
		return false
	case "restricted":
		return containsFold(access.AllowedUsers, identity.Email) || intersectsFold(access.AllowedGroups, identity.GroupNames)
	default:
		return false
	}
}

func routeVisibleInPublicCatalog(route config.Route) bool {
	return !route.Access.IsPrivate()
}

func containsFold(values []string, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return false
	}
	for _, value := range values {
		if strings.ToLower(strings.TrimSpace(value)) == needle {
			return true
		}
	}
	return false
}

func intersectsFold(left, right []string) bool {
	for _, value := range left {
		if containsFold(right, value) {
			return true
		}
	}
	return false
}

func normalizeAbsoluteURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimRight(strings.TrimSpace(raw), "/")
	}
	parsed.Fragment = ""
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed.String()
}

func valuesFromSelection(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || slices.Contains(out, value) {
			continue
		}
		out = append(out, value)
	}
	return out
}
