package gateway

import (
	"log"
	"strings"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

// sensitiveForwardHeader reports whether a forward header usually carries a
// credential, judged by its name.
func sensitiveForwardHeader(name string) bool {
	return looksSensitiveKey(name) || strings.Contains(strings.ToLower(name), "cookie")
}

// forwardHeaderNeedsSealing reports whether a header value is a credential
// still written out in the route.
func forwardHeaderNeedsSealing(name, value string) bool {
	return value != "" && value != config.ForwardHeaderSecretMarker && sensitiveForwardHeader(name)
}

// sealForwardHeaderSecrets moves credentials out of the routes' forward
// headers into the encrypted auth store and leaves a marker in their place,
// so routes.yaml, exports and the admin form no longer contain them. Stored
// values of headers that were removed from a route are dropped.
func (s *Server) sealForwardHeaderSecrets(routes []config.Route) error {
	for i := range routes {
		route := &routes[i]
		secrets := map[string]string{}
		keep := make([]string, 0, len(route.ForwardHeaders))
		for name, value := range route.ForwardHeaders {
			switch {
			case value == config.ForwardHeaderSecretMarker:
				keep = append(keep, name)
			case forwardHeaderNeedsSealing(name, value):
				secrets[name] = value
				keep = append(keep, name)
			}
		}
		if err := s.authManager.SyncRouteForwardHeaderSecrets(route.ID, secrets, keep); err != nil {
			return err
		}
		for name := range secrets {
			route.ForwardHeaders[name] = config.ForwardHeaderSecretMarker
		}
	}
	return nil
}

// sealStoredForwardHeaders migrates a routes file that still has
// credentials in forward headers, as written by older versions or by hand.
// If the file cannot be rewritten the gateway keeps working with the values
// as they are.
func (s *Server) sealStoredForwardHeaders() {
	s.mu.Lock()
	defer s.mu.Unlock()

	needed := false
	for _, route := range s.routes {
		for name, value := range route.ForwardHeaders {
			if forwardHeaderNeedsSealing(name, value) {
				needed = true
			}
		}
	}
	if !needed {
		return
	}
	if err := s.persistRoutesLocked(s.routes); err != nil {
		log.Printf("forward header credentials could not be moved to the auth store and stay in the routes file: %v", err)
		return
	}
	log.Printf("forward header credentials were moved from the routes file to the encrypted auth store")
}

// forwardHeaderTemplate returns the template to send for a forward header:
// the stored credential when the route only holds the marker, otherwise the
// template itself. A marker without a stored value yields "", which drops
// the header.
func (s *Server) forwardHeaderTemplate(routeID, name, template string) string {
	if template != config.ForwardHeaderSecretMarker {
		return template
	}
	value, _ := s.authManager.RouteForwardHeaderSecret(routeID, name)
	return value
}
