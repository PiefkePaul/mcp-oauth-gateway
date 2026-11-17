package gateway

import (
	"log"
	"net/http"
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

// forwardHeaderSeal is what sealForwardHeaderSecrets leaves to do once the
// outcome of saving the routes is known.
type forwardHeaderSeal struct {
	// commit drops stored values of headers the saved routes no longer
	// have. Until then the routes that are still active can use them.
	commit func()
	// rollback puts back the stored values that were replaced.
	rollback func()
}

// sealForwardHeaderSecrets moves credentials out of the routes' forward
// headers into the encrypted auth store and leaves a marker in their place,
// so routes.yaml, exports and the admin form no longer contain them.
//
// Nothing the active routes rely on is removed here: stored values of
// headers that were dropped from a route are only deleted by commit, after
// the new routes are built and written. If that fails, rollback restores
// the values this call replaced, so the old routes keep working.
func (s *Server) sealForwardHeaderSecrets(routes []config.Route) (forwardHeaderSeal, error) {
	var commits, rollbacks []func()
	seal := forwardHeaderSeal{
		commit: func() {
			for _, commit := range commits {
				commit()
			}
		},
		rollback: func() {
			for i := len(rollbacks) - 1; i >= 0; i-- {
				rollbacks[i]()
			}
		},
	}

	active := make(map[string]config.Route, len(s.routes))
	for _, route := range s.routes {
		active[route.ID] = route
	}

	for i := range routes {
		route := &routes[i]
		routeID := route.ID
		previous := active[routeID].ForwardHeaders

		secrets := map[string]string{}
		keep := make([]string, 0, len(route.ForwardHeaders))
		for name, value := range route.ForwardHeaders {
			switch {
			case value == config.ForwardHeaderSecretMarker:
				keep = append(keep, name)
				if _, stored := s.authManager.RouteForwardHeaderSecret(routeID, name); stored {
					continue
				}
				// Header names are case-insensitive: a header that was only
				// respelled ("X-Api-Key" to "x-api-key") keeps its value.
				for previousName := range previous {
					if previousName == name || !strings.EqualFold(previousName, name) {
						continue
					}
					if stored, ok := s.authManager.RouteForwardHeaderSecret(routeID, previousName); ok {
						secrets[name] = stored
						break
					}
				}
			case forwardHeaderNeedsSealing(name, value):
				secrets[name] = value
				keep = append(keep, name)
			}
		}

		// While the outcome is open, keep everything the active route uses.
		keepForNow := append([]string(nil), keep...)
		for previousName := range previous {
			keepForNow = append(keepForNow, previousName)
		}
		replaced := map[string]string{}
		for name := range secrets {
			if stored, ok := s.authManager.RouteForwardHeaderSecret(routeID, name); ok {
				replaced[name] = stored
			}
		}
		previousNames := make([]string, 0, len(previous))
		for previousName := range previous {
			previousNames = append(previousNames, previousName)
		}
		rollbacks = append(rollbacks, func() {
			if err := s.authManager.SyncRouteForwardHeaderSecrets(routeID, replaced, previousNames); err != nil {
				log.Printf("forward header credentials of route %s could not be restored after a failed save: %v", routeID, err)
			}
		})
		if err := s.authManager.SyncRouteForwardHeaderSecrets(routeID, secrets, keepForNow); err != nil {
			seal.rollback()
			return forwardHeaderSeal{}, err
		}
		commits = append(commits, func() {
			if err := s.authManager.SyncRouteForwardHeaderSecrets(routeID, nil, keep); err != nil {
				log.Printf("unused forward header credentials of route %s could not be removed from the auth store: %v", routeID, err)
			}
		})
		for name, value := range route.ForwardHeaders {
			if forwardHeaderNeedsSealing(name, value) {
				route.ForwardHeaders[name] = config.ForwardHeaderSecretMarker
			}
		}
	}
	return seal, nil
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
	log.Printf("forward header credentials were moved from the routes file to the encrypted auth store; gateway versions without this store cannot use the rewritten file, so a rollback needs the previous routes file")
}

// forwardHeaderTemplate returns the template to send for a forward header:
// the stored credential when the route only holds the marker, otherwise the
// template itself. A marker without a stored value yields "", which drops
// the header.
func (s *Server) forwardHeaderTemplate(routeID, name, template string) string {
	if template != config.ForwardHeaderSecretMarker {
		return template
	}
	if value, ok := s.authManager.RouteForwardHeaderSecret(routeID, name); ok {
		return value
	}
	// Header names are case-insensitive. A routes file edited by hand may
	// spell the header differently from the stored value.
	for _, spelling := range []string{http.CanonicalHeaderKey(name), strings.ToLower(name)} {
		if spelling == name {
			continue
		}
		if value, ok := s.authManager.RouteForwardHeaderSecret(routeID, spelling); ok {
			return value
		}
	}
	return ""
}
