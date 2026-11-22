package gateway

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

// Where a route's upstream bearer comes from.
const (
	bearerSourceNone    = ""        // the route sends no upstream bearer
	bearerSourceUser    = "user"    // the user's own bearer from the auth store
	bearerSourceFile    = "file"    // the route secrets file
	bearerSourceStore   = "store"   // the route's bearer from the auth store
	bearerSourceMissing = "missing" // strict mode: expected in the file, not there
)

// resolveUpstreamBearer picks the bearer the gateway sends to a route's
// upstream. Order: the user's own bearer, the route secrets file, the
// route's bearer in the auth store.
//
// In strict mode the auth store's route bearer is never sent. A route that
// still has one stored, or that names its key with upstream_bearer_key, is
// then expected to be in the file; if it is not, the source is
// bearerSourceMissing and the request must not be forwarded. Routes that
// never had an upstream bearer are not affected by strict mode.
func (s *Server) resolveUpstreamBearer(route config.Route, identity *auth.Identity) (token, source string) {
	if token, ok := s.authManager.RouteUserUpstreamBearer(route.ID, identity); ok {
		return token, bearerSourceUser
	}
	if s.routeSecrets == nil {
		if token, ok := s.authManager.RouteGlobalUpstreamBearer(route.ID); ok {
			return token, bearerSourceStore
		}
		return "", bearerSourceNone
	}
	if token, ok := s.routeSecrets.Lookup(route.UpstreamBearerSecretKey()); ok {
		return token, bearerSourceFile
	}
	stored, hasStored := s.authManager.RouteGlobalUpstreamBearer(route.ID)
	if !s.cfg.RouteSecrets.Strict {
		if hasStored {
			return stored, bearerSourceStore
		}
		return "", bearerSourceNone
	}
	if hasStored || route.UpstreamBearerKey != "" {
		return "", bearerSourceMissing
	}
	return "", bearerSourceNone
}

// routeBearerSource is resolveUpstreamBearer for a request without a user,
// which is what the admin pages and the health check describe.
func (s *Server) routeBearerSource(route config.Route) string {
	_, source := s.resolveUpstreamBearer(route, nil)
	return source
}

// routeBearerAvailable reports whether the route has a bearer that does not
// depend on the user.
func (s *Server) routeBearerAvailable(route config.Route) bool {
	source := s.routeBearerSource(route)
	return source == bearerSourceFile || source == bearerSourceStore
}

// routeBearerSourceLabel describes the source for the admin pages. It never
// contains the value.
func (s *Server) routeBearerSourceLabel(route config.Route) string {
	switch s.routeBearerSource(route) {
	case bearerSourceFile:
		label := fmt.Sprintf("aus der Secrets-Datei (%s", route.UpstreamBearerSecretKey())
		if loadedAt := s.routeSecrets.LoadedAt(); !loadedAt.IsZero() {
			label += ", Datei geladen " + loadedAt.Format("2006-01-02 15:04:05")
		}
		return label + ")"
	case bearerSourceStore:
		if s.routeSecrets != nil {
			return fmt.Sprintf("aus dem Admin-Formular; in der Secrets-Datei fehlt %s", route.UpstreamBearerSecretKey())
		}
		return "aus dem Admin-Formular"
	case bearerSourceMissing:
		return fmt.Sprintf("fehlt: %s steht nicht in der Secrets-Datei, die Route wird nicht weitergeleitet", route.UpstreamBearerSecretKey())
	}
	return "nicht gesetzt"
}

// upstreamBearerMissingBody answers a request the gateway does not forward
// because strict mode found no bearer for the route.
const upstreamBearerMissingBody = `{"error":"upstream_bearer_missing","error_description":"the gateway has no upstream credential configured for this route"}` + "\n"

func writeUpstreamBearerMissing(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Retry-After", "30")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(upstreamBearerMissingBody))
}

// missingBearerLog limits the log line about a missing bearer to one per
// route and minute.
func (s *Server) logMissingBearer(route config.Route) {
	now := time.Now()
	s.missingBearerMu.Lock()
	defer s.missingBearerMu.Unlock()
	if last, ok := s.missingBearerLogged[route.ID]; ok && now.Sub(last) < time.Minute {
		return
	}
	if s.missingBearerLogged == nil {
		s.missingBearerLogged = map[string]time.Time{}
	}
	s.missingBearerLogged[route.ID] = now
	log.Printf("gateway does not forward route=%s: key %s is not in the route secrets file (strict mode)", route.ID, route.UpstreamBearerSecretKey())
}
