package gateway

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

const (
	healthStatusOK      = "ok"
	healthStatusError   = "error"
	healthStatusWarning = "warning"
	healthStatusUnknown = "unknown"

	healthCheckTimeout     = 15 * time.Second
	healthCheckConcurrency = 4
	healthCheckStartDelay  = 15 * time.Second
	maxHealthErrorLength   = 300
)

// routeHealth is the result of the last reachability check of a route. A
// check runs a real MCP initialize and tools/list through the route's
// handler, so it covers the upstream, its credentials and the protocol.
type routeHealth struct {
	Status    string
	CheckedAt time.Time
	Latency   time.Duration
	ToolCount int
	// Error explains a failed check. It may name internal hosts, so it is
	// shown to admins only.
	Error string
}

type healthStore struct {
	mu      sync.RWMutex
	results map[string]routeHealth
}

func newHealthStore() *healthStore {
	return &healthStore{results: make(map[string]routeHealth)}
}

func (h *healthStore) get(routeID string) routeHealth {
	h.mu.RLock()
	defer h.mu.RUnlock()
	result, ok := h.results[routeID]
	if !ok {
		return routeHealth{Status: healthStatusUnknown}
	}
	return result
}

func (h *healthStore) set(routeID string, result routeHealth) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.results[routeID] = result
}

// retain drops results of routes that no longer exist.
func (h *healthStore) retain(routeIDs map[string]bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id := range h.results {
		if !routeIDs[id] {
			delete(h.results, id)
		}
	}
}

// checkRoute probes one route and records the result.
func (s *Server) checkRoute(ctx context.Context, routeID string) routeHealth {
	s.mu.RLock()
	runtime, ok := s.runtime[routeID]
	s.mu.RUnlock()
	if !ok {
		return routeHealth{Status: healthStatusUnknown, Error: "route not found"}
	}

	ctx, cancel := context.WithTimeout(ctx, healthCheckTimeout)
	defer cancel()

	// No identity: the probe uses the route's global upstream bearer, like
	// an anonymous OpenAPI spec request. Its session is closed right after.
	caller := newMCPRouteCaller(runtime.Route, runtime.Handler, nil, "")
	start := time.Now()
	tools, err := caller.listTools(ctx)
	latency := time.Since(start)
	closeCtx, closeCancel := context.WithTimeout(context.WithoutCancel(ctx), mcpSessionCloseTimeout)
	caller.close(closeCtx)
	closeCancel()

	result := routeHealth{Status: healthStatusOK, CheckedAt: time.Now(), Latency: latency, ToolCount: len(tools)}
	if err != nil {
		result.Status, result.Error = s.classifyHealthError(ctx, runtime.Route.ID, err)
		result.ToolCount = 0
		log.Printf("health check failed route=%s status=%s err=%s", routeID, result.Status, result.Error)
	}
	s.health.set(routeID, result)
	return result
}

func (s *Server) classifyHealthError(ctx context.Context, routeID string, err error) (status, message string) {
	text := err.Error()
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return healthStatusError, fmt.Sprintf("no answer within %s", healthCheckTimeout)
	case strings.Contains(text, "upstream_unauthorized"):
		globalBearer, userBearers := s.authManager.RouteUpstreamBearerConfigured(routeID)
		if !globalBearer && len(userBearers) != 0 {
			// Only users have their own bearers; the anonymous probe has
			// none to send, so this says nothing about real users.
			return healthStatusWarning, "the route only has user-specific upstream bearers, so the check cannot authenticate; real users may still work"
		}
		return healthStatusError, "the upstream rejected the gateway's credentials; check the route's Upstream Bearer"
	case strings.Contains(text, "bad_gateway"):
		return healthStatusError, "the upstream MCP server could not be reached"
	}
	if len(text) > maxHealthErrorLength {
		text = text[:maxHealthErrorLength] + "…"
	}
	return healthStatusError, text
}

// checkAllRoutes probes every route with bounded concurrency and returns how
// many are reachable.
func (s *Server) checkAllRoutes(ctx context.Context) (ok, total int) {
	routes := s.routesSnapshot()
	ids := make(map[string]bool, len(routes))
	for _, route := range routes {
		ids[route.ID] = true
	}
	s.health.retain(ids)

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		limiter = make(chan struct{}, healthCheckConcurrency)
	)
	for _, route := range routes {
		wg.Add(1)
		limiter <- struct{}{}
		go func(routeID string) {
			defer wg.Done()
			defer func() { <-limiter }()
			if s.checkRoute(ctx, routeID).Status == healthStatusOK {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}(route.ID)
	}
	wg.Wait()
	return ok, len(routes)
}

// startHealthChecks runs checkAllRoutes shortly after start and then every
// interval for the lifetime of the process.
func (s *Server) startHealthChecks(interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		time.Sleep(healthCheckStartDelay)
		for {
			ok, total := s.checkAllRoutes(context.Background())
			log.Printf("health check finished reachable=%d routes=%d", ok, total)
			time.Sleep(interval)
		}
	}()
}

// healthLabel returns the human label and pill style for a status.
func healthLabel(status string) (label, pill string) {
	switch status {
	case healthStatusOK:
		return "Erreichbar", "pill-success"
	case healthStatusError:
		return "Gestoert", "pill-danger"
	case healthStatusWarning:
		return "Eingeschraenkt pruefbar", "pill-warning"
	default:
		return "Noch nicht geprueft", "pill-neutral"
	}
}

// healthSince renders how long ago a check ran, e.g. "vor 3 Min".
func healthSince(checkedAt time.Time, now time.Time) string {
	if checkedAt.IsZero() {
		return ""
	}
	elapsed := now.Sub(checkedAt)
	switch {
	case elapsed < time.Minute:
		return "gerade eben"
	case elapsed < time.Hour:
		return fmt.Sprintf("vor %d Min", int(elapsed.Minutes()))
	case elapsed < 48*time.Hour:
		return fmt.Sprintf("vor %d Std", int(elapsed.Hours()))
	default:
		return fmt.Sprintf("vor %d Tagen", int(elapsed.Hours()/24))
	}
}

// healthJSON is the public, detail-free representation of a route's health.
func healthJSON(result routeHealth) map[string]any {
	payload := map[string]any{"status": result.Status}
	if !result.CheckedAt.IsZero() {
		payload["checked_at"] = result.CheckedAt.UTC().Format(time.RFC3339)
		payload["latency_ms"] = result.Latency.Milliseconds()
	}
	if result.Status == healthStatusOK {
		payload["tool_count"] = result.ToolCount
	}
	return payload
}

// healthView is what the dashboards show for a route's health. Detail is
// only filled for admins, as errors may name internal hosts.
type healthView struct {
	Status string
	Label  string
	Pill   string
	Since  string
	Detail string
}

func (s *Server) healthViewFor(routeID string, admin bool) healthView {
	result := s.health.get(routeID)
	label, pill := healthLabel(result.Status)
	view := healthView{Status: result.Status, Label: label, Pill: pill, Since: healthSince(result.CheckedAt, time.Now())}
	if !admin {
		return view
	}
	switch result.Status {
	case healthStatusOK:
		view.Detail = fmt.Sprintf("%d Tools, %d ms", result.ToolCount, result.Latency.Milliseconds())
	case healthStatusUnknown:
		view.Detail = ""
	default:
		view.Detail = result.Error
	}
	return view
}
