package gateway

import (
	"context"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

const (
	mcpSessionIdleTTL      = 10 * time.Minute
	mcpSessionToolsTTL     = time.Minute
	mcpSessionToolsMinAge  = 5 * time.Second
	mcpSessionMaxEntries   = 256
	mcpSessionCloseTimeout = 10 * time.Second
)

// mcpSessionPool keeps initialized MCP sessions for the OpenAPI adapter, one
// per route and user, so OpenAPI tool calls do not pay for initialize,
// tools/list and (for STDIO routes) a process start on every request.
type mcpSessionPool struct {
	idleTTL    time.Duration
	toolsTTL   time.Duration
	maxEntries int

	mu      sync.Mutex
	entries map[mcpSessionKey]*mcpPooledSession
}

type mcpSessionKey struct {
	routeID string
	userID  string
}

type mcpPooledSession struct {
	pool    *mcpSessionPool
	key     mcpSessionKey
	handler http.Handler
	caller  *mcpRouteCaller

	// Guarded by pool.mu.
	inFlight  int
	lastUsed  time.Time
	retired   bool
	closed    bool
	timer     *time.Timer
	lastCreds mcpCallCredentials

	toolsMu      sync.Mutex
	tools        []mcpToolDefinition
	toolsFetched time.Time
}

func newMCPSessionPool() *mcpSessionPool {
	return &mcpSessionPool{
		idleTTL:    mcpSessionIdleTTL,
		toolsTTL:   mcpSessionToolsTTL,
		maxEntries: mcpSessionMaxEntries,
		entries:    make(map[mcpSessionKey]*mcpPooledSession),
	}
}

func mcpSessionUserKey(identity *auth.Identity) string {
	if identity == nil {
		return ""
	}
	if identity.UserID != "" {
		return "user:" + identity.UserID
	}
	return "email:" + identity.Email
}

// acquire returns the pooled session for route and identity, creating it if
// needed. Every acquire must be paired with release.
func (p *mcpSessionPool) acquire(route config.Route, handler http.Handler, identity *auth.Identity, authHeader string) *mcpPooledSession {
	key := mcpSessionKey{routeID: route.ID, userID: mcpSessionUserKey(identity)}
	creds := mcpCallCredentials{identity: identity, authHeader: authHeader}

	p.mu.Lock()
	defer p.mu.Unlock()

	entry := p.entries[key]
	if entry != nil && !sameHTTPHandler(entry.handler, handler) {
		// The route was rebuilt since this session was created.
		p.retireLocked(entry)
		entry = nil
	}
	if entry == nil {
		p.evictForInsertLocked()
		entry = &mcpPooledSession{
			pool:    p,
			key:     key,
			handler: handler,
			caller:  newMCPRouteCaller(route, handler, nil, ""),
		}
		p.entries[key] = entry
	}
	entry.inFlight++
	entry.lastUsed = time.Now()
	entry.lastCreds = creds
	return entry
}

func (p *mcpSessionPool) release(entry *mcpPooledSession) {
	p.mu.Lock()
	defer p.mu.Unlock()

	entry.inFlight--
	entry.lastUsed = time.Now()
	if entry.inFlight > 0 {
		return
	}
	if entry.retired {
		p.closeLocked(entry)
		return
	}
	if entry.timer == nil {
		entry.timer = time.AfterFunc(p.idleTTL, func() { p.expire(entry) })
	} else {
		entry.timer.Reset(p.idleTTL)
	}
}

// invalidate drops entry from the pool; it is closed once no call uses it.
func (p *mcpSessionPool) invalidate(entry *mcpPooledSession) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.retireLocked(entry)
}

// closeAll drops every pooled session, e.g. after the routes were rebuilt.
func (p *mcpSessionPool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, entry := range p.entries {
		p.retireLocked(entry)
	}
}

func (p *mcpSessionPool) expire(entry *mcpPooledSession) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if entry.retired || entry.inFlight > 0 {
		return
	}
	if idle := time.Since(entry.lastUsed); idle < p.idleTTL {
		entry.timer.Reset(p.idleTTL - idle)
		return
	}
	p.retireLocked(entry)
}

func (p *mcpSessionPool) retireLocked(entry *mcpPooledSession) {
	if p.entries[entry.key] == entry {
		delete(p.entries, entry.key)
	}
	entry.retired = true
	if entry.inFlight == 0 {
		p.closeLocked(entry)
	}
}

func (p *mcpSessionPool) evictForInsertLocked() {
	if len(p.entries) < p.maxEntries {
		return
	}
	var oldest *mcpPooledSession
	for _, entry := range p.entries {
		if entry.inFlight > 0 {
			continue
		}
		if oldest == nil || entry.lastUsed.Before(oldest.lastUsed) {
			oldest = entry
		}
	}
	// When every session is busy the pool temporarily grows past the limit.
	if oldest != nil {
		p.retireLocked(oldest)
	}
}

func (p *mcpSessionPool) closeLocked(entry *mcpPooledSession) {
	if entry.closed {
		return
	}
	entry.closed = true
	if entry.timer != nil {
		entry.timer.Stop()
	}
	creds := entry.lastCreds
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), mcpSessionCloseTimeout)
		defer cancel()
		entry.caller.close(withMCPCallCredentials(ctx, creds.identity, creds.authHeader))
	}()
}

func (e *mcpPooledSession) listTools(ctx context.Context, forceRefresh bool) ([]mcpToolDefinition, error) {
	e.toolsMu.Lock()
	defer e.toolsMu.Unlock()
	if e.tools != nil {
		age := time.Since(e.toolsFetched)
		// A forced refresh is still throttled so requests for unknown
		// operations cannot trigger a tools/list round trip every time.
		if age < mcpSessionToolsMinAge || (!forceRefresh && age < e.pool.toolsTTL) {
			return e.tools, nil
		}
	}
	tools, err := e.caller.listTools(ctx)
	if err != nil {
		return nil, err
	}
	e.tools = tools
	e.toolsFetched = time.Now()
	return tools, nil
}

// withMCPSession runs fn on the pooled session for route and identity. Broken
// sessions are dropped from the pool; if the server rejected the session ID
// (so the request was not processed) fn is retried once on a fresh session.
func (s *Server) withMCPSession(ctx context.Context, route config.Route, handler http.Handler, identity *auth.Identity, authHeader string, fn func(context.Context, *mcpPooledSession) error) error {
	ctx = withMCPCallCredentials(ctx, identity, authHeader)
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		entry := s.mcpSessions.acquire(route, handler, identity, authHeader)
		err = fn(ctx, entry)
		if mcpSessionBroken(ctx, err) {
			s.mcpSessions.invalidate(entry)
		}
		s.mcpSessions.release(entry)
		if !mcpSessionRejected(err) {
			return err
		}
	}
	return err
}

func sameHTTPHandler(a, b http.Handler) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ta, tb := reflect.TypeOf(a), reflect.TypeOf(b)
	if ta != tb || !ta.Comparable() {
		return false
	}
	return a == b
}
