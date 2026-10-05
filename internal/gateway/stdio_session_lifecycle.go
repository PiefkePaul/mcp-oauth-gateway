package gateway

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
)

const (
	defaultStdioSessionIdleTimeout = 30 * time.Minute
	defaultStdioMaxSessionsAgent   = 8
	defaultStdioMaxSessionsRoute   = 64
	maxStdioSweepInterval          = time.Minute
)

var (
	errStdioSessionUnknown = errors.New("unknown stdio session")
	errStdioAgentLimit     = errors.New("too many open sessions for this agent on this route; close one or retry later")
	errStdioRouteLimit     = errors.New("this route has reached its session limit; retry later")
)

// stdioBridgeOptions bound the number and lifetime of STDIO processes.
type stdioBridgeOptions struct {
	// IdleTimeout closes sessions without requests or open streams.
	IdleTimeout time.Duration
	// MaxPerAgent caps the sessions of one agent (auth.Identity.OwnerKey) on
	// the route. The agent's least recently used idle session makes room for
	// a new one; if all are busy the new one is refused.
	MaxPerAgent int
	// MaxPerRoute caps all sessions on the route. Other agents' sessions are
	// never evicted to make room.
	MaxPerRoute int
	// SweepInterval is how often idle, exited and revoked sessions are
	// cleaned up. Zero derives it from IdleTimeout.
	SweepInterval time.Duration
	// Authorize reports whether the agent that opened a session may still
	// use the route. Sessions failing it are closed. Nil skips the check.
	Authorize func(*auth.Identity) bool
}

func (o stdioBridgeOptions) withDefaults() stdioBridgeOptions {
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = defaultStdioSessionIdleTimeout
	}
	if o.MaxPerAgent <= 0 {
		o.MaxPerAgent = defaultStdioMaxSessionsAgent
	}
	if o.MaxPerRoute <= 0 {
		o.MaxPerRoute = defaultStdioMaxSessionsRoute
	}
	if o.SweepInterval <= 0 {
		o.SweepInterval = min(o.IdleTimeout/4, maxStdioSweepInterval)
	}
	return o
}

// makeRoomLocked enforces the limits before a new session of owner is
// created. It may evict one idle session of the same owner.
func (b *stdioBridge) makeRoomLocked(owner string) error {
	var (
		ownerCount int
		oldestIdle *stdioSession
	)
	for id, session := range b.sessions {
		if session.exited() {
			delete(b.sessions, id)
			continue
		}
		if session.owner != owner {
			continue
		}
		ownerCount++
		if session.active == 0 && (oldestIdle == nil || session.lastActivity.Before(oldestIdle.lastActivity)) {
			oldestIdle = session
		}
	}
	if ownerCount >= b.opts.MaxPerAgent {
		if oldestIdle == nil {
			return errStdioAgentLimit
		}
		delete(b.sessions, oldestIdle.id)
		go func() { _ = oldestIdle.Close() }()
	}
	if len(b.sessions) >= b.opts.MaxPerRoute {
		return errStdioRouteLimit
	}
	return nil
}

func (b *stdioBridge) sweepLoop() {
	ticker := time.NewTicker(b.opts.SweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-ticker.C:
			b.sweep()
		}
	}
}

// sweep closes exited, idle and no longer authorized sessions.
func (b *stdioBridge) sweep() {
	now := time.Now()
	type candidate struct {
		session  *stdioSession
		identity *auth.Identity
	}
	var (
		victims    []*stdioSession
		candidates []candidate
	)

	b.mu.Lock()
	for id, session := range b.sessions {
		switch {
		case session.exited():
			delete(b.sessions, id)
		case session.active == 0 && now.Sub(session.lastActivity) >= b.opts.IdleTimeout:
			delete(b.sessions, id)
			victims = append(victims, session)
		case b.opts.Authorize != nil && session.identity != nil:
			candidates = append(candidates, candidate{session: session, identity: session.identity})
		}
	}
	b.mu.Unlock()

	// Check authorization without holding the bridge lock.
	var revoked []*stdioSession
	for _, c := range candidates {
		if !b.opts.Authorize(c.identity) {
			revoked = append(revoked, c.session)
		}
	}
	if len(revoked) != 0 {
		b.mu.Lock()
		for _, session := range revoked {
			if b.sessions[session.id] == session {
				delete(b.sessions, session.id)
				victims = append(victims, session)
			}
		}
		b.mu.Unlock()
	}

	for _, session := range victims {
		_ = session.Close()
	}
}

func writeStdioSessionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errStdioSessionUnknown):
		// 404 tells spec-compliant clients to start a new session.
		writeSessionNotFound(w)
	case errors.Is(err, errStdioAgentLimit):
		w.Header().Set("Retry-After", strconv.Itoa(5))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":             "too_many_sessions",
			"error_description": err.Error(),
		})
	case errors.Is(err, errStdioRouteLimit):
		w.Header().Set("Retry-After", strconv.Itoa(30))
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":             "route_session_limit",
			"error_description": err.Error(),
		})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "stdio_session_error",
			"error_description": err.Error(),
		})
	}
}
