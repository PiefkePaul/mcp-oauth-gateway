package auth

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	// A wrong password for the same account from the same client.
	loginPairLimit  = 5
	loginPairWindow = 15 * time.Minute
	loginPairBlock  = 5 * time.Minute

	// Wrong passwords for one account from anywhere. This is deliberately
	// much higher than the pair limit: it only stops distributed guessing
	// and should not let a single client lock the account for everybody.
	loginEmailLimit  = 30
	loginEmailWindow = 15 * time.Minute
	loginEmailBlock  = 15 * time.Minute

	// Wrong passwords from one client for any account.
	loginIPLimit  = 50
	loginIPWindow = 15 * time.Minute
	loginIPBlock  = 15 * time.Minute

	// Unauthenticated dynamic client registrations per client.
	registrationIPLimit  = 30
	registrationIPWindow = time.Minute

	attemptLimiterMaxEntries = 20000
)

type attemptEntry struct {
	count        int
	windowStart  time.Time
	blockedUntil time.Time
}

// attemptLimiter counts events per key in fixed windows and blocks a key for
// a while once it exceeds its limit. It lives in memory only: a restart
// forgets all counters, which is acceptable for throttling.
type attemptLimiter struct {
	mu      sync.Mutex
	entries map[string]*attemptEntry
	now     func() time.Time
}

func newAttemptLimiter() *attemptLimiter {
	return &attemptLimiter{entries: make(map[string]*attemptEntry), now: time.Now}
}

// blockedFor reports how long key is still blocked, or zero.
func (l *attemptLimiter) blockedFor(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := l.entries[key]
	if entry == nil {
		return 0
	}
	if remaining := entry.blockedUntil.Sub(l.now()); remaining > 0 {
		return remaining
	}
	return 0
}

// record counts one event for key and blocks the key once limit events
// happened within window. It reports whether the key is now blocked.
func (l *attemptLimiter) record(key string, limit int, window, block time.Duration) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.entries) >= attemptLimiterMaxEntries {
		for candidate, entry := range l.entries {
			if now.After(entry.blockedUntil) && now.Sub(entry.windowStart) > window {
				delete(l.entries, candidate)
			}
		}
		if len(l.entries) >= attemptLimiterMaxEntries {
			// Under a flood of distinct keys, forget everything rather than
			// grow without bound.
			l.entries = make(map[string]*attemptEntry)
		}
	}

	entry := l.entries[key]
	if entry == nil || now.Sub(entry.windowStart) > window {
		entry = &attemptEntry{windowStart: now}
		l.entries[key] = entry
	}
	entry.count++
	if entry.count >= limit {
		entry.blockedUntil = now.Add(block)
		entry.count = 0
		entry.windowStart = now
		return true
	}
	return false
}

func (l *attemptLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// defaultTrustedProxies are the peers whose forwarding headers are believed
// when nothing is configured: loopback and private networks, which is where
// a reverse proxy in front of a container normally sits.
var defaultTrustedProxies = mustParsePrefixes(
	"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
)

func mustParsePrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}

func (m *Manager) trustedProxy(addr netip.Addr) bool {
	prefixes := m.cfg.TrustedProxies
	if len(prefixes) == 0 {
		prefixes = defaultTrustedProxies
	}
	addr = addr.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// clientIP returns the address used to throttle a request. Forwarding
// headers are only believed when the direct peer is a trusted proxy;
// otherwise anyone could pick a fresh address per request. With
// ClientIPHeader set (e.g. CF-Connecting-IP) that header wins; otherwise
// the right-most X-Forwarded-For entry that is not itself a trusted proxy.
func (m *Manager) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	if !m.trustedProxy(peer) {
		return peer.String()
	}

	if header := strings.TrimSpace(m.cfg.ClientIPHeader); header != "" {
		if addr, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get(header))); err == nil {
			return addr.Unmap().String()
		}
	}

	forwarded := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(forwarded) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(forwarded[i]))
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if !m.trustedProxy(addr) {
			return addr.String()
		}
	}
	return peer.String()
}

func loginPairKey(email, ip string) string { return "login-pair:" + email + "|" + ip }
func loginEmailKey(email string) string    { return "login-email:" + email }
func loginIPKey(ip string) string          { return "login-ip:" + ip }

// loginBlockedFor reports how long logins for email from ip are still
// throttled, or zero.
func (m *Manager) loginBlockedFor(email, ip string) time.Duration {
	blocked := time.Duration(0)
	for _, key := range []string{loginPairKey(email, ip), loginEmailKey(email), loginIPKey(ip)} {
		if remaining := m.limiter.blockedFor(key); remaining > blocked {
			blocked = remaining
		}
	}
	return blocked
}

func (m *Manager) recordLoginFailure(email, ip string) {
	m.limiter.record(loginPairKey(email, ip), loginPairLimit, loginPairWindow, loginPairBlock)
	m.limiter.record(loginEmailKey(email), loginEmailLimit, loginEmailWindow, loginEmailBlock)
	m.limiter.record(loginIPKey(ip), loginIPLimit, loginIPWindow, loginIPBlock)
}

func (m *Manager) recordLoginSuccess(email, ip string) {
	m.limiter.reset(loginPairKey(email, ip))
}
