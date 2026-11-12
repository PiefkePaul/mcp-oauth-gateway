package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// sessionCookieFor signs email in and returns the browser session cookie.
func sessionCookieFor(t *testing.T, manager *Manager, email string) *http.Cookie {
	t.Helper()
	manager.mu.Lock()
	userID := manager.data.EmailIndex[email]
	manager.mu.Unlock()
	if userID == "" {
		t.Fatalf("unknown user %s", email)
	}
	rec := httptest.NewRecorder()
	if err := manager.startSession(rec, httptest.NewRequest(http.MethodGet, "https://mcp.example.com/", nil), userID); err != nil {
		t.Fatalf("start session: %v", err)
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			return cookie
		}
	}
	t.Fatalf("no session cookie set")
	return nil
}

func loginRequest(email, password, remoteAddr string) *http.Request {
	form := url.Values{"email": {email}, "password": {password}, "csrf_token": {"csrf"}}
	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/account/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf"})
	req.RemoteAddr = remoteAddr
	return req
}

func TestLoginIsThrottledAfterRepeatedFailures(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	attacker := "203.0.113.7:4000"

	for i := 0; i < loginPairLimit; i++ {
		rec := httptest.NewRecorder()
		manager.HandleAccountLogin(rec, loginRequest("admin@example.com", "wrong-password", attacker))
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: expected the login form, got %d", i, rec.Code)
		}
	}

	// Even the right password is refused while the client is blocked.
	rec := httptest.NewRecorder()
	manager.HandleAccountLogin(rec, loginRequest("admin@example.com", "super-secret-password", attacker))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after %d failures, got %d", loginPairLimit, rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatalf("expected a Retry-After header")
	}

	// Another client is not locked out by the attacker's failures.
	rec = httptest.NewRecorder()
	manager.HandleAccountLogin(rec, loginRequest("admin@example.com", "super-secret-password", "198.51.100.9:5000"))
	if rec.Code != http.StatusFound {
		t.Fatalf("expected the owner to still sign in from another address, got %d", rec.Code)
	}

	// The block ends on its own.
	manager.limiter.now = func() time.Time { return time.Now().Add(loginPairBlock + time.Minute) }
	rec = httptest.NewRecorder()
	manager.HandleAccountLogin(rec, loginRequest("admin@example.com", "super-secret-password", attacker))
	if rec.Code != http.StatusFound {
		t.Fatalf("expected the login to work after the block, got %d", rec.Code)
	}
}

func TestLoginThrottleStopsDistributedGuessing(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	for i := 0; i < loginEmailLimit; i++ {
		manager.recordLoginFailure("admin@example.com", "203.0.113."+string(rune('0'+i%10))+":1")
	}
	if manager.loginBlockedFor("admin@example.com", "198.51.100.9") == 0 {
		t.Fatalf("expected the account to be throttled after %d failures from many addresses", loginEmailLimit)
	}
}

func TestClientIPOnlyTrustsForwardingHeadersFromProxies(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")

	direct := httptest.NewRequest(http.MethodGet, "/", nil)
	direct.RemoteAddr = "203.0.113.7:4000"
	direct.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := manager.clientIP(direct); got != "203.0.113.7" {
		t.Fatalf("a public peer must not choose its own address, got %s", got)
	}

	proxied := httptest.NewRequest(http.MethodGet, "/", nil)
	proxied.RemoteAddr = "172.18.0.5:4000"
	proxied.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.9, 10.0.0.2")
	if got := manager.clientIP(proxied); got != "198.51.100.9" {
		t.Fatalf("expected the right-most untrusted address, got %s", got)
	}

	manager.cfg.ClientIPHeader = "CF-Connecting-IP"
	proxied.Header.Set("CF-Connecting-IP", "192.0.2.44")
	if got := manager.clientIP(proxied); got != "192.0.2.44" {
		t.Fatalf("expected the configured client header to win, got %s", got)
	}
	direct.Header.Set("CF-Connecting-IP", "192.0.2.44")
	if got := manager.clientIP(direct); got != "203.0.113.7" {
		t.Fatalf("the client header must be ignored from untrusted peers, got %s", got)
	}
}

func TestSanitizeNextRejectsOtherHosts(t *testing.T) {
	for _, next := range []string{"//evil.example", "/\\evil.example", "https://evil.example", "evil", "/ok\r\nX: y", "///evil.example/x"} {
		if got := sanitizeNext(next); got != "" {
			t.Errorf("sanitizeNext(%q) = %q, want it rejected", next, got)
		}
	}
	for _, next := range []string{"/account", "/authorize?client_id=a&redirect_uri=https%3A%2F%2Fx.example%2Fcb", "/admin?route=x"} {
		if got := sanitizeNext(next); got != next {
			t.Errorf("sanitizeNext(%q) = %q, want it kept", next, got)
		}
	}
}

func TestCSRFRejectsForeignOrigins(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	manager.cfg.PublicBaseURL = "https://mcp.example.com"

	newRequest := func(host string, headers map[string]string) *http.Request {
		form := url.Values{"csrf_token": {"csrf"}}
		req := httptest.NewRequest(http.MethodPost, "http://"+host+"/account/logout", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf"})
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		return req
	}

	cases := []struct {
		name    string
		host    string
		headers map[string]string
		want    bool
	}{
		{"no browser headers", "mcp.example.com", nil, true},
		{"public origin", "gateway:8080", map[string]string{"Origin": "https://mcp.example.com"}, true},
		{"direct LAN origin", "192.168.1.5:40013", map[string]string{"Origin": "http://192.168.1.5:40013"}, true},
		{"foreign origin", "mcp.example.com", map[string]string{"Origin": "https://evil.example"}, false},
		{"sibling subdomain", "mcp.example.com", map[string]string{"Origin": "https://other.example.com"}, false},
		{"null origin", "mcp.example.com", map[string]string{"Origin": "null"}, false},
		{"cross-site fetch metadata", "mcp.example.com", map[string]string{"Sec-Fetch-Site": "cross-site"}, false},
		{"same-site fetch metadata", "mcp.example.com", map[string]string{"Sec-Fetch-Site": "same-site"}, false},
		{"same-origin fetch metadata", "mcp.example.com", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://mcp.example.com"}, true},
	}
	for _, tc := range cases {
		if got := manager.ValidateCSRF(newRequest(tc.host, tc.headers)); got != tc.want {
			t.Errorf("%s: ValidateCSRF = %t, want %t", tc.name, got, tc.want)
		}
	}
}

func TestPasswordChangeEndsOtherSessions(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	current := sessionCookieFor(t, manager, "admin@example.com")
	stolen := sessionCookieFor(t, manager, "admin@example.com")

	manager.mu.Lock()
	userID := manager.data.EmailIndex["admin@example.com"]
	manager.mu.Unlock()
	if err := manager.changeUserPassword(userID, "super-secret-password", "fresh-secret-password", current.Value); err != nil {
		t.Fatalf("change password: %v", err)
	}

	identityFor := func(cookie *http.Cookie) error {
		req := httptest.NewRequest(http.MethodGet, "/account", nil)
		req.AddCookie(cookie)
		_, err := manager.CurrentIdentity(req)
		return err
	}
	if err := identityFor(current); err != nil {
		t.Fatalf("the session that changed the password must stay signed in: %v", err)
	}
	if err := identityFor(stolen); err == nil {
		t.Fatalf("other sessions must end when the password changes")
	}

	if err := manager.SetUserPassword(userID, "another-secret-password"); err != nil {
		t.Fatalf("admin reset: %v", err)
	}
	if err := identityFor(current); err == nil {
		t.Fatalf("an admin password reset must end every session")
	}
}

func TestClientRegistryIsBounded(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	old := time.Now().Add(-2 * unusedClientGracePeriod).Unix()

	manager.mu.Lock()
	for i := 0; i < maxRegisteredClients; i++ {
		id := randomToken(12)
		manager.data.Clients[id] = &clientRecord{ID: id, CreatedAt: old, UpdatedAt: old}
	}
	// One old client is in use and must survive pruning.
	manager.data.Clients["in-use"] = &clientRecord{ID: "in-use", CreatedAt: old, UpdatedAt: old}
	manager.data.RefreshTokens["rt"] = &refreshTokenRecord{Token: "rt", ClientID: "in-use", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	manager.mu.Unlock()

	if _, err := manager.registerClient("New", []string{"https://client.example/cb"}, nil, nil, "none"); err != nil {
		t.Fatalf("expected unused clients to make room: %v", err)
	}
	manager.mu.Lock()
	_, kept := manager.data.Clients["in-use"]
	count := len(manager.data.Clients)
	manager.mu.Unlock()
	if !kept {
		t.Fatalf("a client with tokens must not be pruned")
	}
	if count != 2 {
		t.Fatalf("expected only the in-use and the new client to remain, got %d", count)
	}
}

func TestRedirectPageCannotBreakOutOfScript(t *testing.T) {
	literal := jsStringLiteral(`https://x.example/cb?a=</script><script>alert(1)</script>`)
	if strings.Contains(literal, "<") || strings.Contains(literal, ">") {
		t.Fatalf("angle brackets must be escaped inside the inline script, got %s", literal)
	}
}
