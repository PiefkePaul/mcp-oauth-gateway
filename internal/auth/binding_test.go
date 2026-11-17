package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRefreshTokenReuseAfterGraceRevokesTheWholeLogin(t *testing.T) {
	login := newCredentialTestLogin(t)
	first := login.login(t)

	second, err := login.refresh(first.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	// Someone presents the already exchanged token again.
	if _, err := login.refresh(first.RefreshToken); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected invalid_grant on reuse, got %v", err)
	}

	if _, err := login.manager.ValidateAccessToken(first.AccessToken, credentialTestResource); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("first access token must be revoked after reuse, got %v", err)
	}
	if _, err := login.manager.ValidateAccessToken(second.AccessToken, credentialTestResource); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("access token of the rotated set must be revoked after reuse, got %v", err)
	}
	if _, err := login.refresh(second.RefreshToken); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("current refresh token must be revoked after reuse, got %v", err)
	}
}

func TestRefreshTokenReuseDoesNotTouchOtherLogins(t *testing.T) {
	login := newCredentialTestLogin(t)
	stolen := login.login(t)
	other := login.login(t)

	if _, err := login.refresh(stolen.RefreshToken); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, err := login.refresh(stolen.RefreshToken); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected invalid_grant on reuse, got %v", err)
	}
	if _, err := login.manager.ValidateAccessToken(other.AccessToken, credentialTestResource); err != nil {
		t.Fatalf("a separate login of the same client must survive: %v", err)
	}
}

func TestAuthorizationCodeReplayRevokesIssuedTokens(t *testing.T) {
	login := newCredentialTestLogin(t)
	code, err := login.manager.createAuthorizationCode(login.userID, login.params)
	if err != nil {
		t.Fatalf("create auth code: %v", err)
	}
	exchange := func() (*tokenResponse, error) {
		return login.manager.exchangeAuthorizationCode(login.client.ID, "", "none", code, login.params.RedirectURI, login.verifier, credentialTestResource)
	}
	tokens, err := exchange()
	if err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	if _, err := exchange(); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected invalid_grant on code replay, got %v", err)
	}
	if _, err := login.manager.ValidateAccessToken(tokens.AccessToken, credentialTestResource); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("tokens from the first exchange must be revoked after a replay, got %v", err)
	}
	if _, err := login.refresh(tokens.RefreshToken); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("refresh token from the first exchange must be revoked, got %v", err)
	}
}

func TestLazyClientRegistrationIsLimitedToListedRedirectOrigins(t *testing.T) {
	values := func(redirectURI string) url.Values {
		return url.Values{
			"client_id":             {"Hhds3gZ089JVr1z3tLlNJEmyCmf0rPTK"},
			"redirect_uri":          {redirectURI},
			"response_type":         {"code"},
			"resource":              {"https://mcp.example.com/legal/mcp"},
			"code_challenge":        {"abcdefghijklmnopqrstuvwxyz0123456789abcdef"},
			"code_challenge_method": {"S256"},
		}
	}

	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	if _, _, err := manager.parseAuthorizeRequest(true, true, values("https://attacker.example/cb")); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("unknown client with an unlisted redirect origin must be invalid_client, got %v", err)
	}
	if _, _, err := manager.parseAuthorizeRequest(true, true, values("https://chat.example.com/cb")); err != nil {
		t.Fatalf("listed redirect origin must be accepted lazily: %v", err)
	}

	manager = newTestManager(t, "admin@example.com", "super-secret-password")
	manager.cfg.LazyClientRegistration = "off"
	if _, _, err := manager.parseAuthorizeRequest(true, true, values("https://chat.example.com/cb")); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("lazy registration off must reject unknown clients, got %v", err)
	}

	manager = newTestManager(t, "admin@example.com", "super-secret-password")
	manager.cfg.LazyClientRegistration = "open"
	if _, _, err := manager.parseAuthorizeRequest(true, true, values("https://attacker.example/cb")); err != nil {
		t.Fatalf("open mode keeps the old behaviour: %v", err)
	}
}

func TestRedirectURIRules(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	for raw, wantOK := range map[string]bool{
		"https://claude.ai/api/mcp/auth_callback": true,
		"http://127.0.0.1:1234/cb":                true,
		"http://localhost/cb":                     true,
		"http://[::1]:1234/cb":                    true,
		"https://app.example/cb#frag":             false,
		"https://user@app.example/cb":             false,
		"http://app.example/cb":                   false,
		"javascript:alert(1)":                     false,
		"cursor://callback":                       false,
	} {
		if err := manager.validateRedirectURI(raw); (err == nil) != wantOK {
			t.Errorf("validateRedirectURI(%q) error = %v, want ok = %v", raw, err, wantOK)
		}
	}

	registered := []string{"http://127.0.0.1:1234/cb", "https://app.example/cb"}
	for requested, want := range map[string]bool{
		"http://127.0.0.1:1234/cb":     true,
		"http://127.0.0.1:50999/cb":    true, // loopback: any port
		"http://127.0.0.1/cb":          true,
		"http://127.0.0.1:50999/other": false,
		"http://localhost:50999/cb":    false, // another host name
		"https://app.example/cb":       true,
		"https://app.example:8443/cb":  false, // only loopback ports vary
		"https://app.example/cb/extra": false,
	} {
		if got := redirectURIRegistered(registered, requested); got != want {
			t.Errorf("redirectURIRegistered(%q) = %v, want %v", requested, got, want)
		}
	}
}

func TestAuthorizationResponseCarriesIssuer(t *testing.T) {
	target, err := buildOAuthCodeRedirectURL("https://app.example/cb?x=1", "https://mcp.example.com", "the-code", "the-state")
	if err != nil {
		t.Fatalf("build redirect: %v", err)
	}
	parsed, _ := url.Parse(target)
	if got := parsed.Query().Get("iss"); got != "https://mcp.example.com" {
		t.Fatalf("iss = %q", got)
	}
	target, err = buildOAuthErrorRedirectURL("https://app.example/cb", "https://mcp.example.com", "access_denied", "")
	if err != nil {
		t.Fatalf("build error redirect: %v", err)
	}
	parsed, _ = url.Parse(target)
	if got := parsed.Query().Get("iss"); got != "https://mcp.example.com" {
		t.Fatalf("iss on error = %q", got)
	}
}

// A client that names no resource does not get a token for every route: the
// user picks the one MCP server on the consent page.
func TestConsentBindsResourcelessClientsToOneServer(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	manager.SetResourceLister(func(*Identity) []ResourceOption {
		return []ResourceOption{{URL: "https://mcp.example.com/legal/mcp", Name: "Legal"}, {URL: "https://mcp.example.com/fax/mcp", Name: "Fax"}}
	})
	manager.SetResourceAccessChecker(func(_ *Identity, resource string) error {
		if !strings.HasPrefix(resource, "https://mcp.example.com/") || resource == "https://mcp.example.com/" {
			return errors.New("unknown MCP resource")
		}
		return nil
	})
	client, err := manager.registerClient("Codex CLI", []string{"http://127.0.0.1:51066/callback"}, nil, nil, "none")
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	session := sessionCookieFor(t, manager, "admin@example.com")
	base := url.Values{
		"client_id":             {client.ID},
		"redirect_uri":          {"http://127.0.0.1:51066/callback"},
		"response_type":         {"code"},
		"state":                 {"state-value"},
		"code_challenge":        {"abcdefghijklmnopqrstuvwxyz0123456789abcdef"},
		"code_challenge_method": {"S256"},
	}

	for name, resource := range map[string]string{"no resource": "", "gateway-wide resource": "https://mcp.example.com"} {
		query := url.Values{}
		for key, value := range base {
			query[key] = value
		}
		if resource != "" {
			query.Set("resource", resource)
		}
		req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/authorize?"+query.Encode(), nil)
		req.AddCookie(session)
		rec := httptest.NewRecorder()
		manager.HandleAuthorize(rec, req)
		body := rec.Body.String()
		if rec.Code != http.StatusOK || !strings.Contains(body, `<select name="resource" required>`) || !strings.Contains(body, "https://mcp.example.com/fax/mcp") {
			t.Fatalf("%s: expected a consent page with a server choice, got %d %q", name, rec.Code, body)
		}
		if strings.Contains(body, "gatewayweiter Zugriff") {
			t.Fatalf("%s: consent must not offer gateway-wide access", name)
		}
	}

	post := func(resource string) *httptest.ResponseRecorder {
		form := url.Values{"csrf_token": {"csrf"}, "action": {"approve"}, "scope": {"mcp"}, "resource": {resource}}
		for key, value := range base {
			form[key] = value
		}
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/authorize", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: manager.csrfCookieNameFor(req), Value: "csrf"})
		req.AddCookie(session)
		rec := httptest.NewRecorder()
		manager.HandleAuthorize(rec, req)
		return rec
	}

	for _, resource := range []string{"", "https://mcp.example.com"} {
		if rec := post(resource); rec.Code != http.StatusBadRequest {
			t.Fatalf("approval with resource %q must be refused, got %d %q", resource, rec.Code, rec.Body.String())
		}
	}
	manager.mu.Lock()
	issued := len(manager.data.AuthCodes)
	manager.mu.Unlock()
	if issued != 0 {
		t.Fatalf("no code may be issued without a bound resource, got %d", issued)
	}

	if rec := post("https://mcp.example.com/fax/mcp"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "code=") {
		t.Fatalf("approval with a chosen server must issue a code, got %d %q", rec.Code, rec.Body.String())
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for _, record := range manager.data.AuthCodes {
		if record.Resource != "https://mcp.example.com/fax/mcp" {
			t.Fatalf("code bound to %q, want the chosen server", record.Resource)
		}
	}
}

func TestCSRFCookieUsesHostPrefixOverHTTPS(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")

	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/account/login", nil)
	rec := httptest.NewRecorder()
	manager.ensureCSRFCookie(rec, req)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-"+csrfCookieName || !cookies[0].Secure || cookies[0].Path != "/" || cookies[0].Domain != "" {
		t.Fatalf("unexpected CSRF cookie over HTTPS: %#v", cookies)
	}

	// A token planted under the plain name (as a sibling subdomain could do)
	// is not accepted on the HTTPS origin.
	form := url.Values{"csrf_token": {"planted"}}
	post := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/account/logout", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "planted"})
	if manager.validateCSRFCookie(post) {
		t.Fatalf("a CSRF cookie without the __Host- prefix must not be accepted over HTTPS")
	}
}

// A burst of parallel guesses must not slip past the throttle before the
// first failure is counted.
func TestParallelLoginGuessesAreCountedOneByOne(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")

	const attempts = 20
	codes := make([]int, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			manager.HandleAccountLogin(rec, loginRequest("admin@example.com", "wrong-password", "203.0.113.7:1234"))
			codes[i] = rec.Code
		}(i)
	}
	wg.Wait()

	checked := 0
	for _, code := range codes {
		switch code {
		case http.StatusOK:
			checked++
		case http.StatusTooManyRequests:
		default:
			t.Fatalf("unexpected status %d", code)
		}
	}
	if checked != loginPairLimit {
		t.Fatalf("%d of %d parallel guesses reached the password check, want exactly %d", checked, attempts, loginPairLimit)
	}
}

func TestFullClientRegistryAnswersWithRetryLater(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	manager.mu.Lock()
	for i := 0; i < maxRegisteredClients; i++ {
		id := randomToken(8)
		manager.data.Clients[id] = &clientRecord{ID: id, UpdatedAt: time.Now().Unix()}
	}
	manager.mu.Unlock()

	body := `{"client_name":"x","redirect_uris":["https://app.example/cb"]}`
	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/register", strings.NewReader(body))
	req.RemoteAddr = "203.0.113.9:1"
	rec := httptest.NewRecorder()
	manager.HandleClientRegistration(rec, req)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" || !strings.Contains(rec.Body.String(), "temporarily_unavailable") {
		t.Fatalf("expected 429 temporarily_unavailable with Retry-After, got %d %q", rec.Code, rec.Body.String())
	}
}

// Holding a used code is not enough to end the login it produced: the request
// must also come from the code's client with the right verifier.
func TestUsedCodeAloneCannotRevokeTheLogin(t *testing.T) {
	login := newCredentialTestLogin(t)
	code, err := login.manager.createAuthorizationCode(login.userID, login.params)
	if err != nil {
		t.Fatalf("create auth code: %v", err)
	}
	tokens, err := login.manager.exchangeAuthorizationCode(login.client.ID, "", "none", code, login.params.RedirectURI, login.verifier, credentialTestResource)
	if err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	other, err := login.manager.registerClient("Other", []string{login.params.RedirectURI}, nil, nil, "none")
	if err != nil {
		t.Fatalf("register other client: %v", err)
	}

	if _, err := login.manager.exchangeAuthorizationCode(other.ID, "", "none", code, login.params.RedirectURI, login.verifier, credentialTestResource); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("used code from another client: expected invalid_grant, got %v", err)
	}
	if _, err := login.manager.exchangeAuthorizationCode(login.client.ID, "", "none", code, login.params.RedirectURI, "wrong-verifier-wrong-verifier-wrong-verifier", credentialTestResource); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("used code with a wrong verifier: expected invalid_grant, got %v", err)
	}
	if _, err := login.manager.ValidateAccessToken(tokens.AccessToken, credentialTestResource); err != nil {
		t.Fatalf("the login must survive replays that fail the code's own checks: %v", err)
	}
}

func TestConsentCanBeDeclinedWithoutChoosingAServer(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	client, err := manager.registerClient("Codex CLI", []string{"http://127.0.0.1:51066/callback"}, nil, nil, "none")
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	form := url.Values{
		"csrf_token": {"csrf"}, "action": {"deny"}, "client_id": {client.ID}, "redirect_uri": {"http://127.0.0.1:51066/callback"},
		"response_type": {"code"}, "state": {"state-value"}, "resource": {""},
		"code_challenge": {"abcdefghijklmnopqrstuvwxyz0123456789abcdef"}, "code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: manager.csrfCookieNameFor(req), Value: "csrf"})
	req.AddCookie(sessionCookieFor(t, manager, "admin@example.com"))
	rec := httptest.NewRecorder()
	manager.HandleAuthorize(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "error=access_denied") {
		t.Fatalf("declining without a server must answer access_denied, got %d %q", rec.Code, rec.Body.String())
	}

	// The consent page must let the browser submit the decline button without
	// the required server choice.
	if !strings.Contains(authorizeTemplate, `value="deny" class="btn btn-ghost" formnovalidate`) {
		t.Fatalf("decline button must skip form validation")
	}
}

// Refresh tokens and codes from before the binding must end the login
// instead of yielding access tokens that every route refuses.
func TestUnboundRefreshTokensAndCodesAreRefused(t *testing.T) {
	for name, resource := range map[string]string{"no resource": "", "gateway-wide resource": "https://mcp.example.com"} {
		login := newCredentialTestLogin(t)
		manager := login.manager

		manager.mu.Lock()
		tokens := manager.issueTokenSetLocked(time.Now(), login.userID, login.client.ID, "old-grant", "mcp", resource)
		manager.mu.Unlock()

		if _, err := manager.refreshToken(login.client.ID, "", "none", tokens.RefreshToken, ""); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("%s: unbound refresh token must be refused with invalid_grant, got %v", name, err)
		}
		manager.mu.Lock()
		_, refreshLeft := manager.data.RefreshTokens[tokens.RefreshToken]
		_, accessLeft := manager.data.AccessTokens[tokens.AccessToken]
		manager.mu.Unlock()
		if refreshLeft || accessLeft {
			t.Fatalf("%s: the unbound login must be removed (refresh left %v, access left %v)", name, refreshLeft, accessLeft)
		}

		params := *login.params
		params.Resource = resource
		code, err := manager.createAuthorizationCode(login.userID, &params)
		if err != nil {
			t.Fatalf("create auth code: %v", err)
		}
		if _, err := manager.exchangeAuthorizationCode(login.client.ID, "", "none", code, params.RedirectURI, login.verifier, ""); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("%s: unbound code must be refused with invalid_grant, got %v", name, err)
		}

		// With unbound tokens allowed the old behaviour stays.
		manager.cfg.AllowUnboundTokens = true
		manager.mu.Lock()
		tokens = manager.issueTokenSetLocked(time.Now(), login.userID, login.client.ID, "old-grant-2", "mcp", resource)
		manager.mu.Unlock()
		if _, err := manager.refreshToken(login.client.ID, "", "none", tokens.RefreshToken, ""); err != nil {
			t.Fatalf("%s: with unbound tokens allowed the refresh must work: %v", name, err)
		}
	}
}

// A client that sends the gateway's base URL as resource gets the server
// choice at /authorize; the same value at /token must then not fail against
// the chosen server, on the code exchange or on refresh.
func TestGatewayWideResourceParameterWorksAcrossAuthorizeAndToken(t *testing.T) {
	login := newCredentialTestLogin(t)
	manager := login.manager
	const base = "https://mcp.example.com"

	code, err := manager.createAuthorizationCode(login.userID, login.params) // bound to the chosen server
	if err != nil {
		t.Fatalf("create auth code: %v", err)
	}
	tokens, err := manager.exchangeAuthorizationCode(login.client.ID, "", "none", code, login.params.RedirectURI, login.verifier, base)
	if err != nil {
		t.Fatalf("code exchange with the base URL as resource: %v", err)
	}
	if _, err := manager.ValidateAccessToken(tokens.AccessToken, credentialTestResource); err != nil {
		t.Fatalf("token must be valid on the chosen server: %v", err)
	}
	if _, err := manager.ValidateAccessToken(tokens.AccessToken, "https://mcp.example.com/other/mcp"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("token must stay bound to the chosen server, got %v", err)
	}
	refreshed, err := manager.refreshToken(login.client.ID, "", "none", tokens.RefreshToken, base)
	if err != nil {
		t.Fatalf("refresh with the base URL as resource: %v", err)
	}
	if _, err := manager.ValidateAccessToken(refreshed.AccessToken, credentialTestResource); err != nil {
		t.Fatalf("refreshed token must be valid on the chosen server: %v", err)
	}

	// A different, specific resource is still a mismatch.
	if _, err := manager.refreshToken(login.client.ID, "", "none", refreshed.RefreshToken, "https://mcp.example.com/other/mcp"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("another server as resource must be refused, got %v", err)
	}
}
