package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuthorizeApprovalReturnsBrowserRedirectPage(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")

	client, err := manager.registerClient(
		"Claude",
		[]string{"https://claude.ai/api/mcp/auth_callback"},
		nil,
		nil,
		"none",
	)
	if err != nil {
		t.Fatalf("register client: %v", err)
	}

	userID := manager.ListUsers()[0].ID
	sessionRec := httptest.NewRecorder()
	sessionReq := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/account", nil)
	if err := manager.startSession(sessionRec, sessionReq, userID); err != nil {
		t.Fatalf("start session: %v", err)
	}

	csrfToken := "csrf-token"
	form := url.Values{
		"csrf_token":            {csrfToken},
		"client_id":             {client.ID},
		"redirect_uri":          {"https://claude.ai/api/mcp/auth_callback"},
		"response_type":         {"code"},
		"state":                 {"state-value"},
		"scope":                 {"mcp"},
		"resource":              {"https://mcp.example.com/legal/mcp"},
		"code_challenge":        {"abcdefghijklmnopqrstuvwxyz0123456789abcdef"},
		"code_challenge_method": {"S256"},
		"action":                {"approve"},
	}

	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrfToken})
	for _, cookie := range sessionRec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()

	manager.HandleAuthorize(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d with body %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "" {
		t.Fatalf("expected no Location header, got %q", rec.Header().Get("Location"))
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'unsafe-inline'") {
		t.Fatalf("expected redirect page CSP to allow inline redirect script, got %q", rec.Header().Get("Content-Security-Policy"))
	}
	body := rec.Body.String()
	if !strings.Contains(body, "https://claude.ai/api/mcp/auth_callback?") {
		t.Fatalf("expected callback URL in redirect page, got %q", body)
	}
	if !strings.Contains(body, "code=") {
		t.Fatalf("expected code in redirect page, got %q", body)
	}
	if !strings.Contains(body, "state=state-value") {
		t.Fatalf("expected state in redirect page, got %q", body)
	}
}

func TestAuthorizeDenyReturnsBrowserRedirectPage(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")

	client, err := manager.registerClient(
		"Claude",
		[]string{"https://claude.ai/api/mcp/auth_callback"},
		nil,
		nil,
		"none",
	)
	if err != nil {
		t.Fatalf("register client: %v", err)
	}

	userID := manager.ListUsers()[0].ID
	sessionRec := httptest.NewRecorder()
	sessionReq := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/account", nil)
	if err := manager.startSession(sessionRec, sessionReq, userID); err != nil {
		t.Fatalf("start session: %v", err)
	}

	csrfToken := "csrf-token"
	form := url.Values{
		"csrf_token":            {csrfToken},
		"client_id":             {client.ID},
		"redirect_uri":          {"https://claude.ai/api/mcp/auth_callback"},
		"response_type":         {"code"},
		"state":                 {"state-value"},
		"scope":                 {"mcp"},
		"resource":              {"https://mcp.example.com/legal/mcp"},
		"code_challenge":        {"abcdefghijklmnopqrstuvwxyz0123456789abcdef"},
		"code_challenge_method": {"S256"},
		"action":                {"deny"},
	}

	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrfToken})
	for _, cookie := range sessionRec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()

	manager.HandleAuthorize(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d with body %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "" {
		t.Fatalf("expected no Location header, got %q", rec.Header().Get("Location"))
	}
	body := rec.Body.String()
	if !strings.Contains(body, "https://claude.ai/api/mcp/auth_callback?") {
		t.Fatalf("expected callback URL in redirect page, got %q", body)
	}
	if !strings.Contains(body, "error=access_denied") {
		t.Fatalf("expected access_denied in redirect page, got %q", body)
	}
}

func TestAuthorizeAllowsClientsWithoutResourceParameter(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")

	client, err := manager.registerClient(
		"Codex CLI",
		[]string{"http://127.0.0.1:51066/callback"},
		nil,
		nil,
		"none",
	)
	if err != nil {
		t.Fatalf("register client: %v", err)
	}

	params, _, err := manager.parseAuthorizeRequest(url.Values{
		"client_id":             {client.ID},
		"redirect_uri":          {"http://127.0.0.1:51066/callback"},
		"response_type":         {"code"},
		"state":                 {"state-value"},
		"scope":                 {"mcp"},
		"code_challenge":        {"abcdefghijklmnopqrstuvwxyz0123456789abcdef"},
		"code_challenge_method": {"S256"},
	})
	if err != nil {
		t.Fatalf("parse authorize request without resource: %v", err)
	}
	if params.Resource != "" {
		t.Fatalf("expected empty resource, got %q", params.Resource)
	}
}

func TestGatewayWideAccessTokenCanBeValidatedForSpecificResource(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	userID := manager.ListUsers()[0].ID

	manager.mu.Lock()
	tokenSet := manager.issueTokenSetLocked(time.Now(), userID, "client-id", "mcp", "")
	manager.mu.Unlock()

	identity, err := manager.ValidateAccessToken(tokenSet.AccessToken, "https://mcp.example.com/legal/mcp")
	if err != nil {
		t.Fatalf("validate gateway-wide token for resource: %v", err)
	}
	if identity.Email != "admin@example.com" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
}

func TestRootResourceAccessTokenCanBeValidatedForSpecificResource(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	userID := manager.ListUsers()[0].ID

	manager.mu.Lock()
	tokenSet := manager.issueTokenSetLocked(time.Now(), userID, "client-id", "mcp", "https://mcp.example.com")
	manager.mu.Unlock()

	identity, err := manager.ValidateAccessToken(tokenSet.AccessToken, "https://mcp.example.com/camoufox/mcp")
	if err != nil {
		t.Fatalf("validate root-resource token for route resource: %v", err)
	}
	if identity.Email != "admin@example.com" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
}

func TestDynamicClientRegistrationSupportsClientSecretPost(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")

	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/register", strings.NewReader(`{
		"client_name": "Open WebUI",
		"redirect_uris": ["https://openwebui.example.com/oauth/mcp/callback"],
		"grant_types": ["authorization_code", "refresh_token"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "client_secret_post"
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	manager.HandleClientRegistration(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d with body %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"token_endpoint_auth_method":"client_secret_post"`) {
		t.Fatalf("expected client_secret_post response, got %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"client_secret"`) {
		t.Fatalf("expected client_secret in response, got %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"registration_access_token"`) {
		t.Fatalf("expected registration_access_token in response, got %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"registration_client_uri":"https://mcp.example.com/register/`) {
		t.Fatalf("expected registration_client_uri in response, got %q", rec.Body.String())
	}
}

func TestClientRegistrationManagementLifecycle(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")

	registerReq := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/register", strings.NewReader(`{
		"client_name": "Open WebUI",
		"redirect_uris": ["https://openwebui.example.com/oauth/mcp/callback"],
		"grant_types": ["authorization_code", "refresh_token"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "client_secret_post",
		"client_uri": "https://openwebui.example.com"
	}`))
	registerReq.Header.Set("Content-Type", "application/json")
	registerRec := httptest.NewRecorder()

	manager.HandleClientRegistration(registerRec, registerReq)

	if registerRec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d with body %q", registerRec.Code, registerRec.Body.String())
	}

	var registration map[string]any
	if err := json.Unmarshal(registerRec.Body.Bytes(), &registration); err != nil {
		t.Fatalf("decode registration response: %v", err)
	}
	clientID, _ := registration["client_id"].(string)
	clientSecret, _ := registration["client_secret"].(string)
	registrationAccessToken, _ := registration["registration_access_token"].(string)
	registrationClientURI, _ := registration["registration_client_uri"].(string)
	if clientID == "" || clientSecret == "" || registrationAccessToken == "" || registrationClientURI == "" {
		t.Fatalf("registration response missing RFC 7592 fields: %#v", registration)
	}

	readReq := httptest.NewRequest(http.MethodGet, registrationClientURI, nil)
	readReq.Header.Set("Authorization", "Bearer "+registrationAccessToken)
	readRec := httptest.NewRecorder()

	manager.HandleClientConfiguration(readRec, readReq)

	if readRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d with body %q", readRec.Code, readRec.Body.String())
	}
	if !strings.Contains(readRec.Body.String(), `"client_uri":"https://openwebui.example.com"`) {
		t.Fatalf("expected persisted metadata, got %q", readRec.Body.String())
	}

	updateReq := httptest.NewRequest(http.MethodPut, registrationClientURI, strings.NewReader(`{
		"client_id": "`+clientID+`",
		"client_secret": "`+clientSecret+`",
		"client_name": "Updated Open WebUI",
		"redirect_uris": ["https://openwebui.example.com/oauth/mcp/callback"],
		"grant_types": ["authorization_code", "refresh_token"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "client_secret_post",
		"policy_uri": "https://openwebui.example.com/policy"
	}`))
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.Header.Set("Authorization", "Bearer "+registrationAccessToken)
	updateRec := httptest.NewRecorder()

	manager.HandleClientConfiguration(updateRec, updateReq)

	if updateRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d with body %q", updateRec.Code, updateRec.Body.String())
	}
	if !strings.Contains(updateRec.Body.String(), `"client_name":"Updated Open WebUI"`) {
		t.Fatalf("expected updated metadata, got %q", updateRec.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, registrationClientURI, nil)
	deleteReq.Header.Set("Authorization", "Bearer "+registrationAccessToken)
	deleteRec := httptest.NewRecorder()

	manager.HandleClientConfiguration(deleteRec, deleteReq)

	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d with body %q", deleteRec.Code, deleteRec.Body.String())
	}
	if _, err := manager.lookupClient(clientID); err == nil {
		t.Fatalf("expected client to be deleted")
	}
}

func TestClientRegistrationManagementRejectsOAuthAccessToken(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	client, err := manager.registerClient(
		"Open WebUI",
		[]string{"https://openwebui.example.com/oauth/mcp/callback"},
		nil,
		nil,
		"none",
	)
	if err != nil {
		t.Fatalf("register client: %v", err)
	}

	userID := manager.ListUsers()[0].ID
	manager.mu.Lock()
	tokenSet := manager.issueTokenSetLocked(time.Now(), userID, client.ID, "mcp", "https://mcp.example.com/camoufox/mcp")
	manager.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/register/"+client.ID, nil)
	req.Header.Set("Authorization", "Bearer "+tokenSet.AccessToken)
	rec := httptest.NewRecorder()

	manager.HandleClientConfiguration(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d with body %q", rec.Code, rec.Body.String())
	}
}

func TestDynamicClientRegistrationAllowsTrustedHTTPRedirectOrigin(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	manager.cfg.AllowedRedirectOrigins = []string{"http://192.168.178.254:8080"}

	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/register", strings.NewReader(`{
		"client_name": "Open WebUI",
		"redirect_uris": ["http://192.168.178.254:8080/oauth/clients/mcp:camoufox/callback"],
		"grant_types": ["authorization_code", "refresh_token"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "client_secret_post"
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	manager.HandleClientRegistration(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d with body %q", rec.Code, rec.Body.String())
	}
}

func TestDynamicClientRegistrationRejectsUntrustedHTTPRedirectOrigin(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")

	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/register", strings.NewReader(`{
		"client_name": "Open WebUI",
		"redirect_uris": ["http://192.168.178.254:8080/oauth/clients/mcp:camoufox/callback"],
		"grant_types": ["authorization_code", "refresh_token"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "client_secret_post"
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	manager.HandleClientRegistration(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d with body %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "redirect_uri must use https or localhost http") {
		t.Fatalf("expected redirect_uri validation error, got %q", rec.Body.String())
	}
}

func TestAuthorizationCodeExchangeRequiresConfidentialClientSecret(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	client, err := manager.registerClient(
		"Open WebUI",
		[]string{"https://openwebui.example.com/oauth/mcp/callback"},
		nil,
		nil,
		"client_secret_post",
	)
	if err != nil {
		t.Fatalf("register client: %v", err)
	}

	userID := manager.ListUsers()[0].ID
	codeVerifier := "abcdefghijklmnopqrstuvwxyz0123456789abcdef"
	challengeSum := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	params := &authorizeParams{
		ClientID:            client.ID,
		RedirectURI:         "https://openwebui.example.com/oauth/mcp/callback",
		Scope:               "mcp",
		Resource:            "https://mcp.example.com/camoufox/mcp",
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
	}
	code, err := manager.createAuthorizationCode(userID, params)
	if err != nil {
		t.Fatalf("create auth code: %v", err)
	}

	if _, err := manager.exchangeAuthorizationCode(client.ID, "wrong-secret", "client_secret_post", code, params.RedirectURI, codeVerifier, params.Resource); err == nil {
		t.Fatalf("expected invalid client for wrong secret")
	}
	if _, err := manager.exchangeAuthorizationCode(client.ID, client.Secret, "client_secret_basic", code, params.RedirectURI, codeVerifier, params.Resource); err == nil {
		t.Fatalf("expected invalid client for wrong token endpoint auth method")
	}

	code, err = manager.createAuthorizationCode(userID, params)
	if err != nil {
		t.Fatalf("create second auth code: %v", err)
	}
	if _, err := manager.exchangeAuthorizationCode(client.ID, client.Secret, "client_secret_post", code, params.RedirectURI, codeVerifier, params.Resource); err != nil {
		t.Fatalf("exchange with client secret: %v", err)
	}
}

func TestTokenEndpointInvalidBasicClientIncludesAuthenticateHeader(t *testing.T) {
	manager := newTestManager(t, "admin@example.com", "super-secret-password")
	client, err := manager.registerClient(
		"Open WebUI",
		[]string{"https://openwebui.example.com/oauth/mcp/callback"},
		nil,
		nil,
		"client_secret_post",
	)
	if err != nil {
		t.Fatalf("register client: %v", err)
	}

	userID := manager.ListUsers()[0].ID
	codeVerifier := "abcdefghijklmnopqrstuvwxyz0123456789abcdef"
	challengeSum := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	code, err := manager.createAuthorizationCode(userID, &authorizeParams{
		ClientID:            client.ID,
		RedirectURI:         "https://openwebui.example.com/oauth/mcp/callback",
		Scope:               "mcp",
		Resource:            "https://mcp.example.com/camoufox/mcp",
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("create auth code: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://openwebui.example.com/oauth/mcp/callback"},
		"code_verifier": {codeVerifier},
	}
	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ID, client.Secret)
	rec := httptest.NewRecorder()

	manager.HandleToken(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d with body %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("WWW-Authenticate") != `Basic realm="mcp-oauth-gateway"` {
		t.Fatalf("expected Basic challenge, got %q", rec.Header().Get("WWW-Authenticate"))
	}
}
