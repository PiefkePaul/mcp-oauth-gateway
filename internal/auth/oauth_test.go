package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthorizeApprovalRedirectsWithSeeOther(t *testing.T) {
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

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d with body %q", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, "https://claude.ai/api/mcp/auth_callback?") {
		t.Fatalf("unexpected redirect location %q", location)
	}
	if !strings.Contains(location, "code=") {
		t.Fatalf("expected code in redirect location %q", location)
	}
	if !strings.Contains(location, "state=state-value") {
		t.Fatalf("expected state in redirect location %q", location)
	}
}

func TestAuthorizeDenyRedirectsWithSeeOther(t *testing.T) {
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

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d with body %q", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, "https://claude.ai/api/mcp/auth_callback?") {
		t.Fatalf("unexpected redirect location %q", location)
	}
	if !strings.Contains(location, "error=access_denied") {
		t.Fatalf("expected access_denied in redirect location %q", location)
	}
}
