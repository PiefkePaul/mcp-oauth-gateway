package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

const (
	brokerClientToken = "broker-client-token-for-tests"
	brokerBearer      = "bearer-typed-into-the-admin-form"
)

type fakeBroker struct {
	mu       sync.Mutex
	requests []secretBrokerRequest
	auth     []string
	status   int
	answer   string
}

func newFakeBroker(t *testing.T, status int, answer string) (*fakeBroker, *httptest.Server) {
	t.Helper()
	fb := &fakeBroker{status: status, answer: answer}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req secretBrokerRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		fb.mu.Lock()
		fb.requests = append(fb.requests, req)
		fb.auth = append(fb.auth, r.Header.Get("Authorization"))
		fb.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(fb.status)
		_, _ = w.Write([]byte(fb.answer))
	}))
	t.Cleanup(srv.Close)
	return fb, srv
}

func withBroker(f routeSecretsFixture, url string) {
	f.server.cfg.SecretBroker = config.SecretBrokerConfig{URL: url, Token: brokerClientToken, Timeout: 5 * time.Second, Delay: 5 * time.Minute}
	f.server.secretBroker = newSecretBroker(f.server.cfg.SecretBroker)
}

func saveGermanLegal(t *testing.T, f routeSecretsFixture, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	f.server.cfg.RoutesPath = t.TempDir() + "/routes.yaml"
	cookies := adminTestSession(t, f.server)
	route, _ := f.server.routeByID("german-legal-mcp")
	return postAdminRouteSave(t, f.server, cookies, url.Values{
		"original_id":           {"german-legal-mcp"},
		"id":                    {"german-legal-mcp"},
		"display_name":          {"German Legal"},
		"transport":             {"http"},
		"path_prefix":           {"/legal"},
		"upstream":              {route.Upstream},
		"upstream_mcp_path":     {"/mcp"},
		"upstream_bearer_token": {bearer},
	})
}

func TestBrokerGetsTheBearerAndTheGatewayStoresNone(t *testing.T) {
	f := newRouteSecretsFixture(t, "", false)
	fb, srv := newFakeBroker(t, http.StatusOK, `{"ok":true,"folder":"/mcp-routen/german-legal-mcp","key":"GERMAN_LEGAL_MCP"}`)
	withBroker(f, srv.URL+"/api/route-secret")
	logs := captureGatewayLog(t)

	rec := saveGermanLegal(t, f, "Bearer "+brokerBearer)
	if rec.Code != http.StatusFound {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	if len(fb.requests) != 1 {
		t.Fatalf("broker got %d requests, want 1", len(fb.requests))
	}
	got := fb.requests[0]
	if got.RouteID != "german-legal-mcp" || got.Key != "GERMAN_LEGAL_MCP" || got.Value != brokerBearer {
		t.Fatalf("broker request = %+v", got)
	}
	if fb.auth[0] != "Bearer "+brokerClientToken {
		t.Fatalf("broker auth header = %q", fb.auth[0])
	}
	if _, ok := f.server.authManager.RouteGlobalUpstreamBearer("german-legal-mcp"); ok {
		t.Fatalf("the gateway stored the bearer although the broker took it")
	}
	location := rec.Header().Get("Location")
	if !strings.Contains(location, "token+broker") && !strings.Contains(location, "token%20broker") {
		t.Errorf("notice does not mention the broker: %s", location)
	}
	if strings.Contains(location, brokerBearer) || strings.Contains(logs.String(), brokerBearer) {
		t.Fatalf("bearer value leaked into the redirect or the log")
	}
}

func TestBrokerRefusalStoresNothingAndSaysSo(t *testing.T) {
	f := newRouteSecretsFixture(t, "", false)
	fb, srv := newFakeBroker(t, http.StatusConflict, `{"ok":false,"error":"GERMAN_LEGAL_MCP verweist auf einen anderen Ordner"}`)
	withBroker(f, srv.URL)

	rec := saveGermanLegal(t, f, brokerBearer)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("save: %d, want 502", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "not saved anywhere") || !strings.Contains(body, "verweist auf einen anderen Ordner") {
		t.Errorf("error page does not explain the refusal")
	}
	if strings.Contains(body, brokerBearer) {
		t.Fatalf("bearer value echoed in the error page")
	}
	if _, ok := f.server.authManager.RouteGlobalUpstreamBearer("german-legal-mcp"); ok {
		t.Fatalf("the gateway fell back to storing the bearer")
	}
	if len(fb.requests) != 1 {
		t.Fatalf("broker got %d requests", len(fb.requests))
	}
}

func TestBrokerUnreachableStoresNothing(t *testing.T) {
	f := newRouteSecretsFixture(t, "", false)
	withBroker(f, "http://127.0.0.1:1/api/route-secret")
	rec := saveGermanLegal(t, f, brokerBearer)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("save: %d, want 502", rec.Code)
	}
	if _, ok := f.server.authManager.RouteGlobalUpstreamBearer("german-legal-mcp"); ok {
		t.Fatalf("the gateway stored the bearer")
	}
}

func TestBrokerNotCalledWithoutANewBearer(t *testing.T) {
	f := newRouteSecretsFixture(t, "", false)
	fb, srv := newFakeBroker(t, http.StatusOK, `{"ok":true}`)
	withBroker(f, srv.URL)
	if rec := saveGermanLegal(t, f, ""); rec.Code != http.StatusFound {
		t.Fatalf("save: %d", rec.Code)
	}
	if len(fb.requests) != 0 {
		t.Fatalf("broker was called without a value")
	}
}

func TestBrokerUnlocksTheBearerFieldAndExplains(t *testing.T) {
	f := newRouteSecretsFixture(t, "GERMAN_LEGAL_MCP='"+fileBearer+"'\n", false)
	_, srv := newFakeBroker(t, http.StatusOK, `{"ok":true}`)
	withBroker(f, srv.URL)
	cookies := adminTestSession(t, f.server)
	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/admin?route=german-legal-mcp", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	f.server.ServeHTTP(rec, req)
	body := rec.Body.String()
	if strings.Contains(body, `type="password" autocomplete="off" disabled`) {
		t.Errorf("bearer field is still locked although a broker is configured")
	}
	if !strings.Contains(body, "Token-Broker aktiv") {
		t.Errorf("admin page does not explain the broker")
	}
}

func TestBrokerDoesNotFollowRedirects(t *testing.T) {
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	t.Cleanup(target.Close)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirect.Close)
	b := newSecretBroker(config.SecretBrokerConfig{URL: redirect.URL, Token: "x", Timeout: 5 * time.Second})
	if _, err := b.SetRouteSecret(t.Context(), "r", "R", "v"); err == nil {
		t.Fatalf("redirect was accepted")
	}
	if hits != 0 {
		t.Fatalf("the value followed the redirect")
	}
}
