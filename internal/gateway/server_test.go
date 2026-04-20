package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

func TestProtectedResourceMetadata(t *testing.T) {
	handler := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/.well-known/oauth-protected-resource/n8n/mcp", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	if got, want := payload["resource"], "https://mcp.example.com/n8n/mcp"; got != want {
		t.Fatalf("expected resource %q, got %#v", want, got)
	}
}

func TestProxyChallengesWithoutBearerToken(t *testing.T) {
	handler := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/n8n/mcp", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	challenge := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/n8n/mcp"`) {
		t.Fatalf("expected metadata challenge, got %q", challenge)
	}
}

func TestRouteInfo(t *testing.T) {
	handler := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/n8n", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if got, want := payload["mcp_url"], "https://mcp.example.com/n8n/mcp"; got != want {
		t.Fatalf("expected mcp_url %q, got %#v", want, got)
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()

	cfg := &config.Config{
		PublicBaseURL: "https://mcp.example.com",
		Routes: []config.Route{
			{
				ID:                     "n8n",
				DisplayName:            "n8n MCP",
				PathPrefix:             "/n8n",
				Upstream:               "http://n8n-mcp:8080",
				UpstreamMCPPath:        "/mcp",
				NormalizedPathPrefix:   "/n8n",
				NormalizedUpstreamPath: "/mcp",
			},
		},
	}

	manager, err := auth.NewManager(auth.Config{
		StorePath:            filepath.Join(t.TempDir(), "auth-store.enc"),
		MasterKey:            []byte("0123456789abcdef0123456789abcdef"),
		AccessTokenTTL:       time.Hour,
		RefreshTokenTTL:      24 * time.Hour,
		AuthorizationCodeTTL: 10 * time.Minute,
		SessionTTL:           24 * time.Hour,
		PublicBaseURL:        cfg.PublicBaseURL,
		PortalTitle:          "MCP Gateway",
	})
	if err != nil {
		t.Fatalf("create auth manager: %v", err)
	}

	handler, err := New(cfg, manager)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	return handler
}
