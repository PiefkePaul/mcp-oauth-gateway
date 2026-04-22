package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRoutesFileInitializesMissingFile(t *testing.T) {
	routesPath := filepath.Join(t.TempDir(), "nested", "routes.yaml")

	routes, err := LoadRoutesFile(routesPath)
	if err != nil {
		t.Fatalf("load missing routes file: %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("expected no routes, got %#v", routes)
	}

	payload, err := os.ReadFile(routesPath)
	if err != nil {
		t.Fatalf("read initialized routes file: %v", err)
	}
	if string(payload) != "routes: []\n" {
		t.Fatalf("unexpected initialized routes file: %q", payload)
	}
}

func TestRouteAccessDefaultsToPublic(t *testing.T) {
	routes, err := ParseRoutesPayload([]byte(`
routes:
  - id: legal
    display_name: Legal
    path_prefix: /legal
    upstream: http://legal:8000
    upstream_mcp_path: /mcp
`))
	if err != nil {
		t.Fatalf("parse routes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].Access.Visibility != "public" || routes[0].Access.Mode != "public" {
		t.Fatalf("expected public access defaults, got %#v", routes[0].Access)
	}
}

func TestRouteAccessRejectsInvalidMode(t *testing.T) {
	_, err := ParseRoutesPayload([]byte(`
routes:
  - id: legal
    display_name: Legal
    path_prefix: /legal
    upstream: http://legal:8000
    upstream_mcp_path: /mcp
    access:
      mode: maybe
`))
	if err == nil {
		t.Fatalf("expected invalid access mode error")
	}
}

func TestRouteDeploymentParsesManagedDocker(t *testing.T) {
	routes, err := ParseRoutesPayload([]byte(`
routes:
  - id: n8n
    display_name: n8n
    path_prefix: /n8n
    upstream: http://n8n-mcp:3000
    upstream_mcp_path: /mcp
    deployment:
      type: docker
      managed: true
      image: ghcr.io/czlonkowski/n8n-mcp:latest
      container_name: n8n-mcp
      internal_port: 3000
      networks:
        - mcp-internal
`))
	if err != nil {
		t.Fatalf("parse routes: %v", err)
	}
	if routes[0].Deployment == nil || !routes[0].Deployment.Managed {
		t.Fatalf("expected managed deployment, got %#v", routes[0].Deployment)
	}
}

func TestRouteParsesNativeStdioTransport(t *testing.T) {
	routes, err := ParseRoutesPayload([]byte(`
routes:
  - id: portainer
    display_name: Portainer
    transport: stdio
    path_prefix: /portainer
    upstream_mcp_path: /mcp
    stdio:
      command: /tools/portainer-mcp
      args:
        - -server
        - https://portainer:9443
      env:
        PORTAINER_TOKEN: secret
`))
	if err != nil {
		t.Fatalf("parse routes: %v", err)
	}
	if routes[0].Transport != "stdio" {
		t.Fatalf("expected stdio transport, got %q", routes[0].Transport)
	}
	if routes[0].Stdio == nil || routes[0].Stdio.Command != "/tools/portainer-mcp" {
		t.Fatalf("expected stdio config, got %#v", routes[0].Stdio)
	}
	if routes[0].Upstream != "" {
		t.Fatalf("stdio route should not require upstream, got %q", routes[0].Upstream)
	}
}

func TestNormalizeURLOrigins(t *testing.T) {
	origins, err := normalizeURLOrigins([]string{
		"http://192.168.178.254:8080/oauth/clients/callback",
		"https://openwebui.example.com/",
		"http://192.168.178.254:8080",
	})
	if err != nil {
		t.Fatalf("normalize origins: %v", err)
	}
	want := []string{"http://192.168.178.254:8080", "https://openwebui.example.com"}
	if len(origins) != len(want) {
		t.Fatalf("expected %d origins, got %#v", len(want), origins)
	}
	for i := range want {
		if origins[i] != want[i] {
			t.Fatalf("expected origin %q at index %d, got %q", want[i], i, origins[i])
		}
	}
}
