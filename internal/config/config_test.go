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
