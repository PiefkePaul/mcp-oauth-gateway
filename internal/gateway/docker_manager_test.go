package gateway

import "testing"

func TestSplitDockerImageTag(t *testing.T) {
	tests := []struct {
		image string
		name  string
		tag   string
	}{
		{image: "nginx", name: "nginx", tag: "latest"},
		{image: "nginx:alpine", name: "nginx", tag: "alpine"},
		{image: "ghcr.io/example/mcp:1.2.3", name: "ghcr.io/example/mcp", tag: "1.2.3"},
		{image: "localhost:5000/example/mcp:dev", name: "localhost:5000/example/mcp", tag: "dev"},
		{image: "busybox@sha256:abc", name: "busybox@sha256:abc", tag: ""},
	}
	for _, tt := range tests {
		name, tag := splitDockerImageTag(tt.image)
		if name != tt.name || tag != tt.tag {
			t.Fatalf("splitDockerImageTag(%q) = %q/%q, want %q/%q", tt.image, name, tag, tt.name, tt.tag)
		}
	}
}
