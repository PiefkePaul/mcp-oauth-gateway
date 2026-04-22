package gateway

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

func TestArtifactBuilderValidatesChecksumAndBaseImage(t *testing.T) {
	sum := sha256.Sum256([]byte("binary"))
	builder := newArtifactBuilder(config.BuildManagementConfig{
		Enabled:              true,
		MaxArtifactBytes:     1024,
		AllowedDownloadHosts: []string{"github.com"},
		DefaultBaseImage:     "debian:bookworm-slim",
		AllowedBaseImages:    []string{"debian:bookworm-slim"},
	}, nil)

	err := builder.validateRequest(artifactBuildRequest{
		SourceKind:   artifactSourceURL,
		DownloadURL:  "https://evil.example/release.tar.gz",
		SHA256:       hex.EncodeToString(sum[:]),
		ExtractMode:  extractNone,
		ImageTag:     "local/test:latest",
		BaseImage:    "debian:bookworm-slim",
		InternalPort: 8080,
	})
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected host allowlist error, got %v", err)
	}

	err = builder.validateRequest(artifactBuildRequest{
		SourceKind:   artifactSourceUpload,
		UploadReader: strings.NewReader("binary"),
		SHA256:       strings.Repeat("a", 63),
		ExtractMode:  extractNone,
		ImageTag:     "local/test:latest",
		BaseImage:    "debian:bookworm-slim",
		InternalPort: 8080,
	})
	if err == nil || !strings.Contains(err.Error(), "64 hex") {
		t.Fatalf("expected checksum validation error, got %v", err)
	}
}

func TestExtractFromTarGZRejectsTraversalEntries(t *testing.T) {
	payload := buildTarGZForTest(t, map[string]string{
		"../evil": "bad",
	})

	_, err := extractFromTarGZ(payload, "mcp-server", 1024)
	if err == nil || !strings.Contains(err.Error(), "unsafe archive path") {
		t.Fatalf("expected unsafe archive error, got %v", err)
	}
}

func TestExtractFromTarGZSelectsRequestedArtifact(t *testing.T) {
	payload := buildTarGZForTest(t, map[string]string{
		"README.md":  "ignore",
		"mcp-server": "binary",
	})

	out, err := extractFromTarGZ(payload, "mcp-server", 1024)
	if err != nil {
		t.Fatalf("extract artifact: %v", err)
	}
	if string(out) != "binary" {
		t.Fatalf("expected extracted binary, got %q", out)
	}
}

func TestGeneratedDockerfileUsesJSONEntrypointArgs(t *testing.T) {
	dockerfile, err := generatedDockerfile("debian:bookworm-slim", []string{"mcp", "value with spaces"}, 8080)
	if err != nil {
		t.Fatalf("generate Dockerfile: %v", err)
	}
	if !strings.Contains(dockerfile, `ENTRYPOINT ["/usr/local/bin/mcp-entrypoint","mcp","value with spaces"]`) {
		t.Fatalf("expected JSON entrypoint args, got:\n%s", dockerfile)
	}
}

func buildTarGZForTest(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		payload := []byte(content)
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(payload))}); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write(payload); err != nil {
			t.Fatalf("write tar body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}
