package gateway

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
	"github.com/ulikunitz/xz"
)

func TestStdioInstallerInstallsUploadWithoutImplicitFolders(t *testing.T) {
	storeDir := t.TempDir()
	artifact := testTarXZ(t, []testTarEntry{
		{Name: "./", Mode: 0o755, Dir: true},
		{Name: "annas-mcp", Body: "#!/bin/sh\nexit 0\n", Mode: 0o755},
	})
	installer := newStdioInstaller(config.StdioInstallerConfig{
		Enabled:          true,
		StoreDir:         storeDir,
		MaxArtifactBytes: 2 << 20,
	})

	result, err := installer.Install(context.Background(), stdioInstallRequest{
		SourceKind:   stdioInstallUpload,
		RouteID:      "Anna MCP",
		DisplayName:  "Anna MCP",
		UploadName:   "annas-mcp_0.0.5_linux_amd64.tar.xz",
		UploadReader: bytes.NewReader(artifact),
		ExtractMode:  "auto",
	})
	if err != nil {
		t.Fatalf("install upload: %v", err)
	}
	if result.RouteID != "anna-mcp" {
		t.Fatalf("expected slugified route id, got %q", result.RouteID)
	}
	if _, err := os.Stat(result.Command); err != nil {
		t.Fatalf("expected installed executable: %v", err)
	}
	if _, err := os.Stat(filepath.Join(result.WorkingDir, "manifest.json")); err != nil {
		t.Fatalf("expected manifest: %v", err)
	}
	if _, err := os.Stat(filepath.Join(result.WorkingDir, "downloads")); !os.IsNotExist(err) {
		t.Fatalf("downloads folder should not be created unless requested")
	}
}

func TestStdioInstallerCreatesRequestedExtraFolders(t *testing.T) {
	storeDir := t.TempDir()
	artifact := testTarXZ(t, []testTarEntry{
		{Name: "bin/test-mcp", Body: "#!/bin/sh\nexit 0\n", Mode: 0o755},
	})
	installer := newStdioInstaller(config.StdioInstallerConfig{
		Enabled:          true,
		StoreDir:         storeDir,
		MaxArtifactBytes: 2 << 20,
	})

	result, err := installer.Install(context.Background(), stdioInstallRequest{
		SourceKind:     stdioInstallUpload,
		RouteID:        "with-folders",
		DisplayName:    "With Folders",
		UploadName:     "test-mcp.tar.xz",
		UploadReader:   bytes.NewReader(artifact),
		ExtractMode:    extractTarXZ,
		ExecutablePath: "bin/test-mcp",
		ExtraFolders:   []string{"downloads", "cache/data"},
	})
	if err != nil {
		t.Fatalf("install upload: %v", err)
	}
	for _, folder := range []string{"downloads", "cache/data"} {
		if info, err := os.Stat(filepath.Join(result.WorkingDir, folder)); err != nil || !info.IsDir() {
			t.Fatalf("expected requested folder %q, info=%#v err=%v", folder, info, err)
		}
	}
}

func TestStdioInstallerRejectsUnsafeExtraFolder(t *testing.T) {
	storeDir := t.TempDir()
	artifact := testTarXZ(t, []testTarEntry{
		{Name: "bin/test-mcp", Body: "#!/bin/sh\nexit 0\n", Mode: 0o755},
	})
	installer := newStdioInstaller(config.StdioInstallerConfig{
		Enabled:          true,
		StoreDir:         storeDir,
		MaxArtifactBytes: 2 << 20,
	})

	_, err := installer.Install(context.Background(), stdioInstallRequest{
		SourceKind:     stdioInstallUpload,
		RouteID:        "unsafe-folder",
		DisplayName:    "Unsafe Folder",
		UploadName:     "test-mcp.tar.xz",
		UploadReader:   bytes.NewReader(artifact),
		ExtractMode:    extractTarXZ,
		ExecutablePath: "bin/test-mcp",
		ExtraFolders:   []string{"../downloads"},
	})
	if err == nil {
		t.Fatalf("expected unsafe extra folder to be rejected")
	}
}

func TestSelectExecutableFromTarXZRejectsUnsafeEntryAfterTarget(t *testing.T) {
	artifact := testTarXZ(t, []testTarEntry{
		{Name: "bin/test-mcp", Body: "#!/bin/sh\nexit 0\n", Mode: 0o755},
		{Name: "../evil", Body: "nope", Mode: 0o644},
	})

	if _, _, err := selectExecutable(artifact, extractTarXZ, "bin/test-mcp", 2<<20); err == nil {
		t.Fatalf("expected unsafe archive entry to be rejected even after selected executable")
	}
}

type testTarEntry struct {
	Name string
	Body string
	Mode int64
	Dir  bool
}

func testTarXZ(t *testing.T, entries []testTarEntry) []byte {
	t.Helper()

	var buf bytes.Buffer
	xzw, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatalf("create xz writer: %v", err)
	}
	tw := tar.NewWriter(xzw)
	for _, entry := range entries {
		payload := []byte(entry.Body)
		header := &tar.Header{
			Name: entry.Name,
			Mode: entry.Mode,
			Size: int64(len(payload)),
		}
		if entry.Dir {
			header.Typeflag = tar.TypeDir
			header.Size = 0
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if entry.Dir {
			continue
		}
		if _, err := tw.Write(payload); err != nil {
			t.Fatalf("write tar payload: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := xzw.Close(); err != nil {
		t.Fatalf("close xz writer: %v", err)
	}
	return buf.Bytes()
}
