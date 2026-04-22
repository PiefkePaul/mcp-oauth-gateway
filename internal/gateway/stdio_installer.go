package gateway

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
	"github.com/ulikunitz/xz"
)

const (
	stdioInstallUpload = "upload"
	stdioInstallURL    = "url"
	stdioInstallGitHub = "github"
)

type stdioInstallRequest struct {
	SourceKind     string
	RouteID        string
	DisplayName    string
	DownloadURL    string
	GitHubRepo     string
	GitHubVersion  string
	AssetPattern   string
	UploadName     string
	UploadReader   io.Reader
	SHA256         string
	ExtractMode    string
	ExecutablePath string
	Args           []string
	ExtraFolders   []string
}

type stdioInstallResult struct {
	RouteID        string
	Command        string
	WorkingDir     string
	SHA256         string
	SourceURL      string
	SourceAsset    string
	ExecutablePath string
	ExtraFolders   []string
}

type stdioInstaller struct {
	cfg        config.StdioInstallerConfig
	httpClient *http.Client
}

type stdioInstallManifest struct {
	RouteID        string   `json:"route_id"`
	DisplayName    string   `json:"display_name"`
	SourceKind     string   `json:"source_kind"`
	SourceURL      string   `json:"source_url,omitempty"`
	GitHubRepo     string   `json:"github_repo,omitempty"`
	GitHubVersion  string   `json:"github_version,omitempty"`
	SourceAsset    string   `json:"source_asset,omitempty"`
	SHA256         string   `json:"sha256"`
	Executable     string   `json:"executable"`
	Args           []string `json:"args,omitempty"`
	ExtraFolders   []string `json:"extra_folders,omitempty"`
	InstalledAtUTC string   `json:"installed_at_utc"`
}

type githubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Digest             string `json:"digest"`
	} `json:"assets"`
}

func newStdioInstaller(cfg config.StdioInstallerConfig) *stdioInstaller {
	return &stdioInstaller{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 2 * time.Minute,
		},
	}
}

func (i *stdioInstaller) Install(ctx context.Context, req stdioInstallRequest) (stdioInstallResult, error) {
	if !i.cfg.Enabled {
		return stdioInstallResult{}, fmt.Errorf("STDIO installer is disabled")
	}
	if err := i.validateRequest(req); err != nil {
		return stdioInstallResult{}, err
	}

	sourceName := req.UploadName
	sourceURL := strings.TrimSpace(req.DownloadURL)
	expectedChecksum := normalizeHexChecksum(req.SHA256)
	githubVersion := strings.TrimSpace(req.GitHubVersion)
	if strings.TrimSpace(req.SourceKind) == stdioInstallGitHub {
		assetURL, assetName, assetDigest, version, err := i.resolveGitHubReleaseAsset(ctx, req.GitHubRepo, req.GitHubVersion, req.AssetPattern)
		if err != nil {
			return stdioInstallResult{}, err
		}
		sourceURL = assetURL
		sourceName = assetName
		githubVersion = version
		if expectedChecksum == "" && strings.HasPrefix(assetDigest, "sha256:") {
			expectedChecksum = normalizeHexChecksum(assetDigest)
		}
	}

	raw, err := i.readSource(ctx, req, sourceURL)
	if err != nil {
		return stdioInstallResult{}, err
	}
	sum := sha256.Sum256(raw)
	actualChecksum := hex.EncodeToString(sum[:])
	if expectedChecksum != "" && !strings.EqualFold(actualChecksum, expectedChecksum) {
		return stdioInstallResult{}, fmt.Errorf("sha256 mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}
	if expectedChecksum == "" && strings.TrimSpace(req.SourceKind) != stdioInstallUpload {
		return stdioInstallResult{}, fmt.Errorf("sha256 checksum is required unless GitHub release digest is available")
	}

	mode := detectExtractMode(req.ExtractMode, sourceName, sourceURL)
	executable, selectedPath, err := selectExecutable(raw, mode, req.ExecutablePath, i.cfg.MaxArtifactBytes)
	if err != nil {
		return stdioInstallResult{}, err
	}
	extraFolders, err := validateRelativeFolders(req.ExtraFolders)
	if err != nil {
		return stdioInstallResult{}, err
	}

	routeID := slugify(req.RouteID)
	baseDir := filepath.Join(i.cfg.StoreDir, routeID)
	tempDir := baseDir + ".tmp-" + randomShortSuffix()
	if err := os.RemoveAll(tempDir); err != nil {
		return stdioInstallResult{}, err
	}
	if err := os.MkdirAll(filepath.Join(tempDir, "bin"), 0o750); err != nil {
		return stdioInstallResult{}, fmt.Errorf("create install dir: %w", err)
	}
	for _, folder := range extraFolders {
		target, err := safeJoin(tempDir, folder)
		if err != nil {
			return stdioInstallResult{}, err
		}
		if err := os.MkdirAll(target, 0o750); err != nil {
			return stdioInstallResult{}, fmt.Errorf("create folder %q: %w", folder, err)
		}
	}

	executableName := path.Base(selectedPath)
	if executableName == "." || executableName == "/" || executableName == "" {
		executableName = routeID
	}
	commandPath := filepath.Join(tempDir, "bin", executableName)
	if err := os.WriteFile(commandPath, executable, 0o750); err != nil {
		return stdioInstallResult{}, fmt.Errorf("write executable: %w", err)
	}

	manifest := stdioInstallManifest{
		RouteID:        routeID,
		DisplayName:    strings.TrimSpace(req.DisplayName),
		SourceKind:     strings.TrimSpace(req.SourceKind),
		SourceURL:      sourceURL,
		GitHubRepo:     strings.TrimSpace(req.GitHubRepo),
		GitHubVersion:  githubVersion,
		SourceAsset:    sourceName,
		SHA256:         actualChecksum,
		Executable:     filepath.Join("bin", executableName),
		Args:           normalizeInstallList(req.Args),
		ExtraFolders:   extraFolders,
		InstalledAtUTC: time.Now().UTC().Format(time.RFC3339),
	}
	manifestPayload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return stdioInstallResult{}, err
	}
	if err := os.WriteFile(filepath.Join(tempDir, "manifest.json"), manifestPayload, 0o640); err != nil {
		return stdioInstallResult{}, fmt.Errorf("write manifest: %w", err)
	}

	if err := os.MkdirAll(i.cfg.StoreDir, 0o750); err != nil {
		return stdioInstallResult{}, fmt.Errorf("create STDIO store: %w", err)
	}
	if err := os.RemoveAll(baseDir); err != nil {
		return stdioInstallResult{}, fmt.Errorf("replace install dir: %w", err)
	}
	if err := os.Rename(tempDir, baseDir); err != nil {
		return stdioInstallResult{}, fmt.Errorf("activate install dir: %w", err)
	}

	return stdioInstallResult{
		RouteID:        routeID,
		Command:        filepath.Join(baseDir, "bin", executableName),
		WorkingDir:     baseDir,
		SHA256:         actualChecksum,
		SourceURL:      sourceURL,
		SourceAsset:    sourceName,
		ExecutablePath: selectedPath,
		ExtraFolders:   extraFolders,
	}, nil
}

func (i *stdioInstaller) validateRequest(req stdioInstallRequest) error {
	if slugify(req.RouteID) == "" {
		return fmt.Errorf("route id is required")
	}
	if i.cfg.MaxArtifactBytes <= 0 {
		return fmt.Errorf("max artifact size must be configured")
	}
	switch strings.TrimSpace(req.SourceKind) {
	case stdioInstallUpload:
		if req.UploadReader == nil {
			return fmt.Errorf("artifact upload is required")
		}
	case stdioInstallURL:
		if strings.TrimSpace(req.DownloadURL) == "" {
			return fmt.Errorf("download URL is required")
		}
		if normalizeHexChecksum(req.SHA256) == "" {
			return fmt.Errorf("sha256 checksum is required for URL installs")
		}
		if err := i.validateDownloadURL(req.DownloadURL); err != nil {
			return err
		}
	case stdioInstallGitHub:
		if strings.TrimSpace(req.GitHubRepo) == "" {
			return fmt.Errorf("GitHub repository URL is required")
		}
	default:
		return fmt.Errorf("source kind must be upload, url or github")
	}
	if checksum := normalizeHexChecksum(req.SHA256); checksum != "" {
		if len(checksum) != 64 {
			return fmt.Errorf("sha256 checksum must be 64 hex characters")
		}
		if _, err := hex.DecodeString(checksum); err != nil {
			return fmt.Errorf("sha256 checksum must be hex")
		}
	}
	if _, err := validateRelativeFolders(req.ExtraFolders); err != nil {
		return err
	}
	return nil
}

func (i *stdioInstaller) readSource(ctx context.Context, req stdioInstallRequest, sourceURL string) ([]byte, error) {
	switch strings.TrimSpace(req.SourceKind) {
	case stdioInstallUpload:
		return readLimited(req.UploadReader, i.cfg.MaxArtifactBytes)
	case stdioInstallURL, stdioInstallGitHub:
		if err := i.validateDownloadURL(sourceURL); err != nil {
			return nil, err
		}
		return i.download(ctx, sourceURL)
	default:
		return nil, fmt.Errorf("unsupported source kind")
	}
}

func (i *stdioInstaller) download(ctx context.Context, rawURL string) ([]byte, error) {
	client := *i.httpClient
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return i.validateParsedDownloadURL(req.URL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("download failed: %s", resp.Status)
	}
	if resp.ContentLength > i.cfg.MaxArtifactBytes {
		return nil, fmt.Errorf("artifact is larger than configured max size")
	}
	return readLimited(resp.Body, i.cfg.MaxArtifactBytes)
}

func (i *stdioInstaller) validateDownloadURL(rawURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("download URL is invalid: %w", err)
	}
	return i.validateParsedDownloadURL(parsed)
}

func (i *stdioInstaller) validateParsedDownloadURL(parsed *url.URL) error {
	if parsed == nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return fmt.Errorf("download URL must use https")
	}
	host := strings.ToLower(parsed.Hostname())
	if !i.cfg.AllowAnyDownloadHost && !slices.Contains(i.cfg.AllowedDownloadHosts, host) {
		return fmt.Errorf("download host %q is not allowed", host)
	}
	if i.cfg.AllowAnyDownloadHost {
		ips, err := net.LookupIP(host)
		if err != nil {
			return fmt.Errorf("download host lookup failed: %w", err)
		}
		for _, ip := range ips {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				return fmt.Errorf("download host resolves to a private or local address")
			}
		}
	}
	return nil
}

func (i *stdioInstaller) resolveGitHubReleaseAsset(ctx context.Context, repoURL, version, pattern string) (downloadURL, assetName, digest, resolvedVersion string, err error) {
	owner, repo, err := parseGitHubRepo(repoURL)
	if err != nil {
		return "", "", "", "", err
	}
	version = strings.TrimSpace(version)
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", url.PathEscape(owner), url.PathEscape(repo))
	if version != "" && !strings.EqualFold(version, "latest") {
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(version))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", "", "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := i.httpClient.Do(req)
	if err != nil {
		return "", "", "", "", fmt.Errorf("GitHub release lookup failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", "", "", fmt.Errorf("GitHub release lookup failed: %s", resp.Status)
	}
	var release githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&release); err != nil {
		return "", "", "", "", fmt.Errorf("decode GitHub release: %w", err)
	}
	if len(release.Assets) == 0 {
		return "", "", "", "", fmt.Errorf("GitHub release has no assets")
	}
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		pattern = defaultReleaseAssetPattern()
	}
	for _, asset := range release.Assets {
		name := strings.ToLower(asset.Name)
		if strings.Contains(name, pattern) && strings.TrimSpace(asset.BrowserDownloadURL) != "" {
			return asset.BrowserDownloadURL, asset.Name, asset.Digest, release.TagName, nil
		}
	}
	return "", "", "", "", fmt.Errorf("no release asset matches %q", pattern)
}

func parseGitHubRepo(raw string) (owner, repo string, err error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() != "github.com" {
		return "", "", fmt.Errorf("GitHub repository must be a github.com URL")
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("GitHub repository URL must include owner and repo")
	}
	return parts[0], strings.TrimSuffix(parts[1], ".git"), nil
}

func defaultReleaseAssetPattern() string {
	switch runtime.GOARCH {
	case "amd64":
		return "linux_amd64"
	case "arm64":
		return "linux_arm64"
	case "arm":
		return "linux_arm"
	default:
		return "linux_" + runtime.GOARCH
	}
}

func detectExtractMode(explicit, sourceName, sourceURL string) string {
	mode := strings.ToLower(strings.TrimSpace(explicit))
	if mode != "" && mode != "auto" {
		return mode
	}
	name := strings.ToLower(strings.TrimSpace(sourceName))
	if name == "" {
		if parsed, err := url.Parse(sourceURL); err == nil {
			name = strings.ToLower(path.Base(parsed.Path))
		}
	}
	switch {
	case strings.HasSuffix(name, ".tar.gz"), strings.HasSuffix(name, ".tgz"):
		return extractTarGZ
	case strings.HasSuffix(name, ".tar.xz"), strings.HasSuffix(name, ".txz"):
		return extractTarXZ
	case strings.HasSuffix(name, ".zip"):
		return extractZip
	default:
		return extractNone
	}
}

func selectExecutable(raw []byte, mode, executablePath string, maxBytes int64) ([]byte, string, error) {
	switch mode {
	case extractNone:
		return raw, path.Base(strings.TrimSpace(executablePath)), nil
	case extractTarGZ:
		gz, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, "", fmt.Errorf("open tar.gz: %w", err)
		}
		defer gz.Close()
		return selectExecutableFromTar(tar.NewReader(gz), executablePath, maxBytes)
	case extractTarXZ:
		xzr, err := xz.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, "", fmt.Errorf("open tar.xz: %w", err)
		}
		return selectExecutableFromTar(tar.NewReader(xzr), executablePath, maxBytes)
	case extractZip:
		return selectExecutableFromZip(raw, executablePath, maxBytes)
	default:
		return nil, "", fmt.Errorf("unsupported extract mode %q", mode)
	}
}

func selectExecutableFromTar(tr *tar.Reader, executablePath string, maxBytes int64) ([]byte, string, error) {
	target, hasTarget, err := optionalArchivePath(executablePath)
	if err != nil {
		return nil, "", err
	}
	var selected []byte
	selectedPath := ""
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("read archive: %w", err)
		}
		if header.Typeflag == tar.TypeDir && isArchiveRootPath(header.Name) {
			continue
		}
		name, err := cleanArchivePath(header.Name)
		if err != nil {
			return nil, "", fmt.Errorf("unsafe archive path %q", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg, tar.TypeRegA:
			if hasTarget && name != target {
				continue
			}
			if !hasTarget && header.FileInfo().Mode()&0o111 == 0 {
				continue
			}
			payload, err := readLimited(tr, maxBytes)
			if err != nil {
				return nil, "", err
			}
			if hasTarget {
				if name != target {
					continue
				}
				if selected != nil {
					return nil, "", fmt.Errorf("archive contains duplicate executable path %q", target)
				}
				selected = payload
				selectedPath = name
				continue
			}
			if selected != nil {
				return nil, "", fmt.Errorf("archive contains multiple executable candidates; set executable path explicitly")
			}
			selected = payload
			selectedPath = name
		default:
			return nil, "", fmt.Errorf("archive contains unsupported or unsafe entry %q", header.Name)
		}
	}
	if selected != nil {
		return selected, selectedPath, nil
	}
	if hasTarget {
		return nil, "", fmt.Errorf("executable path %q not found in archive", executablePath)
	}
	return nil, "", fmt.Errorf("no executable file found in archive")
}

func selectExecutableFromZip(raw []byte, executablePath string, maxBytes int64) ([]byte, string, error) {
	target, hasTarget, err := optionalArchivePath(executablePath)
	if err != nil {
		return nil, "", err
	}
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, "", fmt.Errorf("open zip: %w", err)
	}
	var selected []byte
	selectedPath := ""
	for _, file := range reader.File {
		if file.FileInfo().IsDir() && isArchiveRootPath(file.Name) {
			continue
		}
		name, err := cleanArchivePath(file.Name)
		if err != nil {
			return nil, "", fmt.Errorf("unsafe archive path %q", file.Name)
		}
		if file.FileInfo().IsDir() {
			continue
		}
		if file.FileInfo().Mode()&^0777 != 0 {
			return nil, "", fmt.Errorf("archive contains unsupported or unsafe entry %q", file.Name)
		}
		if hasTarget && name != target {
			continue
		}
		if !hasTarget && file.FileInfo().Mode()&0o111 == 0 {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return nil, "", err
		}
		payload, readErr := readLimited(rc, maxBytes)
		_ = rc.Close()
		if readErr != nil {
			return nil, "", readErr
		}
		if hasTarget {
			if name != target {
				continue
			}
			if selected != nil {
				return nil, "", fmt.Errorf("archive contains duplicate executable path %q", target)
			}
			selected = payload
			selectedPath = name
			continue
		}
		if selected != nil {
			return nil, "", fmt.Errorf("archive contains multiple executable candidates; set executable path explicitly")
		}
		selected = payload
		selectedPath = name
	}
	if selected != nil {
		return selected, selectedPath, nil
	}
	if hasTarget {
		return nil, "", fmt.Errorf("executable path %q not found in archive", executablePath)
	}
	return nil, "", fmt.Errorf("no executable file found in archive")
}

func optionalArchivePath(raw string) (string, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false, nil
	}
	clean, err := cleanArchivePath(raw)
	return clean, true, err
}

func safeJoin(base, rel string) (string, error) {
	rel = strings.ReplaceAll(strings.TrimSpace(rel), "\\", "/")
	if rel == "" || strings.HasPrefix(rel, "/") {
		return "", fmt.Errorf("path must be relative")
	}
	clean := path.Clean(rel)
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." {
		return "", fmt.Errorf("path must not traverse directories")
	}
	target := filepath.Join(base, filepath.FromSlash(clean))
	baseClean := filepath.Clean(base)
	if target != baseClean && !strings.HasPrefix(target, baseClean+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes base directory")
	}
	return target, nil
}

func normalizeRelativeFolders(values []string) []string {
	folders, _ := validateRelativeFolders(values)
	return folders
}

func validateRelativeFolders(values []string) ([]string, error) {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, raw := range values {
		raw = strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/")
		if raw == "" {
			continue
		}
		clean := path.Clean(raw)
		if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." || strings.HasPrefix(clean, "/") {
			return nil, fmt.Errorf("folder %q is invalid: path must be relative and must not traverse directories", raw)
		}
		if !seen[clean] {
			seen[clean] = true
			out = append(out, clean)
		}
	}
	return out, nil
}

func normalizeInstallList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func randomShortSuffix() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}
