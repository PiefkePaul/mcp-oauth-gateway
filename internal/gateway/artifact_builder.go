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
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

const (
	artifactSourceUpload = "upload"
	artifactSourceURL    = "url"
	extractNone          = "none"
	extractTarGZ         = "tar.gz"
	extractZip           = "zip"
	buildContextFile     = "mcp-entrypoint"
)

type artifactBuildRequest struct {
	SourceKind     string
	UploadName     string
	UploadReader   io.Reader
	DownloadURL    string
	SHA256         string
	ExtractMode    string
	ArtifactPath   string
	ImageTag       string
	BaseImage      string
	EntrypointArgs []string
	InternalPort   int
}

type artifactBuildResult struct {
	ImageTag     string
	BaseImage    string
	Bytes        int
	SHA256       string
	InternalPort int
}

type artifactBuilder struct {
	cfg           config.BuildManagementConfig
	dockerManager *dockerManager
	httpClient    *http.Client
}

func newArtifactBuilder(cfg config.BuildManagementConfig, dockerManager *dockerManager) *artifactBuilder {
	return &artifactBuilder{
		cfg:           cfg,
		dockerManager: dockerManager,
		httpClient: &http.Client{
			Timeout: 2 * time.Minute,
		},
	}
}

func (b *artifactBuilder) Build(ctx context.Context, req artifactBuildRequest) (artifactBuildResult, error) {
	if !b.cfg.Enabled {
		return artifactBuildResult{}, fmt.Errorf("artifact builds are disabled")
	}
	if b.dockerManager == nil {
		return artifactBuildResult{}, fmt.Errorf("docker management is required for image builds")
	}
	if err := b.validateRequest(req); err != nil {
		return artifactBuildResult{}, err
	}

	raw, err := b.readArtifact(ctx, req)
	if err != nil {
		return artifactBuildResult{}, err
	}
	sum := sha256.Sum256(raw)
	actualChecksum := hex.EncodeToString(sum[:])
	if !strings.EqualFold(actualChecksum, normalizeHexChecksum(req.SHA256)) {
		return artifactBuildResult{}, fmt.Errorf("sha256 mismatch: expected %s, got %s", normalizeHexChecksum(req.SHA256), actualChecksum)
	}

	entrypoint, err := selectEntrypointArtifact(raw, req.ExtractMode, req.ArtifactPath, b.cfg.MaxArtifactBytes)
	if err != nil {
		return artifactBuildResult{}, err
	}
	baseImage := strings.ToLower(strings.TrimSpace(req.BaseImage))
	contextTar, err := buildDockerContext(entrypoint, baseImage, req.EntrypointArgs, req.InternalPort)
	if err != nil {
		return artifactBuildResult{}, err
	}
	if err := b.dockerManager.BuildImage(ctx, req.ImageTag, contextTar); err != nil {
		return artifactBuildResult{}, err
	}

	return artifactBuildResult{
		ImageTag:     req.ImageTag,
		BaseImage:    baseImage,
		Bytes:        len(raw),
		SHA256:       actualChecksum,
		InternalPort: req.InternalPort,
	}, nil
}

func (b *artifactBuilder) validateRequest(req artifactBuildRequest) error {
	switch strings.TrimSpace(req.SourceKind) {
	case artifactSourceUpload:
		if req.UploadReader == nil {
			return fmt.Errorf("artifact upload is required")
		}
	case artifactSourceURL:
		if strings.TrimSpace(req.DownloadURL) == "" {
			return fmt.Errorf("download URL is required")
		}
		if err := b.validateDownloadURL(req.DownloadURL); err != nil {
			return err
		}
	default:
		return fmt.Errorf("source kind must be upload or url")
	}
	if normalizeHexChecksum(req.SHA256) == "" {
		return fmt.Errorf("sha256 checksum is required")
	}
	if len(normalizeHexChecksum(req.SHA256)) != 64 {
		return fmt.Errorf("sha256 checksum must be 64 hex characters")
	}
	if _, err := hex.DecodeString(normalizeHexChecksum(req.SHA256)); err != nil {
		return fmt.Errorf("sha256 checksum must be hex")
	}
	if err := validateImageTag(req.ImageTag); err != nil {
		return err
	}
	if err := validateImageTag(req.BaseImage); err != nil {
		return fmt.Errorf("base image is invalid: %w", err)
	}
	baseImage := strings.ToLower(strings.TrimSpace(req.BaseImage))
	if baseImage == "" {
		return fmt.Errorf("base image is required")
	}
	if !slices.Contains(b.cfg.AllowedBaseImages, baseImage) {
		return fmt.Errorf("base image %q is not allowed", req.BaseImage)
	}
	switch strings.TrimSpace(req.ExtractMode) {
	case extractNone, extractTarGZ, extractZip:
	default:
		return fmt.Errorf("extract mode must be none, tar.gz or zip")
	}
	if req.ExtractMode != extractNone && strings.TrimSpace(req.ArtifactPath) == "" {
		return fmt.Errorf("artifact path inside archive is required")
	}
	if req.InternalPort <= 0 || req.InternalPort > 65535 {
		return fmt.Errorf("internal port must be between 1 and 65535")
	}
	return nil
}

func (b *artifactBuilder) readArtifact(ctx context.Context, req artifactBuildRequest) ([]byte, error) {
	switch req.SourceKind {
	case artifactSourceUpload:
		return readLimited(req.UploadReader, b.cfg.MaxArtifactBytes)
	case artifactSourceURL:
		return b.download(ctx, req.DownloadURL)
	default:
		return nil, fmt.Errorf("unsupported artifact source")
	}
}

func (b *artifactBuilder) download(ctx context.Context, rawURL string) ([]byte, error) {
	client := *b.httpClient
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return b.validateParsedDownloadURL(req.URL)
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
	if resp.ContentLength > b.cfg.MaxArtifactBytes {
		return nil, fmt.Errorf("artifact is larger than configured max size")
	}
	return readLimited(resp.Body, b.cfg.MaxArtifactBytes)
}

func (b *artifactBuilder) validateDownloadURL(rawURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("download URL is invalid: %w", err)
	}
	return b.validateParsedDownloadURL(parsed)
}

func (b *artifactBuilder) validateParsedDownloadURL(parsed *url.URL) error {
	if parsed == nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return fmt.Errorf("download URL must use https")
	}
	host := strings.ToLower(parsed.Hostname())
	if !b.cfg.AllowAnyDownloadHost && !slices.Contains(b.cfg.AllowedDownloadHosts, host) {
		return fmt.Errorf("download host %q is not allowed", host)
	}
	if b.cfg.AllowAnyDownloadHost {
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

func readLimited(reader io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("max artifact size must be configured")
	}
	var buf bytes.Buffer
	written, err := io.CopyN(&buf, reader, maxBytes+1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if written > maxBytes {
		return nil, fmt.Errorf("artifact exceeds max size of %d bytes", maxBytes)
	}
	if buf.Len() == 0 {
		return nil, fmt.Errorf("artifact is empty")
	}
	return buf.Bytes(), nil
}

func selectEntrypointArtifact(raw []byte, mode, artifactPath string, maxBytes int64) ([]byte, error) {
	switch mode {
	case extractNone:
		return raw, nil
	case extractTarGZ:
		return extractFromTarGZ(raw, artifactPath, maxBytes)
	case extractZip:
		return extractFromZip(raw, artifactPath, maxBytes)
	default:
		return nil, fmt.Errorf("unsupported extract mode")
	}
}

func extractFromTarGZ(raw []byte, artifactPath string, maxBytes int64) ([]byte, error) {
	target, err := cleanArchivePath(artifactPath)
	if err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("open tar.gz: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar.gz: %w", err)
		}
		name, err := cleanArchivePath(header.Name)
		if err != nil {
			return nil, fmt.Errorf("unsafe archive path %q", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg, tar.TypeRegA:
			if name == target {
				return readLimited(tr, maxBytes)
			}
		default:
			return nil, fmt.Errorf("archive contains unsupported or unsafe entry %q", header.Name)
		}
	}
	return nil, fmt.Errorf("artifact path %q not found in archive", artifactPath)
}

func extractFromZip(raw []byte, artifactPath string, maxBytes int64) ([]byte, error) {
	target, err := cleanArchivePath(artifactPath)
	if err != nil {
		return nil, err
	}
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	for _, file := range reader.File {
		name, err := cleanArchivePath(file.Name)
		if err != nil {
			return nil, fmt.Errorf("unsafe archive path %q", file.Name)
		}
		if file.FileInfo().IsDir() {
			continue
		}
		if file.FileInfo().Mode()&^0777 != 0 {
			return nil, fmt.Errorf("archive contains unsupported or unsafe entry %q", file.Name)
		}
		if name != target {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return readLimited(rc, maxBytes)
	}
	return nil, fmt.Errorf("artifact path %q not found in archive", artifactPath)
}

func cleanArchivePath(raw string) (string, error) {
	value := strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/")
	if value == "" || strings.HasPrefix(value, "/") {
		return "", fmt.Errorf("archive path must be relative")
	}
	clean := path.Clean(value)
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." {
		return "", fmt.Errorf("archive path must not traverse directories")
	}
	return clean, nil
}

func buildDockerContext(entrypoint []byte, baseImage string, entrypointArgs []string, internalPort int) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	defer tw.Close()

	dockerfile, err := generatedDockerfile(baseImage, entrypointArgs, internalPort)
	if err != nil {
		return nil, err
	}
	if err := writeTarFile(tw, "Dockerfile", []byte(dockerfile), 0o644); err != nil {
		return nil, err
	}
	if err := writeTarFile(tw, buildContextFile, entrypoint, 0o755); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func generatedDockerfile(baseImage string, entrypointArgs []string, internalPort int) (string, error) {
	entrypoint := append([]string{"/usr/local/bin/" + buildContextFile}, normalizeEntrypointArgs(entrypointArgs)...)
	entrypointJSON, err := json.Marshal(entrypoint)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{
		"FROM " + baseImage,
		"RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*",
		"WORKDIR /app",
		"COPY " + buildContextFile + " /usr/local/bin/" + buildContextFile,
		"RUN chmod 0755 /usr/local/bin/" + buildContextFile,
		"EXPOSE " + strconv.Itoa(internalPort),
		"ENTRYPOINT " + string(entrypointJSON),
		"",
	}, "\n"), nil
}

func normalizeEntrypointArgs(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func writeTarFile(tw *tar.Writer, name string, payload []byte, mode int64) error {
	header := &tar.Header{
		Name:    name,
		Mode:    mode,
		Size:    int64(len(payload)),
		ModTime: time.Unix(0, 0),
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(payload)
	return err
}

func validateImageTag(image string) error {
	image = strings.TrimSpace(image)
	if image == "" {
		return fmt.Errorf("image tag is required")
	}
	if strings.ContainsAny(image, " \t\r\n\"'`$\\") {
		return fmt.Errorf("image tag contains unsafe characters")
	}
	if strings.HasPrefix(image, "-") || strings.Contains(image, "..") {
		return fmt.Errorf("image tag is invalid")
	}
	if len(image) > 200 {
		return fmt.Errorf("image tag is too long")
	}
	return nil
}

func normalizeHexChecksum(value string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(value, "sha256:")))
}
