package config

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultListenAddr          = ":8080"
	defaultRoutesPath          = "/config/routes.yaml"
	defaultAuthStorePath       = "/data/auth-store.enc"
	defaultDockerHost          = "unix:///var/run/docker.sock"
	defaultBuildWorkDir        = "/data/builds"
	defaultOpenAPIStoreDir     = "/data/openapi"
	defaultStdioStoreDir       = "/data/stdio-mcp"
	defaultBuildMaxArtifactMB  = 100
	defaultAccessTokenTTL      = time.Hour
	defaultRefreshTokenTTL     = 30 * 24 * time.Hour
	defaultAuthorizationTTL    = 10 * time.Minute
	defaultSessionTTL          = 30 * 24 * time.Hour
	defaultAccountPortalTitle  = "MCP Gateway"
	defaultAuthenticatedUserID = "X-MCP-Authenticated-User-ID"
	defaultAuthenticatedEmail  = "X-MCP-Authenticated-Email"
)

type Config struct {
	ListenAddr          string
	PublicBaseURL       string
	RoutesPath          string
	AccountPortalTitle  string
	AllowSelfSignup     bool
	AccessLog           bool
	BootstrapEmail      string
	BootstrapPassword   string
	AllowedEmails       []string
	AllowedEmailDomains []string
	Auth                AuthConfig
	DockerManagement    DockerManagementConfig
	BuildManagement     BuildManagementConfig
	StdioInstaller      StdioInstallerConfig
	OpenAPIStoreDir     string
	Routes              []Route
}

type AuthConfig struct {
	StorePath              string
	MasterKey              []byte
	AccessTokenTTL         time.Duration
	RefreshTokenTTL        time.Duration
	AuthorizationCodeTTL   time.Duration
	SessionTTL             time.Duration
	AllowedRedirectOrigins []string
}

type DockerManagementConfig struct {
	Enabled         bool
	Host            string
	DefaultNetworks []string
	RestartPolicy   string
}

type BuildManagementConfig struct {
	Enabled              bool
	WorkDir              string
	MaxArtifactBytes     int64
	AllowedDownloadHosts []string
	AllowAnyDownloadHost bool
	DefaultBaseImage     string
	AllowedBaseImages    []string
}

type StdioInstallerConfig struct {
	Enabled              bool
	StoreDir             string
	MaxArtifactBytes     int64
	AllowedDownloadHosts []string
	AllowAnyDownloadHost bool
}

type Route struct {
	ID                     string            `yaml:"id"`
	DisplayName            string            `yaml:"display_name"`
	Transport              string            `yaml:"transport,omitempty"`
	PathPrefix             string            `yaml:"path_prefix"`
	Upstream               string            `yaml:"upstream,omitempty"`
	UpstreamMCPPath        string            `yaml:"upstream_mcp_path,omitempty"`
	ScopesSupported        []string          `yaml:"scopes_supported"`
	PassAuthorization      bool              `yaml:"pass_authorization_header"`
	ForwardHeaders         map[string]string `yaml:"forward_headers"`
	UpstreamEnvironment    map[string]string `yaml:"upstream_environment"`
	Access                 RouteAccess       `yaml:"access"`
	Deployment             *RouteDeployment  `yaml:"deployment,omitempty"`
	Stdio                  *RouteStdio       `yaml:"stdio,omitempty"`
	OpenAPI                *RouteOpenAPI     `yaml:"openapi,omitempty"`
	ResourceDocumentation  string            `yaml:"resource_documentation"`
	Notes                  string            `yaml:"notes"`
	NormalizedPathPrefix   string            `yaml:"-"`
	NormalizedUpstreamPath string            `yaml:"-"`
}

type RouteDeployment struct {
	Type          string   `yaml:"type"`
	Managed       bool     `yaml:"managed"`
	Image         string   `yaml:"image"`
	ContainerName string   `yaml:"container_name"`
	InternalPort  int      `yaml:"internal_port"`
	Networks      []string `yaml:"networks,omitempty"`
	RestartPolicy string   `yaml:"restart_policy,omitempty"`
}

type RouteStdio struct {
	Command       string            `yaml:"command"`
	Args          []string          `yaml:"args,omitempty"`
	Env           map[string]string `yaml:"env,omitempty"`
	EnvSecretRefs map[string]string `yaml:"env_secret_refs,omitempty"`
	WorkingDir    string            `yaml:"working_dir,omitempty"`
}

type RouteOpenAPI struct {
	SpecPath       string            `yaml:"spec_path,omitempty"`
	SpecURL        string            `yaml:"spec_url,omitempty"`
	BaseURL        string            `yaml:"base_url"`
	Headers        map[string]string `yaml:"headers,omitempty"`
	TimeoutSeconds int               `yaml:"timeout_seconds,omitempty"`
}

type RouteAccess struct {
	Visibility    string   `yaml:"visibility"`
	Mode          string   `yaml:"mode"`
	AllowedUsers  []string `yaml:"allowed_users,omitempty"`
	AllowedGroups []string `yaml:"allowed_groups,omitempty"`
	DeniedUsers   []string `yaml:"denied_users,omitempty"`
	DeniedGroups  []string `yaml:"denied_groups,omitempty"`
}

type routesFile struct {
	Routes []Route `yaml:"routes"`
}

func Load() (*Config, error) {
	publicBaseURL, err := normalizePublicBaseURL(os.Getenv("MCP_GATEWAY_PUBLIC_BASE_URL"))
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		ListenAddr:          getEnvOrDefault("MCP_GATEWAY_LISTEN_ADDR", defaultListenAddr),
		PublicBaseURL:       publicBaseURL,
		RoutesPath:          getEnvOrDefault("MCP_GATEWAY_ROUTES_PATH", defaultRoutesPath),
		AccountPortalTitle:  getEnvOrDefault("MCP_GATEWAY_ACCOUNT_TITLE", defaultAccountPortalTitle),
		AllowSelfSignup:     getEnvOrDefault("MCP_GATEWAY_ALLOW_SELF_SIGNUP", "false") == "true",
		AccessLog:           getBoolEnv("MCP_GATEWAY_ACCESS_LOG", false),
		BootstrapEmail:      strings.TrimSpace(os.Getenv("MCP_GATEWAY_BOOTSTRAP_EMAIL")),
		BootstrapPassword:   os.Getenv("MCP_GATEWAY_BOOTSTRAP_PASSWORD"),
		AllowedEmails:       parseCSVEnv("MCP_GATEWAY_ALLOWED_EMAILS"),
		AllowedEmailDomains: parseCSVEnv("MCP_GATEWAY_ALLOWED_EMAIL_DOMAINS"),
		Auth: AuthConfig{
			StorePath:              getEnvOrDefault("MCP_GATEWAY_AUTH_STORE_PATH", defaultAuthStorePath),
			AccessTokenTTL:         getDurationEnv("MCP_GATEWAY_ACCESS_TOKEN_TTL", defaultAccessTokenTTL),
			RefreshTokenTTL:        getDurationEnv("MCP_GATEWAY_REFRESH_TOKEN_TTL", defaultRefreshTokenTTL),
			AuthorizationCodeTTL:   getDurationEnv("MCP_GATEWAY_AUTHORIZATION_CODE_TTL", defaultAuthorizationTTL),
			SessionTTL:             getDurationEnv("MCP_GATEWAY_SESSION_TTL", defaultSessionTTL),
			AllowedRedirectOrigins: parseCSVEnv("MCP_GATEWAY_ALLOWED_REDIRECT_ORIGINS"),
		},
		DockerManagement: DockerManagementConfig{
			Enabled:         getBoolEnv("MCP_GATEWAY_DOCKER_MANAGEMENT_ENABLED", false),
			Host:            getEnvOrDefault("MCP_GATEWAY_DOCKER_HOST", defaultDockerHost),
			DefaultNetworks: parseCSVEnv("MCP_GATEWAY_DOCKER_NETWORKS"),
			RestartPolicy:   getEnvOrDefault("MCP_GATEWAY_DOCKER_RESTART_POLICY", "unless-stopped"),
		},
		BuildManagement: BuildManagementConfig{
			Enabled:              getBoolEnv("MCP_GATEWAY_BUILD_ENABLED", false),
			WorkDir:              getEnvOrDefault("MCP_GATEWAY_BUILD_WORK_DIR", defaultBuildWorkDir),
			MaxArtifactBytes:     int64(getIntEnv("MCP_GATEWAY_BUILD_MAX_ARTIFACT_MB", defaultBuildMaxArtifactMB)) << 20,
			AllowedDownloadHosts: parseCSVEnv("MCP_GATEWAY_BUILD_ALLOWED_DOWNLOAD_HOSTS"),
			AllowAnyDownloadHost: getBoolEnv("MCP_GATEWAY_BUILD_ALLOW_ANY_DOWNLOAD_HOST", false),
			DefaultBaseImage:     getEnvOrDefault("MCP_GATEWAY_BUILD_DEFAULT_BASE_IMAGE", "debian:bookworm-slim"),
			AllowedBaseImages:    parseCSVEnv("MCP_GATEWAY_BUILD_ALLOWED_BASE_IMAGES"),
		},
		StdioInstaller: StdioInstallerConfig{
			Enabled:              getBoolEnv("MCP_GATEWAY_STDIO_INSTALL_ENABLED", false),
			StoreDir:             getEnvOrDefault("MCP_GATEWAY_STDIO_STORE_DIR", defaultStdioStoreDir),
			MaxArtifactBytes:     int64(getIntEnv("MCP_GATEWAY_STDIO_MAX_ARTIFACT_MB", defaultBuildMaxArtifactMB)) << 20,
			AllowedDownloadHosts: parseCSVEnv("MCP_GATEWAY_STDIO_ALLOWED_DOWNLOAD_HOSTS"),
			AllowAnyDownloadHost: getBoolEnv("MCP_GATEWAY_STDIO_ALLOW_ANY_DOWNLOAD_HOST", false),
		},
		OpenAPIStoreDir: getEnvOrDefault("MCP_GATEWAY_OPENAPI_STORE_DIR", defaultOpenAPIStoreDir),
	}
	if len(cfg.BuildManagement.AllowedDownloadHosts) == 0 {
		cfg.BuildManagement.AllowedDownloadHosts = []string{
			"github.com",
			"objects.githubusercontent.com",
			"github-releases.githubusercontent.com",
			"release-assets.githubusercontent.com",
		}
	}
	if len(cfg.BuildManagement.AllowedBaseImages) == 0 {
		cfg.BuildManagement.AllowedBaseImages = []string{strings.ToLower(cfg.BuildManagement.DefaultBaseImage)}
	}
	cfg.BuildManagement.AllowedDownloadHosts = normalizeStringList(cfg.BuildManagement.AllowedDownloadHosts, true)
	cfg.BuildManagement.DefaultBaseImage = strings.ToLower(strings.TrimSpace(cfg.BuildManagement.DefaultBaseImage))
	cfg.BuildManagement.AllowedBaseImages = normalizeStringList(cfg.BuildManagement.AllowedBaseImages, true)
	if len(cfg.StdioInstaller.AllowedDownloadHosts) == 0 {
		cfg.StdioInstaller.AllowedDownloadHosts = append([]string(nil), cfg.BuildManagement.AllowedDownloadHosts...)
	}
	cfg.StdioInstaller.AllowedDownloadHosts = normalizeStringList(cfg.StdioInstaller.AllowedDownloadHosts, true)
	cfg.StdioInstaller.StoreDir = filepath.Clean(strings.TrimSpace(cfg.StdioInstaller.StoreDir))
	if !filepath.IsAbs(cfg.StdioInstaller.StoreDir) {
		return nil, fmt.Errorf("MCP_GATEWAY_STDIO_STORE_DIR must be an absolute path")
	}

	if (cfg.BootstrapEmail == "") != (cfg.BootstrapPassword == "") {
		return nil, fmt.Errorf("MCP_GATEWAY_BOOTSTRAP_EMAIL and MCP_GATEWAY_BOOTSTRAP_PASSWORD must either both be set or both be empty")
	}

	masterKey, err := parseMasterKey(strings.TrimSpace(os.Getenv("MCP_GATEWAY_AUTH_MASTER_KEY")))
	if err != nil {
		return nil, err
	}
	cfg.Auth.MasterKey = masterKey
	allowedRedirectOrigins, err := normalizeURLOrigins(cfg.Auth.AllowedRedirectOrigins)
	if err != nil {
		return nil, err
	}
	cfg.Auth.AllowedRedirectOrigins = allowedRedirectOrigins

	routes, err := LoadRoutesFile(cfg.RoutesPath)
	if err != nil {
		return nil, err
	}
	cfg.Routes = routes

	return cfg, nil
}

func (r Route) PublicMCPPath() string {
	return path.Join(r.NormalizedPathPrefix, "mcp")
}

func (r Route) ProtectedResourceMetadataPath() string {
	return "/.well-known/oauth-protected-resource" + r.PublicMCPPath()
}

func (r Route) PublicInfoPath() string {
	return r.NormalizedPathPrefix
}

func (r Route) PublicDocsPath() string {
	return path.Join(r.NormalizedPathPrefix, "docs")
}

func (r Route) ResourceURL(publicBaseURL string) string {
	return strings.TrimRight(publicBaseURL, "/") + r.PublicMCPPath()
}

func (r Route) ScopeList() []string {
	if len(r.ScopesSupported) == 0 {
		return []string{"mcp"}
	}
	return r.ScopesSupported
}

func (r Route) HeaderTemplates() map[string]string {
	if len(r.ForwardHeaders) != 0 {
		return r.ForwardHeaders
	}
	return map[string]string{
		defaultAuthenticatedUserID: "{user_id}",
		defaultAuthenticatedEmail:  "{email}",
	}
}

func LoadRoutesFile(routesPath string) ([]Route, error) {
	routesPayload, err := os.ReadFile(routesPath)
	if err != nil {
		if os.IsNotExist(err) {
			if err := SaveRoutesFile(routesPath, []Route{}); err != nil {
				return nil, fmt.Errorf("failed to initialize empty routes config %q: %w", routesPath, err)
			}
			routesPayload = []byte("routes: []\n")
		} else if os.IsPermission(err) {
			return nil, fmt.Errorf("failed to read routes config %q: permission denied; ensure the mounted config directory is readable and writable by the gateway container: %w", routesPath, err)
		} else {
			return nil, fmt.Errorf("failed to read routes config %q: %w", routesPath, err)
		}
	}

	return ParseRoutesPayload(routesPayload)
}

func SaveRoutesFile(routesPath string, routes []Route) error {
	payload, err := MarshalRoutesPayload(routes)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(routesPath), 0o755); err != nil {
		return fmt.Errorf("failed to create routes config directory: %w", err)
	}

	tempPath := routesPath + ".tmp"
	if err := os.WriteFile(tempPath, payload, 0o644); err != nil {
		return fmt.Errorf("failed to write routes config: %w", err)
	}
	if err := os.Rename(tempPath, routesPath); err != nil {
		return fmt.Errorf("failed to replace routes config: %w", err)
	}
	return nil
}

func ParseRoutesPayload(payload []byte) ([]Route, error) {
	var parsed routesFile
	if len(bytes.TrimSpace(payload)) != 0 {
		if err := yaml.Unmarshal(payload, &parsed); err != nil {
			return nil, fmt.Errorf("failed to parse routes config: %w", err)
		}
	}

	if parsed.Routes == nil {
		parsed.Routes = []Route{}
	}
	if err := ValidateRoutes(parsed.Routes); err != nil {
		return nil, err
	}
	return cloneRoutes(parsed.Routes), nil
}

func MarshalRoutesPayload(routes []Route) ([]byte, error) {
	cloned := cloneRoutes(routes)
	if err := ValidateRoutes(cloned); err != nil {
		return nil, err
	}

	payload, err := yaml.Marshal(routesFile{Routes: cloned})
	if err != nil {
		return nil, fmt.Errorf("failed to encode routes config: %w", err)
	}
	return payload, nil
}

func ValidateRoutes(routes []Route) error {
	seenIDs := make(map[string]struct{}, len(routes))
	seenPrefixes := make(map[string]struct{}, len(routes))
	for i := range routes {
		if err := NormalizeRoute(&routes[i]); err != nil {
			return err
		}
		if _, exists := seenIDs[routes[i].ID]; exists {
			return fmt.Errorf("duplicate route id %q", routes[i].ID)
		}
		if _, exists := seenPrefixes[routes[i].NormalizedPathPrefix]; exists {
			return fmt.Errorf("duplicate route path prefix %q", routes[i].NormalizedPathPrefix)
		}
		seenIDs[routes[i].ID] = struct{}{}
		seenPrefixes[routes[i].NormalizedPathPrefix] = struct{}{}
	}
	return nil
}

func NormalizeRoute(route *Route) error {
	return normalizeRoute(route)
}

func normalizeRoute(route *Route) error {
	route.ID = strings.TrimSpace(route.ID)
	if route.ID == "" {
		return fmt.Errorf("route id is required")
	}

	route.DisplayName = strings.TrimSpace(route.DisplayName)
	if route.DisplayName == "" {
		route.DisplayName = route.ID
	}

	route.Transport = strings.ToLower(strings.TrimSpace(route.Transport))
	if route.Transport == "" {
		if route.Stdio != nil {
			route.Transport = "stdio"
		} else if route.OpenAPI != nil {
			route.Transport = "openapi"
		} else {
			route.Transport = "http"
		}
	}
	if route.Transport != "http" && route.Transport != "stdio" && route.Transport != "openapi" {
		return fmt.Errorf("route %q transport must be http, stdio or openapi", route.ID)
	}

	pathPrefix := strings.TrimSpace(route.PathPrefix)
	if pathPrefix == "" {
		pathPrefix = "/" + route.ID
	}
	if !strings.HasPrefix(pathPrefix, "/") {
		pathPrefix = "/" + pathPrefix
	}
	if len(pathPrefix) > 1 {
		pathPrefix = strings.TrimRight(pathPrefix, "/")
	}
	if pathPrefix == "/" {
		return fmt.Errorf("route %q path prefix must not be /", route.ID)
	}
	if err := validateReservedPathPrefix(pathPrefix); err != nil {
		return fmt.Errorf("route %q path prefix is invalid: %w", route.ID, err)
	}
	route.NormalizedPathPrefix = pathPrefix

	upstreamPath := strings.TrimSpace(route.UpstreamMCPPath)
	if upstreamPath == "" {
		upstreamPath = "/mcp"
	}
	if !strings.HasPrefix(upstreamPath, "/") {
		upstreamPath = "/" + upstreamPath
	}
	route.NormalizedUpstreamPath = path.Clean(upstreamPath)
	if route.NormalizedUpstreamPath == "." {
		route.NormalizedUpstreamPath = "/"
	}

	switch route.Transport {
	case "http":
		upstreamURL, err := url.Parse(strings.TrimSpace(route.Upstream))
		if err != nil || upstreamURL.Scheme == "" || upstreamURL.Host == "" {
			return fmt.Errorf("route %q has invalid upstream URL", route.ID)
		}
		route.Upstream = upstreamURL.String()
		route.Stdio = nil
		route.OpenAPI = nil
	case "stdio":
		route.Upstream = strings.TrimSpace(route.Upstream)
		if route.Stdio == nil {
			return fmt.Errorf("route %q stdio config is required", route.ID)
		}
		stdio, err := normalizeRouteStdio(*route.Stdio)
		if err != nil {
			return fmt.Errorf("route %q stdio config is invalid: %w", route.ID, err)
		}
		route.Stdio = &stdio
		route.OpenAPI = nil
	case "openapi":
		route.Upstream = strings.TrimSpace(route.Upstream)
		route.Stdio = nil
		if route.OpenAPI == nil {
			return fmt.Errorf("route %q openapi config is required", route.ID)
		}
		openapi, err := normalizeRouteOpenAPI(*route.OpenAPI)
		if err != nil {
			return fmt.Errorf("route %q openapi config is invalid: %w", route.ID, err)
		}
		route.OpenAPI = &openapi
		if route.Upstream == "" {
			route.Upstream = openapi.BaseURL
		}
	}

	if route.ResourceDocumentation != "" {
		docURL, err := url.Parse(strings.TrimSpace(route.ResourceDocumentation))
		if err != nil || docURL.Scheme == "" || docURL.Host == "" {
			return fmt.Errorf("route %q has invalid resource_documentation URL", route.ID)
		}
		route.ResourceDocumentation = docURL.String()
	}

	forwardHeaders := make(map[string]string, len(route.ForwardHeaders))
	for key, value := range route.ForwardHeaders {
		headerName := strings.TrimSpace(key)
		if headerName == "" {
			return fmt.Errorf("route %q has an empty forward header name", route.ID)
		}
		forwardHeaders[headerName] = strings.TrimSpace(value)
	}
	route.ForwardHeaders = forwardHeaders

	upstreamEnvironment := make(map[string]string, len(route.UpstreamEnvironment))
	for key, value := range route.UpstreamEnvironment {
		envName := strings.TrimSpace(key)
		if envName == "" {
			return fmt.Errorf("route %q has an empty upstream environment key", route.ID)
		}
		upstreamEnvironment[envName] = strings.TrimSpace(value)
	}
	route.UpstreamEnvironment = upstreamEnvironment
	route.Access = normalizeRouteAccess(route.Access)
	if route.Access.Visibility != "public" && route.Access.Visibility != "private" {
		return fmt.Errorf("route %q access visibility must be public or private", route.ID)
	}
	switch route.Access.Mode {
	case "public", "restricted", "admin":
	default:
		return fmt.Errorf("route %q access mode must be public, restricted or admin", route.ID)
	}
	if route.Deployment != nil {
		deployment, err := normalizeRouteDeployment(*route.Deployment)
		if err != nil {
			return fmt.Errorf("route %q deployment is invalid: %w", route.ID, err)
		}
		route.Deployment = &deployment
	}
	route.Notes = strings.TrimSpace(route.Notes)

	return nil
}

func normalizeRouteAccess(access RouteAccess) RouteAccess {
	visibility := strings.ToLower(strings.TrimSpace(access.Visibility))
	if visibility == "" {
		visibility = "public"
	}
	mode := strings.ToLower(strings.TrimSpace(access.Mode))
	if mode == "" {
		mode = "public"
	}

	return RouteAccess{
		Visibility:    visibility,
		Mode:          mode,
		AllowedUsers:  normalizeStringList(access.AllowedUsers, true),
		AllowedGroups: normalizeStringList(access.AllowedGroups, false),
		DeniedUsers:   normalizeStringList(access.DeniedUsers, true),
		DeniedGroups:  normalizeStringList(access.DeniedGroups, false),
	}
}

func (a RouteAccess) IsPrivate() bool {
	return strings.EqualFold(strings.TrimSpace(a.Visibility), "private")
}

func (a RouteAccess) EffectiveMode() string {
	mode := strings.ToLower(strings.TrimSpace(a.Mode))
	if mode == "" {
		return "public"
	}
	return mode
}

func normalizeRouteDeployment(deployment RouteDeployment) (RouteDeployment, error) {
	deployment.Type = strings.ToLower(strings.TrimSpace(deployment.Type))
	if deployment.Type == "" {
		deployment.Type = "docker"
	}
	if deployment.Type != "docker" {
		return RouteDeployment{}, fmt.Errorf("type must be docker")
	}
	deployment.Image = strings.TrimSpace(deployment.Image)
	deployment.ContainerName = strings.TrimSpace(deployment.ContainerName)
	deployment.Networks = normalizeStringList(deployment.Networks, false)
	deployment.RestartPolicy = strings.TrimSpace(deployment.RestartPolicy)
	if deployment.Managed {
		if deployment.Image == "" {
			return RouteDeployment{}, fmt.Errorf("image is required")
		}
		if deployment.ContainerName == "" {
			return RouteDeployment{}, fmt.Errorf("container_name is required")
		}
		if deployment.InternalPort <= 0 || deployment.InternalPort > 65535 {
			return RouteDeployment{}, fmt.Errorf("internal_port must be between 1 and 65535")
		}
	}
	return deployment, nil
}

func normalizeRouteStdio(stdio RouteStdio) (RouteStdio, error) {
	stdio.Command = strings.TrimSpace(stdio.Command)
	if stdio.Command == "" {
		return RouteStdio{}, fmt.Errorf("command is required")
	}
	stdio.WorkingDir = strings.TrimSpace(stdio.WorkingDir)
	if stdio.WorkingDir != "" && !filepath.IsAbs(stdio.WorkingDir) {
		return RouteStdio{}, fmt.Errorf("working_dir must be an absolute path")
	}

	args := make([]string, 0, len(stdio.Args))
	for _, raw := range stdio.Args {
		arg := strings.TrimSpace(raw)
		if arg != "" {
			args = append(args, arg)
		}
	}
	stdio.Args = args

	env := make(map[string]string, len(stdio.Env))
	for key, value := range stdio.Env {
		envName := strings.TrimSpace(key)
		if envName == "" {
			return RouteStdio{}, fmt.Errorf("env contains an empty key")
		}
		env[envName] = strings.TrimSpace(value)
	}
	if len(env) == 0 {
		env = nil
	}
	stdio.Env = env
	refs := make(map[string]string, len(stdio.EnvSecretRefs))
	for key, value := range stdio.EnvSecretRefs {
		envName := strings.TrimSpace(key)
		if envName == "" {
			return RouteStdio{}, fmt.Errorf("env_secret_refs contains an empty key")
		}
		ref := strings.TrimSpace(value)
		if ref == "" {
			return RouteStdio{}, fmt.Errorf("env_secret_refs contains an empty ref for %q", envName)
		}
		refs[envName] = ref
	}
	if len(refs) == 0 {
		refs = nil
	}
	stdio.EnvSecretRefs = refs
	return stdio, nil
}

func normalizeRouteOpenAPI(openapi RouteOpenAPI) (RouteOpenAPI, error) {
	openapi.SpecPath = strings.TrimSpace(openapi.SpecPath)
	openapi.SpecURL = strings.TrimSpace(openapi.SpecURL)
	if openapi.SpecPath == "" && openapi.SpecURL == "" {
		return RouteOpenAPI{}, fmt.Errorf("spec_path or spec_url is required")
	}
	if openapi.SpecPath != "" && !filepath.IsAbs(openapi.SpecPath) {
		return RouteOpenAPI{}, fmt.Errorf("spec_path must be an absolute path")
	}
	if openapi.SpecURL != "" {
		specURL, err := url.Parse(openapi.SpecURL)
		if err != nil || specURL.Scheme == "" || specURL.Host == "" {
			return RouteOpenAPI{}, fmt.Errorf("spec_url must be an absolute URL")
		}
		if specURL.Scheme != "https" && specURL.Scheme != "http" {
			return RouteOpenAPI{}, fmt.Errorf("spec_url must use http or https")
		}
		openapi.SpecURL = specURL.String()
	}

	baseURL, err := url.Parse(strings.TrimSpace(openapi.BaseURL))
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return RouteOpenAPI{}, fmt.Errorf("base_url must be an absolute URL")
	}
	if baseURL.Scheme != "https" && baseURL.Scheme != "http" {
		return RouteOpenAPI{}, fmt.Errorf("base_url must use http or https")
	}
	baseURL.RawQuery = ""
	baseURL.Fragment = ""
	openapi.BaseURL = strings.TrimRight(baseURL.String(), "/")

	headers := make(map[string]string, len(openapi.Headers))
	for key, value := range openapi.Headers {
		headerName := strings.TrimSpace(key)
		if headerName == "" {
			return RouteOpenAPI{}, fmt.Errorf("headers contains an empty key")
		}
		headers[headerName] = strings.TrimSpace(value)
	}
	if len(headers) == 0 {
		headers = nil
	}
	openapi.Headers = headers
	if openapi.TimeoutSeconds <= 0 {
		openapi.TimeoutSeconds = 30
	}
	if openapi.TimeoutSeconds > 300 {
		return RouteOpenAPI{}, fmt.Errorf("timeout_seconds must be <= 300")
	}
	return openapi, nil
}

func normalizeStringList(values []string, lower bool) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if lower {
			value = strings.ToLower(value)
		}
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneRoutes(routes []Route) []Route {
	if len(routes) == 0 {
		return []Route{}
	}

	cloned := make([]Route, len(routes))
	for i := range routes {
		cloned[i] = routes[i]
		if routes[i].ScopesSupported != nil {
			cloned[i].ScopesSupported = append([]string(nil), routes[i].ScopesSupported...)
		}
		if routes[i].ForwardHeaders != nil {
			cloned[i].ForwardHeaders = make(map[string]string, len(routes[i].ForwardHeaders))
			for key, value := range routes[i].ForwardHeaders {
				cloned[i].ForwardHeaders[key] = value
			}
		}
		if routes[i].UpstreamEnvironment != nil {
			cloned[i].UpstreamEnvironment = make(map[string]string, len(routes[i].UpstreamEnvironment))
			for key, value := range routes[i].UpstreamEnvironment {
				cloned[i].UpstreamEnvironment[key] = value
			}
		}
		cloned[i].Access = cloneRouteAccess(routes[i].Access)
		if routes[i].Deployment != nil {
			deployment := cloneRouteDeployment(*routes[i].Deployment)
			cloned[i].Deployment = &deployment
		}
		if routes[i].Stdio != nil {
			stdio := cloneRouteStdio(*routes[i].Stdio)
			cloned[i].Stdio = &stdio
		}
		if routes[i].OpenAPI != nil {
			openapi := cloneRouteOpenAPI(*routes[i].OpenAPI)
			cloned[i].OpenAPI = &openapi
		}
	}
	return cloned
}

func cloneRouteAccess(access RouteAccess) RouteAccess {
	return RouteAccess{
		Visibility:    access.Visibility,
		Mode:          access.Mode,
		AllowedUsers:  append([]string(nil), access.AllowedUsers...),
		AllowedGroups: append([]string(nil), access.AllowedGroups...),
		DeniedUsers:   append([]string(nil), access.DeniedUsers...),
		DeniedGroups:  append([]string(nil), access.DeniedGroups...),
	}
}

func cloneRouteDeployment(deployment RouteDeployment) RouteDeployment {
	return RouteDeployment{
		Type:          deployment.Type,
		Managed:       deployment.Managed,
		Image:         deployment.Image,
		ContainerName: deployment.ContainerName,
		InternalPort:  deployment.InternalPort,
		Networks:      append([]string(nil), deployment.Networks...),
		RestartPolicy: deployment.RestartPolicy,
	}
}

func cloneRouteStdio(stdio RouteStdio) RouteStdio {
	cloned := RouteStdio{
		Command:    stdio.Command,
		Args:       append([]string(nil), stdio.Args...),
		WorkingDir: stdio.WorkingDir,
	}
	if stdio.Env != nil {
		cloned.Env = make(map[string]string, len(stdio.Env))
		for key, value := range stdio.Env {
			cloned.Env[key] = value
		}
	}
	if stdio.EnvSecretRefs != nil {
		cloned.EnvSecretRefs = make(map[string]string, len(stdio.EnvSecretRefs))
		for key, value := range stdio.EnvSecretRefs {
			cloned.EnvSecretRefs[key] = value
		}
	}
	return cloned
}

func cloneRouteOpenAPI(openapi RouteOpenAPI) RouteOpenAPI {
	cloned := RouteOpenAPI{
		SpecPath:       openapi.SpecPath,
		SpecURL:        openapi.SpecURL,
		BaseURL:        openapi.BaseURL,
		TimeoutSeconds: openapi.TimeoutSeconds,
	}
	if openapi.Headers != nil {
		cloned.Headers = make(map[string]string, len(openapi.Headers))
		for key, value := range openapi.Headers {
			cloned.Headers[key] = value
		}
	}
	return cloned
}

func parseMasterKey(raw string) ([]byte, error) {
	if raw == "" {
		return nil, fmt.Errorf("MCP_GATEWAY_AUTH_MASTER_KEY must be set")
	}

	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}

	return nil, fmt.Errorf("MCP_GATEWAY_AUTH_MASTER_KEY must decode to exactly 32 bytes (base64, base64url, or hex)")
}

func validateReservedPathPrefix(prefix string) error {
	reserved := []string{
		"/.well-known",
		"/admin",
		"/account",
		"/authorize",
		"/docs",
		"/healthz",
		"/register",
		"/token",
	}
	for _, candidate := range reserved {
		if prefix == candidate || strings.HasPrefix(prefix, candidate+"/") {
			return fmt.Errorf("%q conflicts with a reserved gateway path", prefix)
		}
	}
	return nil
}

func normalizePublicBaseURL(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("MCP_GATEWAY_PUBLIC_BASE_URL must be set")
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("MCP_GATEWAY_PUBLIC_BASE_URL is invalid: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("MCP_GATEWAY_PUBLIC_BASE_URL must include scheme and host")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("MCP_GATEWAY_PUBLIC_BASE_URL must use http or https")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("MCP_GATEWAY_PUBLIC_BASE_URL must not include a path")
	}

	return strings.TrimRight(value, "/"), nil
}

func normalizeURLOrigins(values []string) ([]string, error) {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil {
			return nil, fmt.Errorf("redirect origin %q is invalid: %w", value, err)
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("redirect origin %q must include scheme and host", value)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return nil, fmt.Errorf("redirect origin %q must use http or https", value)
		}
		parsed.Path = ""
		parsed.RawQuery = ""
		parsed.Fragment = ""
		origin := strings.TrimRight(parsed.String(), "/")
		if seen[origin] {
			continue
		}
		seen[origin] = true
		out = append(out, origin)
	}
	return out, nil
}

func getEnvOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func getDurationEnv(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 {
		return fallback
	}

	return parsed
}

func getBoolEnv(key string, fallback bool) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if raw == "" {
		return fallback
	}
	return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
}

func getIntEnv(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	var parsed int
	if _, err := fmt.Sscanf(raw, "%d", &parsed); err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func parseCSVEnv(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value != "" {
			values = append(values, strings.ToLower(value))
		}
	}

	return values
}
