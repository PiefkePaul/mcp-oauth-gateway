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
	BootstrapEmail      string
	BootstrapPassword   string
	AllowedEmails       []string
	AllowedEmailDomains []string
	Auth                AuthConfig
	Routes              []Route
}

type AuthConfig struct {
	StorePath            string
	MasterKey            []byte
	AccessTokenTTL       time.Duration
	RefreshTokenTTL      time.Duration
	AuthorizationCodeTTL time.Duration
	SessionTTL           time.Duration
}

type Route struct {
	ID                     string            `yaml:"id"`
	DisplayName            string            `yaml:"display_name"`
	PathPrefix             string            `yaml:"path_prefix"`
	Upstream               string            `yaml:"upstream"`
	UpstreamMCPPath        string            `yaml:"upstream_mcp_path"`
	ScopesSupported        []string          `yaml:"scopes_supported"`
	PassAuthorization      bool              `yaml:"pass_authorization_header"`
	ForwardHeaders         map[string]string `yaml:"forward_headers"`
	UpstreamEnvironment    map[string]string `yaml:"upstream_environment"`
	ResourceDocumentation  string            `yaml:"resource_documentation"`
	Notes                  string            `yaml:"notes"`
	NormalizedPathPrefix   string            `yaml:"-"`
	NormalizedUpstreamPath string            `yaml:"-"`
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
		BootstrapEmail:      strings.TrimSpace(os.Getenv("MCP_GATEWAY_BOOTSTRAP_EMAIL")),
		BootstrapPassword:   os.Getenv("MCP_GATEWAY_BOOTSTRAP_PASSWORD"),
		AllowedEmails:       parseCSVEnv("MCP_GATEWAY_ALLOWED_EMAILS"),
		AllowedEmailDomains: parseCSVEnv("MCP_GATEWAY_ALLOWED_EMAIL_DOMAINS"),
		Auth: AuthConfig{
			StorePath:            getEnvOrDefault("MCP_GATEWAY_AUTH_STORE_PATH", defaultAuthStorePath),
			AccessTokenTTL:       getDurationEnv("MCP_GATEWAY_ACCESS_TOKEN_TTL", defaultAccessTokenTTL),
			RefreshTokenTTL:      getDurationEnv("MCP_GATEWAY_REFRESH_TOKEN_TTL", defaultRefreshTokenTTL),
			AuthorizationCodeTTL: getDurationEnv("MCP_GATEWAY_AUTHORIZATION_CODE_TTL", defaultAuthorizationTTL),
			SessionTTL:           getDurationEnv("MCP_GATEWAY_SESSION_TTL", defaultSessionTTL),
		},
	}

	if (cfg.BootstrapEmail == "") != (cfg.BootstrapPassword == "") {
		return nil, fmt.Errorf("MCP_GATEWAY_BOOTSTRAP_EMAIL and MCP_GATEWAY_BOOTSTRAP_PASSWORD must either both be set or both be empty")
	}

	masterKey, err := parseMasterKey(strings.TrimSpace(os.Getenv("MCP_GATEWAY_AUTH_MASTER_KEY")))
	if err != nil {
		return nil, err
	}
	cfg.Auth.MasterKey = masterKey

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

	var parsed routesFile
	if len(bytes.TrimSpace(routesPayload)) != 0 {
		if err := yaml.Unmarshal(routesPayload, &parsed); err != nil {
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

func SaveRoutesFile(routesPath string, routes []Route) error {
	cloned := cloneRoutes(routes)
	if err := ValidateRoutes(cloned); err != nil {
		return err
	}

	payload, err := yaml.Marshal(routesFile{Routes: cloned})
	if err != nil {
		return fmt.Errorf("failed to encode routes config: %w", err)
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

	upstreamURL, err := url.Parse(strings.TrimSpace(route.Upstream))
	if err != nil || upstreamURL.Scheme == "" || upstreamURL.Host == "" {
		return fmt.Errorf("route %q has invalid upstream URL", route.ID)
	}

	route.Upstream = upstreamURL.String()

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
	route.Notes = strings.TrimSpace(route.Notes)

	return nil
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
