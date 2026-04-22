package gateway

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

type dashboardData struct {
	Title               string
	AdminEmail          string
	Notice              string
	Error               string
	CSRFToken           string
	PublicBaseURL       string
	RoutesPath          string
	SelfSignupEnabled   bool
	ActiveTab           string
	DockerEnabled       bool
	DockerHost          string
	DockerNetworks      string
	DockerError         string
	BuildEnabled        bool
	BuildMaxMB          int64
	BuildHosts          string
	BuildBaseImages     string
	StdioInstallEnabled bool
	StdioInstallMaxMB   int64
	StdioInstallStore   string
	Routes              []dashboardRouteView
	Deployments         []dashboardDeploymentView
	Users               []dashboardUserView
	Groups              []dashboardGroupView
	SelectedUser        *dashboardUserDetailView
	SelectedRoute       routeFormData
	DeploymentForm      deploymentFormData
	BuildForm           artifactBuildFormData
	StdioInstallForm    stdioInstallFormData
}

type dashboardRouteView struct {
	ID                       string
	DisplayName              string
	Transport                string
	PathPrefix               string
	PublicMCPURL             string
	ProtectedMetadataURL     string
	Upstream                 string
	UpstreamMCPPath          string
	MCPHTTPSessionMode       string
	AccessVisibility         string
	AccessMode               string
	PassAuthorization        bool
	ForwardHeadersCount      int
	UpstreamEnvironmentCount int
}

type dashboardDeploymentView struct {
	RouteID       string
	DisplayName   string
	Transport     string
	PublicMCPURL  string
	Image         string
	ContainerName string
	InternalPort  int
	Networks      string
	Upstream      string
	Command       string
	State         string
	Status        string
	Exists        bool
	Inspectable   bool
}

type dashboardUserView struct {
	ID          string
	Email       string
	IsAdmin     bool
	GroupIDs    []string
	Groups      string
	DeviceCount int
	CreatedAt   string
	UpdatedAt   string
}

type dashboardUserDetailView struct {
	ID        string
	Email     string
	IsAdmin   bool
	GroupIDs  []string
	Groups    string
	CreatedAt string
	UpdatedAt string
	Devices   []dashboardUserDeviceView
}

type dashboardUserDeviceView struct {
	ID               string
	ClientID         string
	ClientName       string
	Resource         string
	Scope            string
	RedirectURIs     string
	TokenCount       int
	CreatedAt        string
	LastUsedAt       string
	RefreshExpiresAt string
}

type dashboardGroupView struct {
	ID          string
	Name        string
	MemberCount int
	CreatedAt   string
	UpdatedAt   string
}

type deploymentFormData struct {
	Transport             string
	ID                    string
	DisplayName           string
	PathPrefix            string
	Image                 string
	ContainerName         string
	InternalPort          string
	UpstreamMCPPath       string
	ScopesSupported       string
	Networks              string
	RestartPolicy         string
	ResourceDocumentation string
	Environment           string
	StdioCommand          string
	StdioArgs             string
	StdioEnv              string
	StdioWorkingDir       string
	Notes                 string
}

type artifactBuildFormData struct {
	SourceKind     string
	ImageTag       string
	BaseImage      string
	InternalPort   string
	DownloadURL    string
	SHA256         string
	ExtractMode    string
	ArtifactPath   string
	EntrypointArgs string
}

type stdioInstallFormData struct {
	SourceKind      string
	ID              string
	DisplayName     string
	PathPrefix      string
	ScopesSupported string
	DownloadURL     string
	GitHubRepo      string
	GitHubVersion   string
	AssetPattern    string
	SHA256          string
	ExtractMode     string
	ExecutablePath  string
	Args            string
	ExtraFolders    []string
	EnvNames        []string
	EnvValues       []string
}

type routeFormData struct {
	OriginalID            string
	ID                    string
	DisplayName           string
	Transport             string
	PathPrefix            string
	Upstream              string
	UpstreamMCPPath       string
	ScopesSupported       string
	PassAuthorization     bool
	ResourceDocumentation string
	MCPHTTPSessionMode    string
	AccessVisibility      string
	AccessMode            string
	AllowedUsers          []string
	AllowedGroups         []string
	DeniedUsers           []string
	DeniedGroups          []string
	ForwardHeaders        string
	UpstreamEnvironment   string
	StdioCommand          string
	StdioArgs             string
	StdioEnv              string
	StdioWorkingDir       string
	OpenAPISpecPath       string
	OpenAPISpecURL        string
	OpenAPIBaseURL        string
	OpenAPIHeaders        string
	OpenAPITimeoutSeconds string
	Notes                 string
}

func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}

	selected := newEmptyRouteFormData()
	if routeID := strings.TrimSpace(r.URL.Query().Get("route")); routeID != "" {
		if route, found := s.routeByID(routeID); found {
			selected = newRouteFormData(route, routeID)
		}
	}

	s.renderAdminDashboard(w, r, identity, selected, strings.TrimSpace(r.URL.Query().Get("notice")), strings.TrimSpace(r.URL.Query().Get("error")), http.StatusOK)
}

func (s *Server) handleAdminRouteSave(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(maxOpenAPISpecBytes + (1 << 20)); err != nil {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	formData, route, err := parseRouteForm(r)
	if err != nil {
		s.renderAdminDashboard(w, r, identity, formData, "", err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(route.ID) == "" {
		if formData.OriginalID != "" {
			route.ID = formData.OriginalID
		} else {
			route.ID = s.nextRouteID(route.DisplayName, route.PathPrefix, "")
		}
		formData.ID = route.ID
	}
	if route.Transport == "openapi" {
		specPath, err := s.storeOpenAPISpecUpload(r, route.ID)
		if err != nil {
			s.renderAdminDashboard(w, r, identity, formData, "", err.Error(), http.StatusBadRequest)
			return
		}
		if specPath != "" {
			route.OpenAPI.SpecPath = specPath
			route.OpenAPI.SpecURL = ""
			formData.OpenAPISpecPath = specPath
			formData.OpenAPISpecURL = ""
		}
	}

	if err := s.upsertRoute(formData.OriginalID, route); err != nil {
		s.renderAdminDashboard(w, r, identity, formData, "", err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, adminRedirectURL(route.ID, "Route saved successfully", ""), http.StatusFound)
}

func (s *Server) storeOpenAPISpecUpload(r *http.Request, routeID string) (string, error) {
	file, header, err := r.FormFile("openapi_spec_file")
	if err != nil {
		return "", nil
	}
	defer file.Close()
	if header == nil || strings.TrimSpace(header.Filename) == "" {
		return "", nil
	}

	payload, err := readLimited(file, maxOpenAPISpecBytes)
	if err != nil {
		return "", fmt.Errorf("read OpenAPI spec upload: %w", err)
	}
	if _, err := parseOpenAPIOperations(payload); err != nil {
		return "", fmt.Errorf("uploaded OpenAPI spec is invalid: %w", err)
	}
	if err := os.MkdirAll(s.cfg.OpenAPIStoreDir, 0o750); err != nil {
		return "", fmt.Errorf("create OpenAPI store directory: %w", err)
	}
	filename := slugify(defaultIfEmpty(routeID, "openapi")) + ".yaml"
	targetPath := filepath.Join(s.cfg.OpenAPIStoreDir, filename)
	tempPath := targetPath + ".tmp"
	if err := os.WriteFile(tempPath, payload, 0o640); err != nil {
		return "", fmt.Errorf("write OpenAPI spec: %w", err)
	}
	if err := os.Rename(tempPath, targetPath); err != nil {
		return "", fmt.Errorf("store OpenAPI spec: %w", err)
	}
	return targetPath, nil
}

func (s *Server) handleAdminRouteDelete(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	routeID := strings.TrimSpace(r.FormValue("route_id"))
	if routeID == "" {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", "route_id is required", http.StatusBadRequest)
		return
	}
	route, routeFound := s.routeByID(routeID)
	if err := s.deleteRoute(routeID); err != nil {
		form := newEmptyRouteFormData()
		form.OriginalID = routeID
		form.ID = routeID
		if route, found := s.routeByID(routeID); found {
			form = newRouteFormData(route, routeID)
		}
		s.renderAdminDashboard(w, r, identity, form, "", err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.authManager.DeleteRouteSecrets(routeID); err != nil {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}
	if routeFound {
		if err := s.removeManagedStdioInstall(route); err != nil {
			s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
			return
		}
	}

	http.Redirect(w, r, adminRedirectURL("", "Route deleted successfully", ""), http.StatusFound)
}

func (s *Server) handleAdminUserCreate(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	_, err := s.authManager.CreateUser(strings.TrimSpace(r.FormValue("email")), r.FormValue("password"), formCheckbox(r, "is_admin"))
	if err != nil {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, adminRedirectURLWithTab("users", "", "User created successfully", ""), http.StatusFound)
}

func (s *Server) handleAdminUserPassword(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	if err := s.authManager.SetUserPassword(strings.TrimSpace(r.FormValue("user_id")), r.FormValue("password")); err != nil {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, adminUserRedirectURL(strings.TrimSpace(r.FormValue("user_id")), "User password updated", ""), http.StatusFound)
}

func (s *Server) handleAdminUserDelete(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	if err := s.authManager.DeleteUser(strings.TrimSpace(r.FormValue("user_id"))); err != nil {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, adminRedirectURLWithTab("users", "", "User deleted successfully", ""), http.StatusFound)
}

func (s *Server) handleAdminUserAdmin(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	targetAdmin := formCheckbox(r, "is_admin")
	if err := s.authManager.SetUserAdmin(strings.TrimSpace(r.FormValue("user_id")), targetAdmin); err != nil {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}

	label := "User role updated"
	http.Redirect(w, r, adminUserRedirectURL(strings.TrimSpace(r.FormValue("user_id")), label, ""), http.StatusFound)
}

func (s *Server) handleAdminUserGroups(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	if err := s.authManager.SetUserGroups(strings.TrimSpace(r.FormValue("user_id")), r.Form["group_ids"]); err != nil {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, adminUserRedirectURL(strings.TrimSpace(r.FormValue("user_id")), "User groups updated", ""), http.StatusFound)
}

func (s *Server) handleAdminUserDeviceDelete(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	userID := strings.TrimSpace(r.FormValue("user_id"))
	if err := s.authManager.RevokeUserDevice(userID, r.FormValue("device_id")); err != nil {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, adminUserRedirectURL(userID, "Device access revoked", ""), http.StatusFound)
}

func (s *Server) handleAdminGroupCreate(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	if _, err := s.authManager.CreateGroup(strings.TrimSpace(r.FormValue("name"))); err != nil {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, adminRedirectURLWithTab("users", "", "Group created successfully", ""), http.StatusFound)
}

func (s *Server) handleAdminGroupDelete(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	if err := s.authManager.DeleteGroup(strings.TrimSpace(r.FormValue("group_id"))); err != nil {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, adminRedirectURLWithTab("users", "", "Group deleted successfully", ""), http.StatusFound)
}

func (s *Server) handleAdminRoutesExport(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if !allowsReadMethod(r.Method) {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}

	routes := s.routesSnapshot()
	if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("redacted")), "true") {
		routes = redactRoutes(routes)
	}
	payload, err := config.MarshalRoutesPayload(routes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="routes.yaml"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func (s *Server) handleAdminRoutesImport(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	payload := []byte(strings.TrimSpace(r.FormValue("routes_yaml")))
	if file, _, err := r.FormFile("routes_file"); err == nil {
		defer file.Close()
		filePayload, readErr := io.ReadAll(io.LimitReader(file, 2<<20))
		if readErr != nil {
			s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", readErr.Error(), http.StatusBadRequest)
			return
		}
		if len(strings.TrimSpace(string(filePayload))) != 0 {
			payload = filePayload
		}
	}
	if len(strings.TrimSpace(string(payload))) == 0 {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", "routes YAML is required", http.StatusBadRequest)
		return
	}

	routes, err := config.ParseRoutesPayload(payload)
	if err != nil {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.replacePersistedRoutes(routes); err != nil {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, adminRedirectURL("", "Routes imported successfully", ""), http.StatusFound)
}

func (s *Server) handleAdminDeploymentCreate(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}
	formData, route, spec, err := s.parseDeploymentForm(r)
	if err != nil {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.validateUpsertRoute("", route); err != nil {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}

	if spec != nil {
		if s.dockerManager == nil {
			s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", "Docker management is disabled", http.StatusBadRequest)
			return
		}
		if err := s.dockerManager.CreateAndStart(r.Context(), *spec); err != nil {
			formData.Environment = normalizeMultiline(r.FormValue("environment"))
			s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
			return
		}
	}
	if err := s.upsertRoute("", route); err != nil {
		if spec != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = s.dockerManager.Remove(rollbackCtx, spec.ContainerName)
		}
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, adminRedirectURLWithTab("deployments", route.ID, "Deployment created successfully", ""), http.StatusFound)
}

func (s *Server) handleAdminDeploymentStart(w http.ResponseWriter, r *http.Request) {
	s.handleAdminDeploymentAction(w, r, "start")
}

func (s *Server) handleAdminDeploymentStop(w http.ResponseWriter, r *http.Request) {
	s.handleAdminDeploymentAction(w, r, "stop")
}

func (s *Server) handleAdminDeploymentRemove(w http.ResponseWriter, r *http.Request) {
	s.handleAdminDeploymentAction(w, r, "remove")
}

func (s *Server) handleAdminArtifactBuild(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(s.cfg.BuildManagement.MaxArtifactBytes + (4 << 20)); err != nil {
		http.Error(w, "invalid multipart form", http.StatusBadRequest)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	formData := artifactBuildFormData{
		SourceKind:     defaultIfEmpty(strings.TrimSpace(r.FormValue("source_kind")), artifactSourceURL),
		ImageTag:       strings.TrimSpace(r.FormValue("image_tag")),
		BaseImage:      defaultIfEmpty(strings.TrimSpace(r.FormValue("base_image")), s.cfg.BuildManagement.DefaultBaseImage),
		InternalPort:   defaultIfEmpty(strings.TrimSpace(r.FormValue("internal_port")), "8080"),
		DownloadURL:    strings.TrimSpace(r.FormValue("download_url")),
		SHA256:         strings.TrimSpace(r.FormValue("sha256")),
		ExtractMode:    defaultIfEmpty(strings.TrimSpace(r.FormValue("extract_mode")), extractNone),
		ArtifactPath:   strings.TrimSpace(r.FormValue("artifact_path")),
		EntrypointArgs: normalizeMultiline(r.FormValue("entrypoint_args")),
	}

	internalPort, err := strconv.Atoi(formData.InternalPort)
	if err != nil {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", "internal port must be numeric", http.StatusBadRequest)
		return
	}
	buildReq := artifactBuildRequest{
		SourceKind:     formData.SourceKind,
		DownloadURL:    formData.DownloadURL,
		SHA256:         formData.SHA256,
		ExtractMode:    formData.ExtractMode,
		ArtifactPath:   formData.ArtifactPath,
		ImageTag:       formData.ImageTag,
		BaseImage:      formData.BaseImage,
		EntrypointArgs: parseFlexibleList(formData.EntrypointArgs),
		InternalPort:   internalPort,
	}
	if formData.SourceKind == artifactSourceUpload {
		file, header, err := r.FormFile("artifact_file")
		if err != nil {
			s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", "artifact file is required", http.StatusBadRequest)
			return
		}
		defer file.Close()
		buildReq.UploadName = header.Filename
		buildReq.UploadReader = file
	}

	result, err := s.buildManager.Build(r.Context(), buildReq)
	if err != nil {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}
	notice := fmt.Sprintf("Image %s built from verified artifact sha256:%s", result.ImageTag, result.SHA256)
	http.Redirect(w, r, adminRedirectURLWithTab("deployments", "", notice, ""), http.StatusFound)
}

func (s *Server) handleAdminStdioInstall(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(s.cfg.StdioInstaller.MaxArtifactBytes + (4 << 20)); err != nil {
		http.Error(w, "invalid multipart form", http.StatusBadRequest)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	formData := stdioInstallFormData{
		SourceKind:      defaultIfEmpty(strings.TrimSpace(r.FormValue("stdio_install_source_kind")), stdioInstallGitHub),
		ID:              strings.TrimSpace(r.FormValue("stdio_install_id")),
		DisplayName:     strings.TrimSpace(r.FormValue("stdio_install_display_name")),
		PathPrefix:      strings.TrimSpace(r.FormValue("stdio_install_path_prefix")),
		ScopesSupported: strings.TrimSpace(r.FormValue("stdio_install_scopes_supported")),
		DownloadURL:     strings.TrimSpace(r.FormValue("stdio_install_download_url")),
		GitHubRepo:      strings.TrimSpace(r.FormValue("stdio_install_github_repo")),
		GitHubVersion:   defaultIfEmpty(strings.TrimSpace(r.FormValue("stdio_install_github_version")), "latest"),
		AssetPattern:    strings.TrimSpace(r.FormValue("stdio_install_asset_pattern")),
		SHA256:          strings.TrimSpace(r.FormValue("stdio_install_sha256")),
		ExtractMode:     defaultIfEmpty(strings.TrimSpace(r.FormValue("stdio_install_extract_mode")), "auto"),
		ExecutablePath:  strings.TrimSpace(r.FormValue("stdio_install_executable_path")),
		Args:            normalizeMultiline(r.FormValue("stdio_install_args")),
		ExtraFolders:    valuesFromSelection(r.Form["stdio_install_folder"]),
		EnvNames:        r.Form["stdio_install_env_name"],
		EnvValues:       r.Form["stdio_install_env_value"],
	}
	env, err := parseEnvRows(formData.EnvNames, formData.EnvValues)
	if err != nil {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}
	if formData.DisplayName == "" {
		formData.DisplayName = defaultIfEmpty(formData.ID, "STDIO MCP")
	}
	if formData.ID == "" {
		formData.ID = s.nextRouteID(formData.DisplayName, formData.PathPrefix, "")
	}
	if formData.PathPrefix == "" {
		formData.PathPrefix = "/" + formData.ID
	}
	if _, exists := s.routeByID(formData.ID); exists {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", "route id already exists", http.StatusBadRequest)
		return
	}

	installReq := stdioInstallRequest{
		SourceKind:     formData.SourceKind,
		RouteID:        formData.ID,
		DisplayName:    formData.DisplayName,
		DownloadURL:    formData.DownloadURL,
		GitHubRepo:     formData.GitHubRepo,
		GitHubVersion:  formData.GitHubVersion,
		AssetPattern:   formData.AssetPattern,
		SHA256:         formData.SHA256,
		ExtractMode:    formData.ExtractMode,
		ExecutablePath: formData.ExecutablePath,
		Args:           parseFlexibleList(formData.Args),
		ExtraFolders:   formData.ExtraFolders,
	}
	if formData.SourceKind == stdioInstallUpload {
		file, header, err := r.FormFile("stdio_install_file")
		if err != nil {
			s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", "STDIO artifact file is required", http.StatusBadRequest)
			return
		}
		defer file.Close()
		installReq.UploadName = header.Filename
		installReq.UploadReader = file
	}

	result, err := s.stdioInstaller.Install(r.Context(), installReq)
	if err != nil {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}

	envSecretRefs := make(map[string]string, len(env))
	for key := range env {
		envSecretRefs[key] = auth.RouteEnvSecretRef(result.RouteID, key)
	}
	route := config.Route{
		ID:              result.RouteID,
		DisplayName:     formData.DisplayName,
		Transport:       "stdio",
		PathPrefix:      formData.PathPrefix,
		UpstreamMCPPath: "/mcp",
		ScopesSupported: parseCommaList(defaultIfEmpty(formData.ScopesSupported, "mcp")),
		Access: config.RouteAccess{
			Visibility: "public",
			Mode:       "public",
		},
		Stdio: &config.RouteStdio{
			Command:       result.Command,
			Args:          parseFlexibleList(formData.Args),
			EnvSecretRefs: envSecretRefs,
			WorkingDir:    result.WorkingDir,
		},
		Notes: fmt.Sprintf("Installed by STDIO installer from %s sha256:%s", defaultIfEmpty(result.SourceAsset, result.SourceURL), result.SHA256),
	}
	if err := s.validateUpsertRoute("", route); err != nil {
		_ = os.RemoveAll(result.WorkingDir)
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.authManager.SetRouteEnvSecrets(result.RouteID, env); err != nil {
		_ = os.RemoveAll(result.WorkingDir)
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.upsertRoute("", route); err != nil {
		_ = s.authManager.DeleteRouteSecrets(result.RouteID)
		_ = os.RemoveAll(result.WorkingDir)
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}

	notice := fmt.Sprintf("STDIO MCP %s installed with executable %s", route.ID, result.ExecutablePath)
	http.Redirect(w, r, adminRedirectURLWithTab("deployments", route.ID, notice, ""), http.StatusFound)
}

func (s *Server) handleAdminDeploymentAction(w http.ResponseWriter, r *http.Request, action string) {
	identity, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.authManager.ValidateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}
	if s.dockerManager == nil {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", "Docker management is disabled", http.StatusBadRequest)
		return
	}

	routeID := strings.TrimSpace(r.FormValue("route_id"))
	route, found := s.routeByID(routeID)
	if !found || route.Deployment == nil || !route.Deployment.Managed {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", "managed deployment route not found", http.StatusBadRequest)
		return
	}
	containerName := route.Deployment.ContainerName
	var err error
	switch action {
	case "start":
		err = s.dockerManager.Start(r.Context(), containerName)
	case "stop":
		err = s.dockerManager.Stop(r.Context(), containerName)
	case "remove":
		err = s.dockerManager.Remove(r.Context(), containerName)
	default:
		err = fmt.Errorf("unsupported deployment action")
	}
	if err != nil {
		s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, adminRedirectURLWithTab("deployments", routeID, "Deployment "+action+" completed", ""), http.StatusFound)
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (*auth.Identity, bool) {
	identity, err := s.authManager.CurrentIdentity(r)
	if err != nil {
		http.Redirect(w, r, "/account/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return nil, false
	}
	if !identity.IsAdmin {
		http.Error(w, "admin access required", http.StatusForbidden)
		return nil, false
	}
	return identity, true
}

func (s *Server) renderAdminDashboard(w http.ResponseWriter, r *http.Request, identity *auth.Identity, selected routeFormData, notice, errText string, status int) {
	csrfToken := s.authManager.EnsureCSRFToken(w, r)
	routes := s.routesSnapshot()
	slices.SortFunc(routes, func(a, b config.Route) int {
		switch {
		case a.NormalizedPathPrefix < b.NormalizedPathPrefix:
			return -1
		case a.NormalizedPathPrefix > b.NormalizedPathPrefix:
			return 1
		default:
			return 0
		}
	})

	users := s.authManager.ListUsers()
	userViews := make([]dashboardUserView, 0, len(users))
	for _, user := range users {
		devices := s.authManager.ListUserDevices(user.ID)
		userViews = append(userViews, dashboardUserView{
			ID:          user.ID,
			Email:       user.Email,
			IsAdmin:     user.IsAdmin,
			GroupIDs:    user.GroupIDs,
			Groups:      strings.Join(user.GroupNames, ", "),
			DeviceCount: len(devices),
			CreatedAt:   user.CreatedAt.Format("2006-01-02 15:04"),
			UpdatedAt:   user.UpdatedAt.Format("2006-01-02 15:04"),
		})
	}
	selectedUser := s.dashboardSelectedUser(r)

	groups := s.authManager.ListGroups()
	groupViews := make([]dashboardGroupView, 0, len(groups))
	for _, group := range groups {
		groupViews = append(groupViews, dashboardGroupView{
			ID:          group.ID,
			Name:        group.Name,
			MemberCount: group.MemberCount,
			CreatedAt:   group.CreatedAt.Format("2006-01-02 15:04"),
			UpdatedAt:   group.UpdatedAt.Format("2006-01-02 15:04"),
		})
	}

	routeViews := make([]dashboardRouteView, 0, len(routes))
	for _, route := range routes {
		routeViews = append(routeViews, dashboardRouteView{
			ID:                       route.ID,
			DisplayName:              route.DisplayName,
			Transport:                defaultIfEmpty(route.Transport, "http"),
			PathPrefix:               route.NormalizedPathPrefix,
			PublicMCPURL:             s.absoluteURL(route.PublicMCPPath()),
			ProtectedMetadataURL:     s.absoluteURL(route.ProtectedResourceMetadataPath()),
			Upstream:                 routeUpstreamLabel(route),
			UpstreamMCPPath:          route.NormalizedUpstreamPath,
			MCPHTTPSessionMode:       strings.TrimSpace(route.UpstreamEnvironment["MCP_HTTP_SESSION_MODE"]),
			AccessVisibility:         defaultIfEmpty(route.Access.Visibility, "public"),
			AccessMode:               route.Access.EffectiveMode(),
			PassAuthorization:        route.PassAuthorization,
			ForwardHeadersCount:      len(route.ForwardHeaders),
			UpstreamEnvironmentCount: countNonSessionEnv(route.UpstreamEnvironment),
		})
	}
	deploymentViews, dockerErr := s.dashboardDeploymentViews(r.Context(), routes)

	if selected.UpstreamMCPPath == "" {
		selected.UpstreamMCPPath = "/mcp"
	}
	if selected.Transport == "" {
		selected.Transport = "http"
	}
	if selected.AccessVisibility == "" {
		selected.AccessVisibility = "public"
	}
	if selected.AccessMode == "" {
		selected.AccessMode = "public"
	}

	data := dashboardData{
		Title:               s.cfg.AccountPortalTitle + " Admin",
		AdminEmail:          identity.Email,
		Notice:              notice,
		Error:               errText,
		CSRFToken:           csrfToken,
		PublicBaseURL:       s.cfg.PublicBaseURL,
		RoutesPath:          s.cfg.RoutesPath,
		SelfSignupEnabled:   s.cfg.AllowSelfSignup,
		ActiveTab:           adminActiveTab(r),
		DockerEnabled:       s.cfg.DockerManagement.Enabled,
		DockerHost:          s.cfg.DockerManagement.Host,
		DockerNetworks:      strings.Join(s.cfg.DockerManagement.DefaultNetworks, ", "),
		DockerError:         dockerErr,
		BuildEnabled:        s.cfg.BuildManagement.Enabled,
		BuildMaxMB:          s.cfg.BuildManagement.MaxArtifactBytes >> 20,
		BuildHosts:          strings.Join(s.cfg.BuildManagement.AllowedDownloadHosts, ", "),
		BuildBaseImages:     strings.Join(s.cfg.BuildManagement.AllowedBaseImages, ", "),
		StdioInstallEnabled: s.cfg.StdioInstaller.Enabled,
		StdioInstallMaxMB:   s.cfg.StdioInstaller.MaxArtifactBytes >> 20,
		StdioInstallStore:   s.cfg.StdioInstaller.StoreDir,
		Routes:              routeViews,
		Deployments:         deploymentViews,
		Users:               userViews,
		Groups:              groupViews,
		SelectedUser:        selectedUser,
		SelectedRoute:       selected,
		DeploymentForm:      newDeploymentFormData(s.cfg.DockerManagement),
		BuildForm:           newArtifactBuildFormData(s.cfg.BuildManagement),
		StdioInstallForm:    newStdioInstallFormData(),
	}

	renderAdminHTML(w, status, data)
}

func (s *Server) dashboardSelectedUser(r *http.Request) *dashboardUserDetailView {
	userID := strings.TrimSpace(r.URL.Query().Get("user"))
	if userID == "" {
		return nil
	}
	user, ok := s.authManager.UserByID(userID)
	if !ok {
		return nil
	}
	devices := s.authManager.ListUserDevices(user.ID)
	deviceViews := make([]dashboardUserDeviceView, 0, len(devices))
	for _, device := range devices {
		deviceViews = append(deviceViews, dashboardUserDeviceView{
			ID:               device.ID,
			ClientID:         device.ClientID,
			ClientName:       device.ClientName,
			Resource:         defaultIfEmpty(device.Resource, "gatewayweit"),
			Scope:            device.Scope,
			RedirectURIs:     strings.Join(device.RedirectURIs, ", "),
			TokenCount:       device.TokenCount,
			CreatedAt:        device.CreatedAt.Format("2006-01-02 15:04"),
			LastUsedAt:       device.LastUsedAt.Format("2006-01-02 15:04"),
			RefreshExpiresAt: device.RefreshExpiresAt.Format("2006-01-02 15:04"),
		})
	}
	return &dashboardUserDetailView{
		ID:        user.ID,
		Email:     user.Email,
		IsAdmin:   user.IsAdmin,
		GroupIDs:  user.GroupIDs,
		Groups:    strings.Join(user.GroupNames, ", "),
		CreatedAt: user.CreatedAt.Format("2006-01-02 15:04"),
		UpdatedAt: user.UpdatedAt.Format("2006-01-02 15:04"),
		Devices:   deviceViews,
	}
}

func parseRouteForm(r *http.Request) (routeFormData, config.Route, error) {
	formData := routeFormData{
		OriginalID:            strings.TrimSpace(r.FormValue("original_id")),
		ID:                    strings.TrimSpace(r.FormValue("id")),
		DisplayName:           strings.TrimSpace(r.FormValue("display_name")),
		Transport:             defaultIfEmpty(strings.ToLower(strings.TrimSpace(r.FormValue("transport"))), "http"),
		PathPrefix:            strings.TrimSpace(r.FormValue("path_prefix")),
		Upstream:              strings.TrimSpace(r.FormValue("upstream")),
		UpstreamMCPPath:       strings.TrimSpace(r.FormValue("upstream_mcp_path")),
		ScopesSupported:       strings.TrimSpace(r.FormValue("scopes_supported")),
		PassAuthorization:     formCheckbox(r, "pass_authorization_header"),
		ResourceDocumentation: strings.TrimSpace(r.FormValue("resource_documentation")),
		MCPHTTPSessionMode:    strings.TrimSpace(r.FormValue("mcp_http_session_mode")),
		AccessVisibility:      defaultIfEmpty(strings.TrimSpace(r.FormValue("access_visibility")), "public"),
		AccessMode:            defaultIfEmpty(strings.TrimSpace(r.FormValue("access_mode")), "public"),
		AllowedUsers:          valuesFromSelection(r.Form["allowed_users"]),
		AllowedGroups:         valuesFromSelection(r.Form["allowed_groups"]),
		DeniedUsers:           valuesFromSelection(r.Form["denied_users"]),
		DeniedGroups:          valuesFromSelection(r.Form["denied_groups"]),
		ForwardHeaders:        normalizeMultiline(r.FormValue("forward_headers")),
		UpstreamEnvironment:   normalizeMultiline(r.FormValue("upstream_environment")),
		StdioCommand:          strings.TrimSpace(r.FormValue("stdio_command")),
		StdioArgs:             normalizeMultiline(r.FormValue("stdio_args")),
		StdioEnv:              normalizeMultiline(r.FormValue("stdio_env")),
		StdioWorkingDir:       strings.TrimSpace(r.FormValue("stdio_working_dir")),
		OpenAPISpecPath:       strings.TrimSpace(r.FormValue("openapi_spec_path")),
		OpenAPISpecURL:        strings.TrimSpace(r.FormValue("openapi_spec_url")),
		OpenAPIBaseURL:        strings.TrimSpace(r.FormValue("openapi_base_url")),
		OpenAPIHeaders:        normalizeMultiline(r.FormValue("openapi_headers")),
		OpenAPITimeoutSeconds: defaultIfEmpty(strings.TrimSpace(r.FormValue("openapi_timeout_seconds")), "30"),
		Notes:                 strings.TrimSpace(r.FormValue("notes")),
	}
	if len(r.Form["access_subject"]) != 0 {
		formData.AllowedUsers, formData.AllowedGroups, formData.DeniedUsers, formData.DeniedGroups = parseAccessMatrix(r.Form["access_subject"], r.Form["access_decision"])
	}
	if formData.Transport != "http" && formData.Transport != "stdio" && formData.Transport != "openapi" {
		return formData, config.Route{}, fmt.Errorf("transport must be http, stdio or openapi")
	}

	forwardHeaders, err := parseMapTextarea(formData.ForwardHeaders, "header")
	if err != nil {
		return formData, config.Route{}, err
	}
	upstreamEnvironment, err := parseMapTextarea(formData.UpstreamEnvironment, "env")
	if err != nil {
		return formData, config.Route{}, err
	}
	if formData.MCPHTTPSessionMode != "" {
		if upstreamEnvironment == nil {
			upstreamEnvironment = map[string]string{}
		}
		upstreamEnvironment["MCP_HTTP_SESSION_MODE"] = formData.MCPHTTPSessionMode
	}
	if formData.Transport == "stdio" {
		stdioEnv, err := parseMapTextarea(formData.StdioEnv, "env")
		if err != nil {
			return formData, config.Route{}, err
		}
		route := config.Route{
			ID:                    formData.ID,
			DisplayName:           formData.DisplayName,
			Transport:             "stdio",
			PathPrefix:            formData.PathPrefix,
			UpstreamMCPPath:       defaultIfEmpty(formData.UpstreamMCPPath, "/mcp"),
			ScopesSupported:       parseCommaList(formData.ScopesSupported),
			ForwardHeaders:        forwardHeaders,
			UpstreamEnvironment:   upstreamEnvironment,
			ResourceDocumentation: formData.ResourceDocumentation,
			Notes:                 formData.Notes,
			Access: config.RouteAccess{
				Visibility:    formData.AccessVisibility,
				Mode:          formData.AccessMode,
				AllowedUsers:  formData.AllowedUsers,
				AllowedGroups: formData.AllowedGroups,
				DeniedUsers:   formData.DeniedUsers,
				DeniedGroups:  formData.DeniedGroups,
			},
			Stdio: &config.RouteStdio{
				Command:    formData.StdioCommand,
				Args:       parseFlexibleList(formData.StdioArgs),
				Env:        stdioEnv,
				WorkingDir: formData.StdioWorkingDir,
			},
		}
		return formData, route, nil
	}

	if formData.Transport == "openapi" {
		headers, err := parseMapTextarea(formData.OpenAPIHeaders, "header")
		if err != nil {
			return formData, config.Route{}, err
		}
		timeoutSeconds, err := strconv.Atoi(formData.OpenAPITimeoutSeconds)
		if err != nil {
			return formData, config.Route{}, fmt.Errorf("OpenAPI timeout must be numeric")
		}
		route := config.Route{
			ID:                    formData.ID,
			DisplayName:           formData.DisplayName,
			Transport:             "openapi",
			PathPrefix:            formData.PathPrefix,
			UpstreamMCPPath:       defaultIfEmpty(formData.UpstreamMCPPath, "/mcp"),
			ScopesSupported:       parseCommaList(formData.ScopesSupported),
			ForwardHeaders:        forwardHeaders,
			UpstreamEnvironment:   upstreamEnvironment,
			ResourceDocumentation: formData.ResourceDocumentation,
			Notes:                 formData.Notes,
			Access: config.RouteAccess{
				Visibility:    formData.AccessVisibility,
				Mode:          formData.AccessMode,
				AllowedUsers:  formData.AllowedUsers,
				AllowedGroups: formData.AllowedGroups,
				DeniedUsers:   formData.DeniedUsers,
				DeniedGroups:  formData.DeniedGroups,
			},
			OpenAPI: &config.RouteOpenAPI{
				SpecPath:       formData.OpenAPISpecPath,
				SpecURL:        formData.OpenAPISpecURL,
				BaseURL:        formData.OpenAPIBaseURL,
				Headers:        headers,
				TimeoutSeconds: timeoutSeconds,
			},
		}
		return formData, route, nil
	}

	route := config.Route{
		ID:                  formData.ID,
		DisplayName:         formData.DisplayName,
		Transport:           "http",
		PathPrefix:          formData.PathPrefix,
		Upstream:            formData.Upstream,
		UpstreamMCPPath:     defaultIfEmpty(formData.UpstreamMCPPath, "/mcp"),
		ScopesSupported:     parseCommaList(formData.ScopesSupported),
		PassAuthorization:   formData.PassAuthorization,
		ForwardHeaders:      forwardHeaders,
		UpstreamEnvironment: upstreamEnvironment,
		Access: config.RouteAccess{
			Visibility:    formData.AccessVisibility,
			Mode:          formData.AccessMode,
			AllowedUsers:  formData.AllowedUsers,
			AllowedGroups: formData.AllowedGroups,
			DeniedUsers:   formData.DeniedUsers,
			DeniedGroups:  formData.DeniedGroups,
		},
		ResourceDocumentation: formData.ResourceDocumentation,
		Notes:                 formData.Notes,
	}

	return formData, route, nil
}

func (s *Server) parseDeploymentForm(r *http.Request) (deploymentFormData, config.Route, *dockerDeploymentSpec, error) {
	formData := deploymentFormData{
		Transport:             defaultIfEmpty(strings.ToLower(strings.TrimSpace(r.FormValue("transport"))), "http"),
		ID:                    strings.TrimSpace(r.FormValue("id")),
		DisplayName:           strings.TrimSpace(r.FormValue("display_name")),
		PathPrefix:            strings.TrimSpace(r.FormValue("path_prefix")),
		Image:                 strings.TrimSpace(r.FormValue("image")),
		ContainerName:         strings.TrimSpace(r.FormValue("container_name")),
		InternalPort:          defaultIfEmpty(strings.TrimSpace(r.FormValue("internal_port")), "8080"),
		UpstreamMCPPath:       defaultIfEmpty(strings.TrimSpace(r.FormValue("upstream_mcp_path")), "/mcp"),
		ScopesSupported:       strings.TrimSpace(r.FormValue("scopes_supported")),
		Networks:              normalizeMultiline(r.FormValue("networks")),
		RestartPolicy:         defaultIfEmpty(strings.TrimSpace(r.FormValue("restart_policy")), s.cfg.DockerManagement.RestartPolicy),
		ResourceDocumentation: strings.TrimSpace(r.FormValue("resource_documentation")),
		Environment:           normalizeMultiline(r.FormValue("environment")),
		StdioCommand:          strings.TrimSpace(r.FormValue("stdio_command")),
		StdioArgs:             normalizeMultiline(r.FormValue("stdio_args")),
		StdioEnv:              normalizeMultiline(r.FormValue("stdio_env")),
		StdioWorkingDir:       strings.TrimSpace(r.FormValue("stdio_working_dir")),
		Notes:                 strings.TrimSpace(r.FormValue("notes")),
	}
	if formData.Transport != "http" && formData.Transport != "stdio" {
		return formData, config.Route{}, nil, fmt.Errorf("transport must be http or stdio")
	}
	if formData.DisplayName == "" {
		formData.DisplayName = formData.Image
		if formData.Transport == "stdio" {
			formData.DisplayName = formData.StdioCommand
		}
	}
	if formData.ID == "" {
		formData.ID = s.nextRouteID(formData.DisplayName, formData.PathPrefix, "")
	}
	if formData.ContainerName == "" {
		formData.ContainerName = slugify(formData.ID)
	}
	if formData.PathPrefix == "" {
		formData.PathPrefix = "/" + formData.ID
	}

	if formData.Transport == "stdio" {
		env, err := parseMapTextarea(formData.StdioEnv, "env")
		if err != nil {
			return formData, config.Route{}, nil, err
		}
		route := config.Route{
			ID:                    formData.ID,
			DisplayName:           formData.DisplayName,
			Transport:             "stdio",
			PathPrefix:            formData.PathPrefix,
			UpstreamMCPPath:       defaultIfEmpty(formData.UpstreamMCPPath, "/mcp"),
			ScopesSupported:       parseCommaList(formData.ScopesSupported),
			UpstreamEnvironment:   env,
			ResourceDocumentation: formData.ResourceDocumentation,
			Notes:                 formData.Notes,
			Access: config.RouteAccess{
				Visibility: "public",
				Mode:       "public",
			},
			Stdio: &config.RouteStdio{
				Command:    formData.StdioCommand,
				Args:       parseFlexibleList(formData.StdioArgs),
				Env:        env,
				WorkingDir: formData.StdioWorkingDir,
			},
		}
		return formData, route, nil, nil
	}

	internalPort, err := strconv.Atoi(formData.InternalPort)
	if err != nil || internalPort <= 0 || internalPort > 65535 {
		return formData, config.Route{}, nil, fmt.Errorf("internal port must be between 1 and 65535")
	}
	env, err := parseMapTextarea(formData.Environment, "env")
	if err != nil {
		return formData, config.Route{}, nil, err
	}
	networks := parseFlexibleList(formData.Networks)
	if len(networks) == 0 {
		networks = append([]string(nil), s.cfg.DockerManagement.DefaultNetworks...)
	}

	route := config.Route{
		ID:                    formData.ID,
		DisplayName:           formData.DisplayName,
		Transport:             "http",
		PathPrefix:            formData.PathPrefix,
		Upstream:              fmt.Sprintf("http://%s:%d", formData.ContainerName, internalPort),
		UpstreamMCPPath:       formData.UpstreamMCPPath,
		ScopesSupported:       parseCommaList(formData.ScopesSupported),
		UpstreamEnvironment:   env,
		ResourceDocumentation: formData.ResourceDocumentation,
		Notes:                 formData.Notes,
		Access: config.RouteAccess{
			Visibility: "public",
			Mode:       "public",
		},
		Deployment: &config.RouteDeployment{
			Type:          "docker",
			Managed:       true,
			Image:         formData.Image,
			ContainerName: formData.ContainerName,
			InternalPort:  internalPort,
			Networks:      networks,
			RestartPolicy: formData.RestartPolicy,
		},
	}
	spec := dockerDeploymentSpec{
		RouteID:       formData.ID,
		DisplayName:   formData.DisplayName,
		Image:         formData.Image,
		ContainerName: formData.ContainerName,
		InternalPort:  internalPort,
		Env:           env,
		Networks:      networks,
		RestartPolicy: formData.RestartPolicy,
	}
	return formData, route, &spec, nil
}

func newRouteFormData(route config.Route, originalID string) routeFormData {
	environment := mapToLines(route.UpstreamEnvironment, "env", "MCP_HTTP_SESSION_MODE")
	form := routeFormData{
		OriginalID:            originalID,
		ID:                    route.ID,
		DisplayName:           route.DisplayName,
		Transport:             defaultIfEmpty(route.Transport, "http"),
		PathPrefix:            route.NormalizedPathPrefix,
		Upstream:              route.Upstream,
		UpstreamMCPPath:       route.NormalizedUpstreamPath,
		ScopesSupported:       strings.Join(route.ScopesSupported, ", "),
		PassAuthorization:     route.PassAuthorization,
		ResourceDocumentation: route.ResourceDocumentation,
		MCPHTTPSessionMode:    strings.TrimSpace(route.UpstreamEnvironment["MCP_HTTP_SESSION_MODE"]),
		AccessVisibility:      defaultIfEmpty(route.Access.Visibility, "public"),
		AccessMode:            route.Access.EffectiveMode(),
		AllowedUsers:          append([]string(nil), route.Access.AllowedUsers...),
		AllowedGroups:         append([]string(nil), route.Access.AllowedGroups...),
		DeniedUsers:           append([]string(nil), route.Access.DeniedUsers...),
		DeniedGroups:          append([]string(nil), route.Access.DeniedGroups...),
		ForwardHeaders:        mapToLines(route.ForwardHeaders, "header"),
		UpstreamEnvironment:   environment,
		Notes:                 route.Notes,
	}
	if route.Stdio != nil {
		form.StdioCommand = route.Stdio.Command
		form.StdioArgs = strings.Join(route.Stdio.Args, "\n")
		form.StdioEnv = mapToLines(route.Stdio.Env, "env")
		form.StdioWorkingDir = route.Stdio.WorkingDir
	}
	if route.OpenAPI != nil {
		form.OpenAPISpecPath = route.OpenAPI.SpecPath
		form.OpenAPISpecURL = route.OpenAPI.SpecURL
		form.OpenAPIBaseURL = route.OpenAPI.BaseURL
		form.OpenAPIHeaders = mapToLines(route.OpenAPI.Headers, "header")
		form.OpenAPITimeoutSeconds = strconv.Itoa(route.OpenAPI.TimeoutSeconds)
	}
	return form
}

func newDeploymentFormData(cfg config.DockerManagementConfig) deploymentFormData {
	return deploymentFormData{
		Transport:       "http",
		InternalPort:    "8080",
		UpstreamMCPPath: "/mcp",
		ScopesSupported: "mcp",
		Networks:        strings.Join(cfg.DefaultNetworks, "\n"),
		RestartPolicy:   defaultIfEmpty(cfg.RestartPolicy, "unless-stopped"),
	}
}

func newArtifactBuildFormData(cfg config.BuildManagementConfig) artifactBuildFormData {
	return artifactBuildFormData{
		SourceKind:   artifactSourceURL,
		BaseImage:    defaultIfEmpty(cfg.DefaultBaseImage, "debian:bookworm-slim"),
		InternalPort: "8080",
		ExtractMode:  extractNone,
	}
}

func newStdioInstallFormData() stdioInstallFormData {
	return stdioInstallFormData{
		SourceKind:      stdioInstallGitHub,
		ScopesSupported: "mcp",
		GitHubVersion:   "latest",
		ExtractMode:     "auto",
		EnvNames:        make([]string, 8),
		EnvValues:       make([]string, 8),
		ExtraFolders:    make([]string, 6),
	}
}

func newEmptyRouteFormData() routeFormData {
	return routeFormData{
		Transport:             "http",
		UpstreamMCPPath:       "/mcp",
		ScopesSupported:       "mcp",
		OpenAPITimeoutSeconds: "30",
		AccessVisibility:      "public",
		AccessMode:            "public",
	}
}

func parseMapTextarea(raw string, mode string) (map[string]string, error) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	values := make(map[string]string)
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		key, value, ok := splitKeyValueLine(line, mode)
		if !ok {
			return nil, fmt.Errorf("invalid %s entry on line %d", mode, idx+1)
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if len(values) == 0 {
		return nil, nil
	}
	return values, nil
}

func splitKeyValueLine(line, mode string) (string, string, bool) {
	if mode == "env" {
		if key, value, ok := strings.Cut(line, "="); ok && strings.TrimSpace(key) != "" {
			return key, value, true
		}
	}
	if key, value, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(key) != "" {
		return key, value, true
	}
	if mode == "header" {
		if key, value, ok := strings.Cut(line, "="); ok && strings.TrimSpace(key) != "" {
			return key, value, true
		}
	}
	return "", "", false
}

func parseCommaList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func mapToLines(values map[string]string, mode string, ignoredKeys ...string) string {
	if len(values) == 0 {
		return ""
	}
	ignored := make(map[string]struct{}, len(ignoredKeys))
	for _, key := range ignoredKeys {
		ignored[key] = struct{}{}
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		if _, skip := ignored[key]; skip {
			continue
		}
		keys = append(keys, key)
	}
	slices.Sort(keys)

	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		separator := ": "
		if mode == "env" {
			separator = "="
		}
		lines = append(lines, key+separator+values[key])
	}
	return strings.Join(lines, "\n")
}

func formCheckbox(r *http.Request, field string) bool {
	value := strings.ToLower(strings.TrimSpace(r.FormValue(field)))
	return value == "on" || value == "true" || value == "1" || value == "yes"
}

func normalizeMultiline(raw string) string {
	return strings.TrimSpace(strings.ReplaceAll(raw, "\r\n", "\n"))
}

func parseFlexibleList(raw string) []string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, ",", "\n")
	parts := strings.Split(raw, "\n")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" || slices.Contains(values, value) {
			continue
		}
		values = append(values, value)
	}
	return values
}

func parseEnvRows(names, values []string) (map[string]string, error) {
	out := make(map[string]string)
	for idx, rawName := range names {
		name := strings.TrimSpace(rawName)
		value := ""
		if idx < len(values) {
			value = values[idx]
		}
		if name == "" && strings.TrimSpace(value) == "" {
			continue
		}
		if name == "" {
			return nil, fmt.Errorf("environment variable name is required")
		}
		out[name] = value
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (s *Server) removeManagedStdioInstall(route config.Route) error {
	if route.Transport != "stdio" || route.Stdio == nil || strings.TrimSpace(route.Stdio.WorkingDir) == "" {
		return nil
	}
	storeDir := filepath.Clean(strings.TrimSpace(s.cfg.StdioInstaller.StoreDir))
	workingDir := filepath.Clean(strings.TrimSpace(route.Stdio.WorkingDir))
	if storeDir == "" || !filepath.IsAbs(storeDir) || !filepath.IsAbs(workingDir) {
		return nil
	}
	rel, err := filepath.Rel(storeDir, workingDir)
	if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return nil
	}
	if err := os.RemoveAll(workingDir); err != nil {
		return fmt.Errorf("remove managed STDIO install %q: %w", workingDir, err)
	}
	return nil
}

func defaultIfEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func adminRedirectURL(routeID, notice, errText string) string {
	query := url.Values{}
	if routeID != "" {
		query.Set("route", routeID)
	}
	if notice != "" {
		query.Set("notice", notice)
	}
	if errText != "" {
		query.Set("error", errText)
	}
	if encoded := query.Encode(); encoded != "" {
		return "/admin?" + encoded
	}
	return "/admin"
}

func adminRedirectURLWithTab(tab, routeID, notice, errText string) string {
	query := url.Values{}
	if tab != "" && tab != "routes" {
		query.Set("tab", tab)
	}
	if routeID != "" {
		query.Set("route", routeID)
	}
	if notice != "" {
		query.Set("notice", notice)
	}
	if errText != "" {
		query.Set("error", errText)
	}
	if encoded := query.Encode(); encoded != "" {
		return "/admin?" + encoded
	}
	return "/admin"
}

func adminUserRedirectURL(userID, notice, errText string) string {
	query := url.Values{}
	query.Set("tab", "users")
	if userID != "" {
		query.Set("user", userID)
	}
	if notice != "" {
		query.Set("notice", notice)
	}
	if errText != "" {
		query.Set("error", errText)
	}
	return "/admin?" + query.Encode()
}

func adminActiveTab(r *http.Request) string {
	if strings.HasPrefix(r.URL.Path, "/admin/deployments") {
		return "deployments"
	}
	if strings.HasPrefix(r.URL.Path, "/admin/users") || strings.HasPrefix(r.URL.Path, "/admin/groups") {
		return "users"
	}
	tab := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tab")))
	switch tab {
	case "deployments", "users":
		return tab
	default:
		return "routes"
	}
}

func parseAccessMatrix(subjects, decisions []string) (allowedUsers, allowedGroups, deniedUsers, deniedGroups []string) {
	for idx, subject := range subjects {
		decision := ""
		if idx < len(decisions) {
			decision = strings.ToLower(strings.TrimSpace(decisions[idx]))
		}
		if decision != "allow" && decision != "deny" {
			continue
		}

		kind, value, ok := strings.Cut(strings.TrimSpace(subject), ":")
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		switch {
		case kind == "user" && decision == "allow":
			allowedUsers = append(allowedUsers, value)
		case kind == "group" && decision == "allow":
			allowedGroups = append(allowedGroups, value)
		case kind == "user" && decision == "deny":
			deniedUsers = append(deniedUsers, value)
		case kind == "group" && decision == "deny":
			deniedGroups = append(deniedGroups, value)
		}
	}
	return valuesFromSelection(allowedUsers), valuesFromSelection(allowedGroups), valuesFromSelection(deniedUsers), valuesFromSelection(deniedGroups)
}

func countNonSessionEnv(values map[string]string) int {
	count := 0
	for key := range values {
		if key == "MCP_HTTP_SESSION_MODE" {
			continue
		}
		count++
	}
	return count
}

func routeUpstreamLabel(route config.Route) string {
	if route.Transport == "stdio" {
		if route.Stdio == nil {
			return "stdio"
		}
		return "stdio://" + route.Stdio.Command
	}
	if route.Transport == "openapi" {
		if route.OpenAPI == nil {
			return "openapi"
		}
		return "openapi://" + route.OpenAPI.BaseURL
	}
	return route.Upstream
}

func (s *Server) managedDeploymentRoutes() []config.Route {
	routes := s.routesSnapshot()
	out := make([]config.Route, 0, len(routes))
	for _, route := range routes {
		if route.Transport == "stdio" || route.Deployment != nil && route.Deployment.Managed {
			out = append(out, route)
		}
	}
	return out
}

func (s *Server) dashboardDeploymentViews(ctx context.Context, routes []config.Route) ([]dashboardDeploymentView, string) {
	views := make([]dashboardDeploymentView, 0)
	var dockerErr string
	for _, route := range routes {
		if route.Transport == "stdio" {
			view := dashboardDeploymentView{
				RouteID:      route.ID,
				DisplayName:  route.DisplayName,
				Transport:    "stdio",
				PublicMCPURL: s.absoluteURL(route.PublicMCPPath()),
				Upstream:     routeUpstreamLabel(route),
				State:        "native",
				Exists:       true,
				Inspectable:  true,
			}
			if route.Stdio != nil {
				view.Command = strings.Join(append([]string{route.Stdio.Command}, route.Stdio.Args...), " ")
			}
			views = append(views, view)
			continue
		}
		if route.Deployment == nil || !route.Deployment.Managed {
			continue
		}
		deployment := route.Deployment
		view := dashboardDeploymentView{
			RouteID:       route.ID,
			DisplayName:   route.DisplayName,
			Transport:     defaultIfEmpty(route.Transport, "http"),
			PublicMCPURL:  s.absoluteURL(route.PublicMCPPath()),
			Image:         deployment.Image,
			ContainerName: deployment.ContainerName,
			InternalPort:  deployment.InternalPort,
			Networks:      strings.Join(deployment.Networks, ", "),
			Upstream:      route.Upstream,
			State:         "unknown",
		}
		if s.dockerManager != nil {
			state, err := s.dockerManager.Inspect(ctx, deployment.ContainerName)
			if err != nil {
				dockerErr = err.Error()
			} else {
				view.Inspectable = true
				view.Exists = state.Exists
				if state.Exists {
					view.State = defaultIfEmpty(state.State, "unknown")
					view.Status = state.Status
				} else {
					view.State = "missing"
				}
			}
		}
		views = append(views, view)
	}
	return views, dockerErr
}

func (s *Server) nextRouteID(displayName, pathPrefix, excludeID string) string {
	base := slugify(defaultIfEmpty(displayName, strings.Trim(pathPrefix, "/")))
	if base == "" {
		base = "mcp"
	}

	exists := func(candidate string) bool {
		routes := s.routesSnapshot()
		for _, route := range routes {
			if route.ID == excludeID {
				continue
			}
			if strings.EqualFold(route.ID, candidate) {
				return true
			}
		}
		return false
	}

	if !exists(base) {
		return base
	}
	for idx := 2; ; idx++ {
		candidate := fmt.Sprintf("%s-%d", base, idx)
		if !exists(candidate) {
			return candidate
		}
	}
}

func slugify(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	lastDash := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			builder.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && builder.Len() > 0 {
				builder.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(builder.String(), "-")
}

func redactRoutes(routes []config.Route) []config.Route {
	redacted := cloneRoutes(routes)
	for i := range redacted {
		for key := range redacted[i].ForwardHeaders {
			if looksSensitiveKey(key) {
				redacted[i].ForwardHeaders[key] = "[redacted]"
			}
		}
		for key := range redacted[i].UpstreamEnvironment {
			if looksSensitiveKey(key) {
				redacted[i].UpstreamEnvironment[key] = "[redacted]"
			}
		}
		if redacted[i].Stdio != nil {
			for key := range redacted[i].Stdio.Env {
				if looksSensitiveKey(key) {
					redacted[i].Stdio.Env[key] = "[redacted]"
				}
			}
		}
	}
	return redacted
}

func looksSensitiveKey(key string) bool {
	key = strings.ToLower(key)
	for _, marker := range []string{"authorization", "token", "secret", "password", "key"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func hasString(values []string, candidate string) bool {
	return containsFold(values, candidate)
}

func accessDecision(form routeFormData, subjectType, value string) string {
	switch subjectType {
	case "user":
		if containsFold(form.DeniedUsers, value) {
			return "deny"
		}
		if containsFold(form.AllowedUsers, value) {
			return "allow"
		}
	case "group":
		if containsFold(form.DeniedGroups, value) {
			return "deny"
		}
		if containsFold(form.AllowedGroups, value) {
			return "allow"
		}
	}
	return ""
}

func renderAdminHTML(w http.ResponseWriter, status int, data dashboardData) {
	t := template.Must(template.New("admin").Funcs(template.FuncMap{
		"accessDecision": accessDecision,
		"has":            hasString,
	}).Parse(adminDashboardTemplate))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_ = t.Execute(w, data)
}

const adminDashboardTemplate = `
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #eef3ee;
      --card: #fffdf7;
      --card-2: #f8fbf4;
      --border: #d9dece;
      --ink: #18201c;
      --muted: #627064;
      --accent: #145a49;
      --accent-soft: #e2efe7;
      --danger: #8c1d1d;
      --success: #14623d;
      --warn: #9b5a15;
      font-family: "Aptos", "Trebuchet MS", system-ui, sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background:
        radial-gradient(circle at 8% 2%, rgba(20,90,73,0.13), transparent 28rem),
        radial-gradient(circle at 92% 0%, rgba(155,90,21,0.13), transparent 24rem),
        linear-gradient(180deg, #fbf8ef 0%, var(--bg) 100%);
      color: var(--ink);
    }
    main { max-width: 88rem; margin: 0 auto; padding: 2rem 1rem 4rem; }
    header { display: flex; justify-content: space-between; gap: 1rem; align-items: flex-start; margin-bottom: 1.2rem; }
    h1, h2, h3 { margin: 0; letter-spacing: -0.02em; }
    h1 { font-size: clamp(2rem, 5vw, 3.4rem); line-height: 1; }
    h2 { font-size: 1.15rem; margin-bottom: 0.45rem; }
    h3 { font-size: 0.98rem; }
    p { margin: 0; }
    a { color: var(--accent); }
    .muted { color: var(--muted); }
    .pill, .tag {
      display: inline-flex;
      width: fit-content;
      background: var(--accent-soft);
      color: var(--accent);
      border-radius: 999px;
      padding: 0.24rem 0.62rem;
      font-size: 0.82rem;
      font-weight: 800;
    }
    .tag.private { background: #f7e7d7; color: var(--warn); }
    .top-actions, .route-actions, .inline-actions, .form-actions, .toolbar {
      display: flex;
      gap: 0.55rem;
      flex-wrap: wrap;
      align-items: center;
    }
    .link-button, button {
      appearance: none;
      border: 1px solid transparent;
      background: var(--accent);
      color: white;
      border-radius: 999px;
      padding: 0.72rem 1rem;
      font: inherit;
      font-weight: 750;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }
    button.secondary, .link-button.secondary { background: #fffdf7; color: var(--ink); border-color: var(--border); }
    button.danger { background: var(--danger); }
    details.import-menu { position: relative; }
    details.import-menu summary {
      list-style: none;
      border: 1px solid var(--border);
      background: #fffdf7;
      color: var(--ink);
      border-radius: 999px;
      padding: 0.72rem 1rem;
      font-weight: 750;
      cursor: pointer;
    }
    details.import-menu summary::-webkit-details-marker { display: none; }
    .import-panel {
      position: absolute;
      right: 0;
      top: calc(100% + .55rem);
      z-index: 10;
      width: min(34rem, calc(100vw - 2rem));
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 1rem;
      box-shadow: 0 24px 70px rgba(24,32,28,0.18);
    }
    .tabs {
      display: flex;
      gap: .55rem;
      flex-wrap: wrap;
      margin: 1rem 0;
    }
    .tab {
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: .72rem 1rem;
      color: var(--ink);
      background: #fffdf7;
      text-decoration: none;
      font-weight: 800;
    }
    .tab.active { background: var(--accent); color: white; border-color: var(--accent); }
    .notice, .error {
      margin-bottom: 1rem;
      padding: 0.9rem 1rem;
      border-radius: 16px;
      border: 1px solid var(--border);
    }
    .notice { background: #edf8f1; color: var(--success); border-color: #b7e1c6; }
    .error { background: #fff0f0; color: var(--danger); border-color: #f0c3c3; }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr));
      gap: 0.8rem;
      margin-bottom: 1rem;
    }
    .summary-card, section {
      background: rgba(255,253,247,0.92);
      border: 1px solid var(--border);
      border-radius: 22px;
      box-shadow: 0 18px 50px rgba(24,32,28,0.07);
    }
    .summary-card { padding: 1rem; }
    .summary-card strong { display: block; font-size: 1.22rem; margin-top: 0.35rem; word-break: break-all; }
    .layout {
      display: grid;
      grid-template-columns: minmax(18rem, 0.88fr) minmax(26rem, 1.35fr);
      gap: 1rem;
      align-items: start;
    }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; align-items: start; }
    section { padding: 1rem; }
    .stack { display: grid; gap: 0.85rem; }
    .route-list, .users { display: grid; gap: 0.75rem; margin-top: 1rem; }
    .route-card, .user-card, .mini-card {
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 0.95rem;
      background: linear-gradient(180deg, #fffefb, var(--card-2));
    }
    .route-meta, .user-meta, .mini-meta {
      display: grid;
      gap: 0.22rem;
      margin-top: 0.45rem;
      font-size: 0.91rem;
    }
    label { display: block; font-size: 0.9rem; font-weight: 800; margin-bottom: 0.35rem; }
    input[type="text"], input[type="url"], input[type="email"], input[type="password"], input[type="file"], select, textarea {
      width: 100%;
      border: 1px solid #cbd2c3;
      border-radius: 14px;
      padding: 0.72rem 0.82rem;
      font: inherit;
      background: #fff;
      color: var(--ink);
    }
    textarea {
      min-height: 7.2rem;
      resize: vertical;
      font-family: "SFMono-Regular", "Cascadia Mono", monospace;
      font-size: 0.88rem;
    }
    .field-grid { display: grid; gap: 0.8rem; grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .full { grid-column: 1 / -1; }
    .checkbox, .checkline {
      display: flex;
      gap: 0.58rem;
      align-items: flex-start;
      border: 1px dashed #cad3c2;
      border-radius: 15px;
      padding: 0.72rem 0.82rem;
      background: #fcfff8;
    }
    .checkline { font-weight: 650; margin: 0; }
    .checkbox input, .checkline input { width: auto; margin: 0.18rem 0 0; }
    .picker-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0.6rem; }
    details.advanced {
      border: 1px solid var(--border);
      border-radius: 18px;
      background: #fffdf7;
      padding: .85rem;
    }
    details.advanced summary {
      cursor: pointer;
      font-weight: 850;
    }
    .access-table {
      width: 100%;
      border-collapse: collapse;
      font-size: .92rem;
      margin-top: .7rem;
    }
    .data-table {
      width: 100%;
      border-collapse: collapse;
      font-size: .92rem;
      margin-top: .8rem;
    }
    .data-table th, .data-table td {
      border-bottom: 1px solid var(--border);
      padding: .72rem .5rem;
      text-align: left;
      vertical-align: top;
    }
    .data-table th { color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; }
    .data-table td:last-child { text-align: right; }
    .detail-panel { margin-top: 1rem; }
    .access-table th, .access-table td {
      border-bottom: 1px solid var(--border);
      padding: .55rem .45rem;
      text-align: left;
      vertical-align: middle;
    }
    .access-table th { color: var(--muted); font-size: .82rem; }
    .access-table select { min-width: 9rem; padding: .48rem .55rem; border-radius: 10px; }
    .helper { font-size: 0.86rem; color: var(--muted); margin-top: 0.3rem; }
    .small-form { display: grid; gap: 0.5rem; margin-top: 0.75rem; }
    .divider { height: 1px; background: var(--border); margin: 1rem 0; }
    code { background: #f0eadf; padding: 0.12rem 0.35rem; border-radius: 7px; word-break: break-all; }
    @media (max-width: 1080px) {
      .layout, .grid { grid-template-columns: 1fr; }
      .field-grid, .picker-grid { grid-template-columns: 1fr; }
      header { flex-direction: column; }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <div class="stack">
        <span class="pill">Admin Dashboard</span>
        <h1>{{.Title}}</h1>
        <p class="muted">Angemeldet als <strong>{{.AdminEmail}}</strong>. Routen, Sichtbarkeit, Rechte, Gruppen und Export zentral verwalten.</p>
      </div>
      <div class="top-actions">
        <details class="import-menu">
          <summary>Import / Export</summary>
          <div class="import-panel">
            <h2>Routen sichern</h2>
            <p class="muted">Full Export enthaelt ggf. interne Tokens. Redacted Export ist zum Teilen gedacht.</p>
            <div class="form-actions">
              <a class="link-button" href="/admin/routes/export">Full Export</a>
              <a class="link-button secondary" href="/admin/routes/export?redacted=true">Redacted Export</a>
            </div>
            <div class="divider"></div>
            <form method="post" action="/admin/routes/import" enctype="multipart/form-data" class="small-form">
              <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
              <label for="routes_file">YAML-Datei importieren</label>
              <input id="routes_file" name="routes_file" type="file" accept=".yaml,.yml,text/yaml">
              <label for="routes_yaml">Oder YAML einfuegen</label>
              <textarea id="routes_yaml" name="routes_yaml" placeholder="routes: []"></textarea>
              <p class="helper">Import ersetzt die aktuelle Routen-Konfiguration nach erfolgreicher Validierung.</p>
              <button type="submit">Importieren</button>
            </form>
          </div>
        </details>
        <a class="link-button secondary" href="/">Public Dashboard</a>
        <a class="link-button secondary" href="/docs">Docs</a>
        <a class="link-button secondary" href="/account">Account</a>
      </div>
    </header>

    {{if .Notice}}<div class="notice">{{.Notice}}</div>{{end}}
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}

    <div class="summary">
      <div class="summary-card"><span class="muted">Public Base URL</span><strong>{{.PublicBaseURL}}</strong></div>
      <div class="summary-card"><span class="muted">Routes Config</span><strong>{{.RoutesPath}}</strong></div>
      <div class="summary-card"><span class="muted">Self-Signup</span><strong>{{if .SelfSignupEnabled}}Enabled{{else}}Disabled{{end}}</strong></div>
      <div class="summary-card"><span class="muted">Routes / Deployments</span><strong>{{len .Routes}} / {{len .Deployments}}</strong></div>
      <div class="summary-card"><span class="muted">Docker Management</span><strong>{{if .DockerEnabled}}Enabled{{else}}Disabled{{end}}</strong></div>
    </div>

    <nav class="tabs">
      <a class="tab {{if eq .ActiveTab "routes"}}active{{end}}" href="/admin">MCP-Routen</a>
      <a class="tab {{if eq .ActiveTab "deployments"}}active{{end}}" href="/admin?tab=deployments">Deployments</a>
      <a class="tab {{if eq .ActiveTab "users"}}active{{end}}" href="/admin?tab=users">Nutzer & Gruppen</a>
    </nav>

    {{if eq .ActiveTab "routes"}}
    <div class="layout">
      <section>
        <div class="toolbar" style="justify-content:space-between;">
          <div>
            <h2>MCP Routes</h2>
            <p class="muted">Oeffentliche Routen erscheinen im Katalog. Private Routen bleiben verborgen und sind nur per direkter URL fuer berechtigte Nutzer sichtbar.</p>
          </div>
          <a class="link-button secondary" href="/admin">Neue Route</a>
        </div>
        <div class="route-list">
          {{if .Routes}}
            {{range .Routes}}
              <article class="route-card">
                <div style="display:flex; justify-content:space-between; gap:1rem; align-items:flex-start;">
                  <div>
                    <h3>{{.DisplayName}}</h3>
                    <p class="muted"><code>{{.ID}}</code> at <code>{{.PathPrefix}}</code></p>
                  </div>
                  <div class="stack" style="gap:.35rem; justify-items:end;">
                    <span class="tag {{if eq .AccessVisibility "private"}}private{{end}}">{{.AccessVisibility}}</span>
                    <span class="tag">{{.AccessMode}}</span>
                  </div>
                </div>
                <div class="route-meta">
                  <span>Transport: <code>{{.Transport}}</code></span>
                  <span>MCP: <code>{{.PublicMCPURL}}</code></span>
                  <span>Docs: <code>{{.PublicMCPURL}}</code> -> <code>{{.PathPrefix}}/docs</code></span>
                  <span>Upstream: <code>{{.Upstream}}</code>{{if eq .Transport "http"}}<code>{{.UpstreamMCPPath}}</code>{{end}}</span>
                  <span>Headers: {{.ForwardHeadersCount}} | Env: {{.UpstreamEnvironmentCount}} | Pass Auth: {{if .PassAuthorization}}yes{{else}}no{{end}}</span>
                  {{if .MCPHTTPSessionMode}}<span>Session: <code>{{.MCPHTTPSessionMode}}</code></span>{{end}}
                </div>
                <div class="route-actions">
                  <a class="link-button secondary" href="/admin?route={{.ID}}">Bearbeiten</a>
                  <a class="link-button secondary" href="{{.PathPrefix}}/docs">Docs</a>
                </div>
              </article>
            {{end}}
          {{else}}
            <article class="route-card"><p>Noch keine MCP-Routen angelegt.</p></article>
          {{end}}
        </div>
      </section>

      <section>
        <h2>{{if .SelectedRoute.OriginalID}}Route bearbeiten{{else}}Route anlegen{{end}}</h2>
        <p class="muted">Die Route-ID ist optional. Wenn sie leer bleibt, erzeugt der Gateway sie aus dem Display Name oder Path Prefix.</p>
        <form method="post" action="/admin/routes/save" enctype="multipart/form-data" style="margin-top: 1rem;">
          <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
          <input type="hidden" name="original_id" value="{{.SelectedRoute.OriginalID}}">
          <div class="field-grid">
            <div>
              <label for="id">Route ID</label>
              <input id="id" name="id" type="text" value="{{.SelectedRoute.ID}}" placeholder="auto, z.B. german-legal">
              <p class="helper">Leer lassen fuer Autofill.</p>
            </div>
            <div>
              <label for="display_name">Display Name</label>
              <input id="display_name" name="display_name" type="text" value="{{.SelectedRoute.DisplayName}}" placeholder="German Legal">
            </div>
            <div>
              <label for="route_transport">Transport</label>
              <select id="route_transport" name="transport">
                <option value="http" {{if eq .SelectedRoute.Transport "http"}}selected{{end}}>HTTP / Streamable HTTP</option>
                <option value="stdio" {{if eq .SelectedRoute.Transport "stdio"}}selected{{end}}>Native STDIO</option>
                <option value="openapi" {{if eq .SelectedRoute.Transport "openapi"}}selected{{end}}>OpenAPI -> MCP Tools</option>
              </select>
            </div>
            <div>
              <label for="path_prefix">Path Prefix</label>
              <input id="path_prefix" name="path_prefix" type="text" value="{{.SelectedRoute.PathPrefix}}" placeholder="/german-legal">
            </div>
            <div>
              <label for="scopes_supported">Scopes</label>
              <input id="scopes_supported" name="scopes_supported" type="text" value="{{.SelectedRoute.ScopesSupported}}" placeholder="mcp">
            </div>
            <div class="full">
              <label for="upstream">Upstream Base URL</label>
              <input id="upstream" name="upstream" type="url" value="{{.SelectedRoute.Upstream}}" placeholder="http://n8n-mcp:8080">
              <p class="helper">Nur fuer HTTP-Routen erforderlich.</p>
            </div>
            <div>
              <label for="upstream_mcp_path">Upstream MCP Path</label>
              <input id="upstream_mcp_path" name="upstream_mcp_path" type="text" value="{{.SelectedRoute.UpstreamMCPPath}}" placeholder="/mcp">
            </div>
            <div class="full">
              <label for="notes">Notes / Beschreibung</label>
              <textarea id="notes" name="notes" placeholder="Kurzbeschreibung, Setup-Hinweise, Reverse-Proxy-Anforderungen...">{{.SelectedRoute.Notes}}</textarea>
            </div>
            <details class="advanced full">
              <summary>STDIO-Command</summary>
              <div class="field-grid" style="margin-top:.9rem;">
                <div class="full">
                  <label for="stdio_command">Executable / Command</label>
                  <input id="stdio_command" name="stdio_command" type="text" value="{{.SelectedRoute.StdioCommand}}" placeholder="/tools/portainer-mcp">
                </div>
                <div class="full">
                  <label for="stdio_args">Argumente</label>
                  <textarea id="stdio_args" name="stdio_args" placeholder="-server&#10;https://portainer:9443&#10;-token&#10;...">{{.SelectedRoute.StdioArgs}}</textarea>
                  <p class="helper">Ein Argument pro Zeile. Nur fuer STDIO-Routen.</p>
                </div>
                <div class="full">
                  <label for="stdio_env">STDIO Environment</label>
                  <textarea id="stdio_env" name="stdio_env" placeholder="ANNAS_SECRET_KEY=...&#10;ANNAS_DOWNLOAD_PATH=/data/downloads">{{.SelectedRoute.StdioEnv}}</textarea>
                </div>
                <div class="full">
                  <label for="stdio_working_dir">Working Directory</label>
                  <input id="stdio_working_dir" name="stdio_working_dir" type="text" value="{{.SelectedRoute.StdioWorkingDir}}" placeholder="/tools">
                </div>
              </div>
            </details>
            <details class="advanced full">
              <summary>OpenAPI Tool-Bridge</summary>
              <div class="field-grid" style="margin-top:.9rem;">
                <div class="full">
                  <label for="openapi_spec_file">OpenAPI Spec importieren</label>
                  <input id="openapi_spec_file" name="openapi_spec_file" type="file" accept=".yaml,.yml,.json,application/yaml,application/json">
                  <p class="helper">Optionaler Upload. Der Gateway prueft die Spec und speichert sie im konfigurierten OpenAPI Store.</p>
                </div>
                <div class="full">
                  <label for="openapi_spec_path">OpenAPI Spec Path</label>
                  <input id="openapi_spec_path" name="openapi_spec_path" type="text" value="{{.SelectedRoute.OpenAPISpecPath}}" placeholder="/data/openapi/example.yaml">
                  <p class="helper">Absoluter Pfad im Gateway-Container. Wird durch Upload automatisch befuellt.</p>
                </div>
                <div class="full">
                  <label for="openapi_spec_url">OpenAPI Spec URL</label>
                  <input id="openapi_spec_url" name="openapi_spec_url" type="url" value="{{.SelectedRoute.OpenAPISpecURL}}" placeholder="https://api.example.com/openapi.yaml">
                </div>
                <div class="full">
                  <label for="openapi_base_url">OpenAPI Base URL</label>
                  <input id="openapi_base_url" name="openapi_base_url" type="url" value="{{.SelectedRoute.OpenAPIBaseURL}}" placeholder="https://api.example.com">
                  <p class="helper">Ziel-API, gegen die die generierten Tools Requests ausfuehren.</p>
                </div>
                <div class="full">
                  <label for="openapi_headers">OpenAPI API Headers</label>
                  <textarea id="openapi_headers" name="openapi_headers" placeholder="Authorization: Bearer internal-api-token&#10;X-Api-Key: ...">{{.SelectedRoute.OpenAPIHeaders}}</textarea>
                </div>
                <div>
                  <label for="openapi_timeout_seconds">OpenAPI Timeout Sekunden</label>
                  <input id="openapi_timeout_seconds" name="openapi_timeout_seconds" type="text" value="{{.SelectedRoute.OpenAPITimeoutSeconds}}" placeholder="30">
                </div>
              </div>
            </details>
            <details class="advanced full">
              <summary>Erweiterte Einstellungen</summary>
              <div class="field-grid" style="margin-top:.9rem;">
                <div>
                  <label for="mcp_http_session_mode">MCP_HTTP_SESSION_MODE</label>
                  <input id="mcp_http_session_mode" name="mcp_http_session_mode" type="text" value="{{.SelectedRoute.MCPHTTPSessionMode}}" placeholder="stateful or stateless">
                </div>
                <div>
                  <label for="access_visibility">Katalog-Sichtbarkeit</label>
                  <select id="access_visibility" name="access_visibility">
                    <option value="public" {{if eq .SelectedRoute.AccessVisibility "public"}}selected{{end}}>Public im Dashboard</option>
                    <option value="private" {{if eq .SelectedRoute.AccessVisibility "private"}}selected{{end}}>Private/versteckt</option>
                  </select>
                </div>
                <div>
                  <label for="access_mode">Nutzungsrecht</label>
                  <select id="access_mode" name="access_mode">
                    <option value="public" {{if eq .SelectedRoute.AccessMode "public"}}selected{{end}}>Alle angemeldeten Nutzer</option>
                    <option value="restricted" {{if eq .SelectedRoute.AccessMode "restricted"}}selected{{end}}>Nur ausgewaehlte Nutzer/Gruppen</option>
                    <option value="admin" {{if eq .SelectedRoute.AccessMode "admin"}}selected{{end}}>Nur Admins</option>
                  </select>
                </div>
                <div>
                  <label for="resource_documentation">Resource Documentation URL</label>
                  <input id="resource_documentation" name="resource_documentation" type="url" value="{{.SelectedRoute.ResourceDocumentation}}" placeholder="https://github.com/your-server/docs">
                </div>
                <div class="full">
                  <details>
                    <summary>Berechtigungsmatrix fuer Nutzer und Gruppen</summary>
                    <p class="helper">Default nutzt den Modus oben. Allow gilt bei restricted Routen, Deny ist eine harte Sperre und gilt auch fuer Admins.</p>
                    <table class="access-table">
                      <thead>
                        <tr><th>Typ</th><th>Name</th><th>Berechtigung</th></tr>
                      </thead>
                      <tbody>
                        {{range .Groups}}
                          {{$decision := accessDecision $.SelectedRoute "group" .Name}}
                          <tr>
                            <td>Gruppe</td>
                            <td>{{.Name}}</td>
                            <td>
                              <input type="hidden" name="access_subject" value="group:{{.Name}}">
                              <select name="access_decision">
                                <option value="" {{if eq $decision ""}}selected{{end}}>Default</option>
                                <option value="allow" {{if eq $decision "allow"}}selected{{end}}>Allow</option>
                                <option value="deny" {{if eq $decision "deny"}}selected{{end}}>Deny</option>
                              </select>
                            </td>
                          </tr>
                        {{end}}
                        {{range .Users}}
                          {{$decision := accessDecision $.SelectedRoute "user" .Email}}
                          <tr>
                            <td>Nutzer</td>
                            <td>{{.Email}}</td>
                            <td>
                              <input type="hidden" name="access_subject" value="user:{{.Email}}">
                              <select name="access_decision">
                                <option value="" {{if eq $decision ""}}selected{{end}}>Default</option>
                                <option value="allow" {{if eq $decision "allow"}}selected{{end}}>Allow</option>
                                <option value="deny" {{if eq $decision "deny"}}selected{{end}}>Deny</option>
                              </select>
                            </td>
                          </tr>
                        {{end}}
                      </tbody>
                    </table>
                  </details>
                </div>
                <div class="full checkbox">
                  <input id="pass_authorization_header" name="pass_authorization_header" type="checkbox" {{if .SelectedRoute.PassAuthorization}}checked{{end}}>
                  <div>
                    <label for="pass_authorization_header" style="margin:0;">Inbound Authorization an Upstream weiterreichen</label>
                    <p class="helper">Aus lassen, wenn der Gateway interne Header wie <code>Authorization: Bearer ...</code> setzen soll.</p>
                  </div>
                </div>
                <div class="full">
                  <label for="forward_headers">Forward Headers</label>
                  <textarea id="forward_headers" name="forward_headers" placeholder="Authorization: Bearer internal-token&#10;X-MCP-User: {email}">{{.SelectedRoute.ForwardHeaders}}</textarea>
                </div>
                <div class="full">
                  <label for="upstream_environment">Upstream Environment Metadata</label>
                  <textarea id="upstream_environment" name="upstream_environment" placeholder="AUTH_TOKEN=replace-me&#10;PORT=8080">{{.SelectedRoute.UpstreamEnvironment}}</textarea>
                  <p class="helper">Nur Metadaten: Der Gateway startet Container in Phase 1 noch nicht selbst.</p>
                </div>
              </div>
            </details>
          </div>
          <div class="form-actions">
            <button type="submit">Route speichern</button>
            <a class="link-button secondary" href="/admin">Neue Route</a>
          </div>
        </form>
        {{if .SelectedRoute.OriginalID}}
          <form method="post" action="/admin/routes/delete">
            <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
            <input type="hidden" name="route_id" value="{{.SelectedRoute.OriginalID}}">
            <div class="form-actions"><button type="submit" class="danger">Route loeschen</button></div>
          </form>
        {{end}}
      </section>
    </div>
    {{else if eq .ActiveTab "deployments"}}

    <div class="layout">
      <section>
        <h2>Managed Deployments</h2>
        <p class="muted">Container werden nur verwaltet, wenn Docker Management aktiv ist und der Gateway Zugriff auf den Docker Host hat.</p>
        {{if .DockerError}}<div class="error" style="margin-top:1rem;">{{.DockerError}}</div>{{end}}
        <div class="route-list">
          {{if .Deployments}}
            {{range .Deployments}}
              <article class="route-card">
                <div style="display:flex; justify-content:space-between; gap:1rem; align-items:flex-start;">
                  <div>
                    <h3>{{.DisplayName}}</h3>
                    <p class="muted">{{if eq .Transport "stdio"}}Native STDIO fuer Route{{else}}<code>{{.ContainerName}}</code> fuer Route{{end}} <code>{{.RouteID}}</code></p>
                  </div>
                  <span class="tag {{if eq .State "running"}}{{else}}private{{end}}">{{.State}}</span>
                </div>
                <div class="route-meta">
                  <span>Transport: <code>{{.Transport}}</code></span>
                  {{if eq .Transport "stdio"}}
                    <span>Command: <code>{{.Command}}</code></span>
                  {{else}}
                    <span>Image: <code>{{.Image}}</code></span>
                    <span>Internal: <code>{{.ContainerName}}:{{.InternalPort}}</code></span>
                  {{end}}
                  <span>Upstream: <code>{{.Upstream}}</code></span>
                  <span>Remote MCP: <code>{{.PublicMCPURL}}</code></span>
                  {{if .Networks}}<span>Networks: <code>{{.Networks}}</code></span>{{end}}
                </div>
                <div class="route-actions">
                  {{if ne .Transport "stdio"}}
                    <form method="post" action="/admin/deployments/start">
                      <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                      <input type="hidden" name="route_id" value="{{.RouteID}}">
                      <button type="submit" class="secondary">Start</button>
                    </form>
                    <form method="post" action="/admin/deployments/stop">
                      <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                      <input type="hidden" name="route_id" value="{{.RouteID}}">
                      <button type="submit" class="secondary">Stop</button>
                    </form>
                    <form method="post" action="/admin/deployments/remove">
                      <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                      <input type="hidden" name="route_id" value="{{.RouteID}}">
                      <button type="submit" class="danger">Remove Container</button>
                    </form>
                  {{end}}
                  <a class="link-button secondary" href="/admin?route={{.RouteID}}">Route bearbeiten</a>
                </div>
              </article>
            {{end}}
          {{else}}
            <article class="route-card"><p>Noch keine vom Gateway verwalteten Deployments.</p></article>
          {{end}}
        </div>
      </section>

      <section>
        <h2>MCP Deployment anlegen</h2>
        {{if .DockerEnabled}}
          <p class="muted">Erzeugt entweder einen HTTP-MCP-Docker-Container oder eine native STDIO-Route im Gateway-Prozess.</p>
        {{else}}
          <p class="muted">Docker Management ist deaktiviert. Native STDIO-Routen funktionieren trotzdem, wenn das Executable im Gateway-Container vorhanden oder gemountet ist.</p>
        {{end}}
        <form method="post" action="/admin/deployments/create" style="margin-top:1rem;">
          <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
          <div class="field-grid">
            <div>
              <label for="deploy_transport">Transport</label>
              <select id="deploy_transport" name="transport">
                <option value="http" {{if eq .DeploymentForm.Transport "http"}}selected{{end}}>HTTP / Streamable HTTP Container</option>
                <option value="stdio" {{if eq .DeploymentForm.Transport "stdio"}}selected{{end}}>Native STDIO Command</option>
              </select>
              <p class="helper">STDIO startet der Gateway selbst pro MCP-Session. Kein extra Adapter-Container.</p>
            </div>
            <div>
              <label for="deploy_display_name">Display Name</label>
              <input id="deploy_display_name" name="display_name" type="text" value="{{.DeploymentForm.DisplayName}}" placeholder="n8n MCP">
            </div>
            <div>
              <label for="deploy_id">Route ID</label>
              <input id="deploy_id" name="id" type="text" value="{{.DeploymentForm.ID}}" placeholder="auto">
            </div>
            <div class="full">
              <label for="deploy_image">Docker Image</label>
              <input id="deploy_image" name="image" type="text" value="{{.DeploymentForm.Image}}" placeholder="ghcr.io/czlonkowski/n8n-mcp:latest">
              <p class="helper">Nur fuer HTTP-Container erforderlich.</p>
            </div>
            <div>
              <label for="deploy_container_name">Container Name</label>
              <input id="deploy_container_name" name="container_name" type="text" value="{{.DeploymentForm.ContainerName}}" placeholder="auto aus Route ID">
            </div>
            <div>
              <label for="deploy_internal_port">Interner Port</label>
              <input id="deploy_internal_port" name="internal_port" type="text" value="{{.DeploymentForm.InternalPort}}" placeholder="8080">
            </div>
            <div>
              <label for="deploy_path_prefix">Path Prefix</label>
              <input id="deploy_path_prefix" name="path_prefix" type="text" value="{{.DeploymentForm.PathPrefix}}" placeholder="/n8n">
            </div>
            <div>
              <label for="deploy_upstream_mcp_path">Upstream MCP Path</label>
              <input id="deploy_upstream_mcp_path" name="upstream_mcp_path" type="text" value="{{.DeploymentForm.UpstreamMCPPath}}" placeholder="/mcp">
            </div>
            <details class="advanced full">
              <summary>Container-Details</summary>
              <div class="field-grid" style="margin-top:.9rem;">
                <div>
                  <label for="deploy_scopes">Scopes</label>
                  <input id="deploy_scopes" name="scopes_supported" type="text" value="{{.DeploymentForm.ScopesSupported}}" placeholder="mcp">
                </div>
                <div>
                  <label for="deploy_restart_policy">Restart Policy</label>
                  <input id="deploy_restart_policy" name="restart_policy" type="text" value="{{.DeploymentForm.RestartPolicy}}" placeholder="unless-stopped">
                </div>
                <div class="full">
                  <label for="deploy_networks">Docker Networks</label>
                  <textarea id="deploy_networks" name="networks" placeholder="mcp-shared&#10;mcp-internal">{{.DeploymentForm.Networks}}</textarea>
                  <p class="helper">Mindestens ein gemeinsames Docker-Netz mit dem Gateway ist empfohlen, damit <code>http://container:port</code> aufloest.</p>
                </div>
                <div class="full">
                  <label for="deploy_environment">Environment</label>
                  <textarea id="deploy_environment" name="environment" placeholder="MCP_MODE=http&#10;PORT=8080">{{.DeploymentForm.Environment}}</textarea>
                </div>
                <div class="full">
                  <label for="deploy_resource_documentation">Resource Documentation URL</label>
                  <input id="deploy_resource_documentation" name="resource_documentation" type="url" value="{{.DeploymentForm.ResourceDocumentation}}" placeholder="https://github.com/example/mcp">
                </div>
                <div class="full">
                  <label for="deploy_notes">Notes</label>
                  <textarea id="deploy_notes" name="notes" placeholder="Deployment-Hinweise...">{{.DeploymentForm.Notes}}</textarea>
                </div>
              </div>
            </details>
            <details class="advanced full">
              <summary>STDIO-Command</summary>
              <div class="field-grid" style="margin-top:.9rem;">
                <div class="full">
                  <label for="deploy_stdio_command">Executable / Command</label>
                  <input id="deploy_stdio_command" name="stdio_command" type="text" value="{{.DeploymentForm.StdioCommand}}" placeholder="/tools/portainer-mcp">
                  <p class="helper">Pfad oder Command, der innerhalb des Gateway-Containers existiert. Fuer Host-Dateien bitte als Volume in den Gateway mounten.</p>
                </div>
                <div class="full">
                  <label for="deploy_stdio_args">Argumente</label>
                  <textarea id="deploy_stdio_args" name="stdio_args" placeholder="-server&#10;https://portainer:9443&#10;-token&#10;...">{{.DeploymentForm.StdioArgs}}</textarea>
                  <p class="helper">Ein Argument pro Zeile. Leerzeichen werden nicht gesplittet.</p>
                </div>
                <div class="full">
                  <label for="deploy_stdio_env">STDIO Environment</label>
                  <textarea id="deploy_stdio_env" name="stdio_env" placeholder="ANNAS_SECRET_KEY=...&#10;ANNAS_DOWNLOAD_PATH=/data/downloads">{{.DeploymentForm.StdioEnv}}</textarea>
                </div>
                <div class="full">
                  <label for="deploy_stdio_working_dir">Working Directory</label>
                  <input id="deploy_stdio_working_dir" name="stdio_working_dir" type="text" value="{{.DeploymentForm.StdioWorkingDir}}" placeholder="/tools">
                </div>
              </div>
            </details>
          </div>
          <div class="form-actions">
            <button type="submit">Deployment erstellen & Route anlegen</button>
          </div>
        </form>
        <div class="divider"></div>
        <h2>STDIO MCP installieren</h2>
        {{if .StdioInstallEnabled}}
          <p class="muted">Installiert fertige STDIO-MCP-Artefakte nach <code>{{.StdioInstallStore}}</code>. Maximalgroesse: {{.StdioInstallMaxMB}} MB. Env-Werte werden verschluesselt im Auth-Store gespeichert.</p>
        {{else}}
          <p class="muted">Der STDIO Installer ist deaktiviert. Setze <code>MCP_GATEWAY_STDIO_INSTALL_ENABLED=true</code>, wenn Admins Uploads, GitHub-Releases oder Download-Links installieren duerfen.</p>
        {{end}}
        <form method="post" action="/admin/stdio/install" enctype="multipart/form-data" style="margin-top:1rem;">
          <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
          <div class="field-grid">
            <div>
              <label for="stdio_install_source_kind">Quelle</label>
              <select id="stdio_install_source_kind" name="stdio_install_source_kind">
                <option value="github" {{if eq .StdioInstallForm.SourceKind "github"}}selected{{end}}>GitHub Release</option>
                <option value="url" {{if eq .StdioInstallForm.SourceKind "url"}}selected{{end}}>HTTPS Download</option>
                <option value="upload" {{if eq .StdioInstallForm.SourceKind "upload"}}selected{{end}}>File Upload</option>
              </select>
            </div>
            <div>
              <label for="stdio_install_id">Route ID</label>
              <input id="stdio_install_id" name="stdio_install_id" type="text" value="{{.StdioInstallForm.ID}}" placeholder="annas">
            </div>
            <div>
              <label for="stdio_install_display_name">Display Name</label>
              <input id="stdio_install_display_name" name="stdio_install_display_name" type="text" value="{{.StdioInstallForm.DisplayName}}" placeholder="Anna's MCP">
            </div>
            <div>
              <label for="stdio_install_path_prefix">Path Prefix</label>
              <input id="stdio_install_path_prefix" name="stdio_install_path_prefix" type="text" value="{{.StdioInstallForm.PathPrefix}}" placeholder="/annas">
            </div>
            <div>
              <label for="stdio_install_scopes">Scopes</label>
              <input id="stdio_install_scopes" name="stdio_install_scopes_supported" type="text" value="{{.StdioInstallForm.ScopesSupported}}" placeholder="mcp">
            </div>
            <div class="full">
              <label for="stdio_install_github_repo">GitHub Repo URL</label>
              <input id="stdio_install_github_repo" name="stdio_install_github_repo" type="url" value="{{.StdioInstallForm.GitHubRepo}}" placeholder="https://github.com/iosifache/annas-mcp">
            </div>
            <div>
              <label for="stdio_install_github_version">GitHub Version</label>
              <input id="stdio_install_github_version" name="stdio_install_github_version" type="text" value="{{.StdioInstallForm.GitHubVersion}}" placeholder="latest oder v0.0.5">
            </div>
            <div>
              <label for="stdio_install_asset_pattern">Asset Pattern</label>
              <input id="stdio_install_asset_pattern" name="stdio_install_asset_pattern" type="text" value="{{.StdioInstallForm.AssetPattern}}" placeholder="linux_amd64">
              <p class="helper">Leer nutzt automatisch linux_amd64, linux_arm64 usw. passend zur Gateway-Architektur.</p>
            </div>
            <div class="full">
              <label for="stdio_install_download_url">HTTPS Download URL</label>
              <input id="stdio_install_download_url" name="stdio_install_download_url" type="url" value="{{.StdioInstallForm.DownloadURL}}" placeholder="https://github.com/org/repo/releases/download/v1/server_linux_amd64.tar.xz">
            </div>
            <div class="full">
              <label for="stdio_install_file">Artefakt hochladen</label>
              <input id="stdio_install_file" name="stdio_install_file" type="file">
            </div>
            <div class="full">
              <label for="stdio_install_sha256">SHA-256</label>
              <input id="stdio_install_sha256" name="stdio_install_sha256" type="text" value="{{.StdioInstallForm.SHA256}}" placeholder="optional bei GitHub mit digest, Pflicht fuer Download URL">
            </div>
            <div>
              <label for="stdio_install_extract_mode">Entpacken</label>
              <select id="stdio_install_extract_mode" name="stdio_install_extract_mode">
                <option value="auto" {{if eq .StdioInstallForm.ExtractMode "auto"}}selected{{end}}>Auto</option>
                <option value="none" {{if eq .StdioInstallForm.ExtractMode "none"}}selected{{end}}>Nicht entpacken</option>
                <option value="tar.gz" {{if eq .StdioInstallForm.ExtractMode "tar.gz"}}selected{{end}}>tar.gz</option>
                <option value="tar.xz" {{if eq .StdioInstallForm.ExtractMode "tar.xz"}}selected{{end}}>tar.xz</option>
                <option value="zip" {{if eq .StdioInstallForm.ExtractMode "zip"}}selected{{end}}>zip</option>
              </select>
            </div>
            <div>
              <label for="stdio_install_executable_path">Executable im Archiv</label>
              <input id="stdio_install_executable_path" name="stdio_install_executable_path" type="text" value="{{.StdioInstallForm.ExecutablePath}}" placeholder="annas-mcp oder path/in/archive/annas-mcp">
            </div>
            <div class="full">
              <label for="stdio_install_args">Start-Argumente</label>
              <textarea id="stdio_install_args" name="stdio_install_args" placeholder="mcp">{{.StdioInstallForm.Args}}</textarea>
              <p class="helper">Ein Argument pro Zeile. Fuer iosifache/annas-mcp: <code>mcp</code>.</p>
            </div>
            <div class="full">
              <label>Zusatzordner</label>
              <table class="access-table">
                <thead><tr><th>Relativer Ordner unter der Installation</th></tr></thead>
                <tbody>
                  {{range .StdioInstallForm.ExtraFolders}}
                    <tr><td><input name="stdio_install_folder" type="text" value="{{.}}" placeholder="downloads"></td></tr>
                  {{end}}
                </tbody>
              </table>
              <p class="helper">Leer lassen, wenn keine Ordner benoetigt werden. Absolute Pfade und <code>..</code> werden abgelehnt.</p>
            </div>
            <div class="full">
              <label>Environment Secrets</label>
              <table class="access-table">
                <thead><tr><th>Name</th><th>Wert</th></tr></thead>
                <tbody>
                  {{range $idx, $name := .StdioInstallForm.EnvNames}}
                    <tr>
                      <td><input name="stdio_install_env_name" type="text" value="{{$name}}" placeholder="ANNAS_SECRET_KEY"></td>
                      <td><input name="stdio_install_env_value" type="password" value="{{index $.StdioInstallForm.EnvValues $idx}}" placeholder="verschluesselt gespeichert"></td>
                    </tr>
                  {{end}}
                </tbody>
              </table>
              <p class="helper">Diese Werte landen nicht in <code>routes.yaml</code>, sondern verschluesselt in <code>auth-store.enc</code> und werden erst beim STDIO-Prozessstart injiziert.</p>
            </div>
          </div>
          <div class="form-actions">
            <button type="submit">STDIO MCP installieren & Route anlegen</button>
          </div>
        </form>
        <div class="divider"></div>
        <h2>Image aus Artefakt bauen</h2>
        {{if .BuildEnabled}}
          <p class="muted">Builds sind aktiv. Downloads sind auf erlaubte Hosts beschraenkt: <code>{{.BuildHosts}}</code>. Maximalgroesse: {{.BuildMaxMB}} MB.</p>
        {{else}}
          <p class="muted">Builds sind deaktiviert. Setze <code>MCP_GATEWAY_BUILD_ENABLED=true</code>, wenn Admins verifizierte Artefakte in eigene Images bauen duerfen.</p>
        {{end}}
        <form method="post" action="/admin/artifacts/build" enctype="multipart/form-data" style="margin-top:1rem;">
          <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
          <div class="field-grid">
            <div>
              <label for="build_source_kind">Quelle</label>
              <select id="build_source_kind" name="source_kind">
                <option value="url" {{if eq .BuildForm.SourceKind "url"}}selected{{end}}>HTTPS Download</option>
                <option value="upload" {{if eq .BuildForm.SourceKind "upload"}}selected{{end}}>File Upload</option>
              </select>
            </div>
            <div>
              <label for="build_image_tag">Image Tag</label>
              <input id="build_image_tag" name="image_tag" type="text" value="{{.BuildForm.ImageTag}}" placeholder="local/portainer-mcp:0.7.0">
            </div>
            <div class="full">
              <label for="build_download_url">GitHub Release / HTTPS URL</label>
              <input id="build_download_url" name="download_url" type="url" value="{{.BuildForm.DownloadURL}}" placeholder="https://github.com/org/repo/releases/download/v1/server-linux-amd64.tar.gz">
              <p class="helper">Nur HTTPS. Standardmaessig sind GitHub-Release-Hosts erlaubt; private/LAN-Ziele werden blockiert, wenn freie Hosts aktiviert werden.</p>
            </div>
            <div class="full">
              <label for="build_artifact_file">Artefakt hochladen</label>
              <input id="build_artifact_file" name="artifact_file" type="file">
            </div>
            <div class="full">
              <label for="build_sha256">SHA-256 Checksum</label>
              <input id="build_sha256" name="sha256" type="text" value="{{.BuildForm.SHA256}}" placeholder="64 hex chars oder sha256:...">
              <p class="helper">Pflicht fuer Upload und Download. Verifiziert wird das Originalartefakt vor dem Entpacken.</p>
            </div>
            <div>
              <label for="build_extract_mode">Entpacken</label>
              <select id="build_extract_mode" name="extract_mode">
                <option value="none" {{if eq .BuildForm.ExtractMode "none"}}selected{{end}}>Nicht entpacken</option>
                <option value="tar.gz" {{if eq .BuildForm.ExtractMode "tar.gz"}}selected{{end}}>tar.gz</option>
                <option value="zip" {{if eq .BuildForm.ExtractMode "zip"}}selected{{end}}>zip</option>
              </select>
            </div>
            <div>
              <label for="build_artifact_path">Pfad im Archiv</label>
              <input id="build_artifact_path" name="artifact_path" type="text" value="{{.BuildForm.ArtifactPath}}" placeholder="portainer-mcp">
              <p class="helper">Pflicht bei Archiven. Absolute Pfade, Symlinks und Traversal werden abgelehnt.</p>
            </div>
            <div>
              <label for="build_base_image">Base Image</label>
              <input id="build_base_image" name="base_image" type="text" value="{{.BuildForm.BaseImage}}" placeholder="debian:bookworm-slim">
              <p class="helper">Erlaubt: <code>{{.BuildBaseImages}}</code></p>
            </div>
            <div class="full">
              <label for="build_entrypoint_args">Feste Start-Argumente</label>
              <textarea id="build_entrypoint_args" name="entrypoint_args" placeholder="mcp&#10;--port&#10;8080">{{.BuildForm.EntrypointArgs}}</textarea>
              <p class="helper">Optional, ein Argument pro Zeile. Wird als JSON-ENTRYPOINT erzeugt, nicht als Shell-Command.</p>
            </div>
            <div>
              <label for="build_internal_port">EXPOSE Port</label>
              <input id="build_internal_port" name="internal_port" type="text" value="{{.BuildForm.InternalPort}}" placeholder="8080">
            </div>
          </div>
          <div class="form-actions">
            <button type="submit">Verifizieren & Image bauen</button>
          </div>
          <p class="helper">Der Dockerfile-Inhalt wird vom Gateway erzeugt. Es werden keine frei eingegebenen Shell-Kommandos in den Build uebernommen.</p>
        </form>
      </section>
    </div>
    {{else if eq .ActiveTab "users"}}

    <div class="grid" style="margin-top: 1rem;">
      <section>
        <h2>Benutzer</h2>
        <p class="muted">Schlanke Uebersicht. Details, Gruppen, Passwort und registrierte Clients oeffnest du pro Nutzer.</p>
        <table class="data-table">
          <thead>
            <tr>
              <th>Email</th>
              <th>Rolle</th>
              <th>Gruppen</th>
              <th>Clients</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
          {{range .Users}}
            <tr>
              <td><strong>{{.Email}}</strong><br><span class="muted"><code>{{.ID}}</code></span></td>
              <td>{{if .IsAdmin}}<span class="pill">Admin</span>{{else}}Nutzer{{end}}</td>
              <td>{{if .Groups}}{{.Groups}}{{else}}<span class="muted">keine</span>{{end}}</td>
              <td>{{.DeviceCount}}</td>
              <td><a class="link-button secondary" href="/admin?tab=users&user={{.ID}}">Details</a></td>
            </tr>
          {{else}}
            <tr><td colspan="5" class="muted">Noch keine Nutzer vorhanden.</td></tr>
          {{end}}
          </tbody>
        </table>

        {{with .SelectedUser}}
          {{$selected := .}}
          <article class="user-card detail-panel">
            <div style="display:flex; justify-content:space-between; gap:1rem; align-items:flex-start;">
              <div>
                <h3>{{.Email}}</h3>
                <div class="user-meta">
                  <span>ID: <code>{{.ID}}</code></span>
                  <span>Gruppen: {{if .Groups}}{{.Groups}}{{else}}keine{{end}}</span>
                  <span>Created: {{.CreatedAt}} | Updated: {{.UpdatedAt}}</span>
                </div>
              </div>
              {{if .IsAdmin}}<span class="pill">Admin</span>{{end}}
            </div>

            <details class="advanced" open style="margin-top:1rem;">
              <summary>Nutzerrechte und Gruppen</summary>
              <div class="stack" style="margin-top:.9rem;">
                <form method="post" action="/admin/users/groups" class="small-form">
                  <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                  <input type="hidden" name="user_id" value="{{.ID}}">
                  <label>Gruppen</label>
                  <div class="picker-grid">
                    {{range $.Groups}}
                      <label class="checkline"><input type="checkbox" name="group_ids" value="{{.ID}}" {{if has $selected.GroupIDs .ID}}checked{{end}}> {{.Name}}</label>
                    {{else}}
                      <p class="muted">Noch keine Gruppen angelegt.</p>
                    {{end}}
                  </div>
                  <button type="submit" class="secondary">Gruppen speichern</button>
                </form>

                <form method="post" action="/admin/users/admin" class="small-form">
                  <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                  <input type="hidden" name="user_id" value="{{.ID}}">
                  <input type="hidden" name="is_admin" value="{{if .IsAdmin}}false{{else}}true{{end}}">
                  <button type="submit" class="secondary">{{if .IsAdmin}}Admin-Rolle entfernen{{else}}Admin-Rolle geben{{end}}</button>
                </form>
              </div>
            </details>

            <details class="advanced" style="margin-top:1rem;">
              <summary>Passwort und Konto</summary>
              <div class="stack" style="margin-top:.9rem;">
                <form method="post" action="/admin/users/password" class="small-form">
                  <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                  <input type="hidden" name="user_id" value="{{.ID}}">
                  <label for="password_{{.ID}}">Passwort zuruecksetzen</label>
                  <input id="password_{{.ID}}" name="password" type="password" minlength="10" placeholder="Neues Passwort" required>
                  <button type="submit" class="secondary">Passwort setzen</button>
                </form>

                <form method="post" action="/admin/users/delete" class="small-form">
                  <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                  <input type="hidden" name="user_id" value="{{.ID}}">
                  <button type="submit" class="danger">Nutzer loeschen</button>
                </form>
              </div>
            </details>

            <details class="advanced" open style="margin-top:1rem;">
              <summary>Registrierte Clients / Geraete</summary>
              {{if .Devices}}
                <table class="data-table">
                  <thead><tr><th>Client</th><th>Resource</th><th>Zuletzt</th><th>Gueltig bis</th><th></th></tr></thead>
                  <tbody>
                    {{range .Devices}}
                      <tr>
                        <td><strong>{{.ClientName}}</strong><br><span class="muted"><code>{{.ClientID}}</code></span></td>
                        <td><code>{{.Resource}}</code><br><span class="muted">Scopes: {{.Scope}} | Tokens: {{.TokenCount}}</span></td>
                        <td>{{.LastUsedAt}}</td>
                        <td>{{.RefreshExpiresAt}}</td>
                        <td>
                          <form method="post" action="/admin/users/devices/delete">
                            <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                            <input type="hidden" name="user_id" value="{{$selected.ID}}">
                            <input type="hidden" name="device_id" value="{{.ID}}">
                            <button type="submit" class="danger">Widerrufen</button>
                          </form>
                        </td>
                      </tr>
                    {{end}}
                  </tbody>
                </table>
              {{else}}
                <p class="muted" style="margin-top:.8rem;">Dieser Nutzer hat noch keine OAuth-Clients autorisiert.</p>
              {{end}}
            </details>
          </article>
        {{else}}
          <article class="mini-card detail-panel"><p class="muted">Waehle einen Nutzer aus, um Gruppen, Rolle, Passwort und registrierte Clients zu verwalten.</p></article>
        {{end}}
      </section>

      <section class="stack">
        <div>
          <h2>Gruppen</h2>
          <p class="muted">Gruppen dienen als wiederverwendbare Berechtigungslisten fuer MCP-Routen.</p>
        </div>
        <form method="post" action="/admin/groups/create" class="small-form">
          <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
          <label for="group_name">Neue Gruppe</label>
          <input id="group_name" name="name" type="text" placeholder="Legal Team" required>
          <button type="submit">Gruppe anlegen</button>
        </form>
        <div class="stack">
          {{range .Groups}}
            <article class="mini-card">
              <h3>{{.Name}}</h3>
              <div class="mini-meta">
                <span>ID: <code>{{.ID}}</code></span>
                <span>Members: {{.MemberCount}}</span>
              </div>
              <form method="post" action="/admin/groups/delete" class="small-form">
                <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                <input type="hidden" name="group_id" value="{{.ID}}">
                <button type="submit" class="danger">Gruppe loeschen</button>
              </form>
            </article>
          {{else}}
            <article class="mini-card"><p class="muted">Noch keine Gruppen angelegt.</p></article>
          {{end}}
        </div>

        <div class="divider"></div>

        <div>
          <h2>Neuen Nutzer anlegen</h2>
          <p class="muted">Auch moeglich, wenn Self-Signup deaktiviert ist.</p>
        </div>
        <form method="post" action="/admin/users/create" class="small-form">
          <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
          <label for="user_email">Email</label>
          <input id="user_email" name="email" type="email" required>
          <label for="user_password">Passwort</label>
          <input id="user_password" name="password" type="password" minlength="10" required>
          <label class="checkbox"><input id="user_is_admin" name="is_admin" type="checkbox"> Admin-Rechte direkt vergeben</label>
          <button type="submit">Nutzer anlegen</button>
        </form>
      </section>
    </div>

    {{end}}
  </main>
</body>
</html>
`
