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
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/webui"
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
	ShowRouteEditor     bool
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
	UpstreamBearerConfigured bool
	UserUpstreamBearerCount  int
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
	UpstreamBearerToken   string
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
	OriginalID                   string
	ID                           string
	DisplayName                  string
	Transport                    string
	PathPrefix                   string
	Upstream                     string
	UpstreamMCPPath              string
	ScopesSupported              string
	PassAuthorization            bool
	ResourceDocumentation        string
	MCPHTTPSessionMode           string
	AccessVisibility             string
	AccessMode                   string
	AllowedUsers                 []string
	AllowedGroups                []string
	DeniedUsers                  []string
	DeniedGroups                 []string
	ForwardHeaders               string
	UpstreamEnvironment          string
	UpstreamBearerToken          string
	ClearUpstreamBearer          bool
	UpstreamBearerConfigured     bool
	UserUpstreamBearerConfigured map[string]bool
	StdioCommand                 string
	StdioArgs                    string
	StdioEnv                     string
	StdioWorkingDir              string
	OpenAPISpecPath              string
	OpenAPISpecURL               string
	OpenAPIBaseURL               string
	OpenAPIHeaders               string
	OpenAPITimeoutSeconds        string
	Notes                        string
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
	if err := s.authManager.RenameRouteSecrets(formData.OriginalID, route.ID); err != nil {
		s.renderAdminDashboard(w, r, identity, formData, "", err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.saveRouteUpstreamBearerForm(r, route.ID); err != nil {
		s.renderAdminDashboard(w, r, identity, formData, "", err.Error(), http.StatusBadRequest)
		return
	}

	notice := "Route saved successfully"
	switch next := strings.TrimSpace(r.FormValue("next_route")); next {
	case "":
		http.Redirect(w, r, adminRedirectURL(route.ID, notice, ""), http.StatusFound)
	case routeEditorBrowseSentinel:
		http.Redirect(w, r, adminRedirectURL("", notice, ""), http.StatusFound)
	case routeEditorNewSentinel:
		http.Redirect(w, r, "/admin?new=1&notice="+url.QueryEscape(notice), http.StatusFound)
	default:
		http.Redirect(w, r, adminRedirectURL(next, notice, ""), http.StatusFound)
	}
}

// The route editor's "next_route" hidden field carries the id of the route
// to continue to after a "save, then switch" action; these two sentinel
// values cover the two destinations that are not an existing route id.
const (
	routeEditorBrowseSentinel = "__browse__"
	routeEditorNewSentinel    = "__new__"
)

func (s *Server) saveRouteUpstreamBearerForm(r *http.Request, routeID string) error {
	token := strings.TrimSpace(r.FormValue("upstream_bearer_token"))
	clearGlobal := formCheckbox(r, "clear_upstream_bearer")
	if token != "" {
		if err := s.authManager.SetRouteUpstreamBearer(routeID, token); err != nil {
			return err
		}
	} else if clearGlobal {
		if err := s.authManager.SetRouteUpstreamBearer(routeID, ""); err != nil {
			return err
		}
	}

	clearUsers := map[string]bool{}
	for _, userID := range r.Form["clear_user_upstream_bearer"] {
		clearUsers[strings.TrimSpace(userID)] = true
	}
	userIDs := r.Form["upstream_bearer_user_id"]
	userTokens := r.Form["upstream_bearer_user_token"]
	for idx, userID := range userIDs {
		userID = strings.TrimSpace(userID)
		if userID == "" {
			continue
		}
		token := ""
		if idx < len(userTokens) {
			token = strings.TrimSpace(userTokens[idx])
		}
		switch {
		case token != "":
			if err := s.authManager.SetRouteUserUpstreamBearer(routeID, userID, token); err != nil {
				return err
			}
		case clearUsers[userID]:
			if err := s.authManager.SetRouteUserUpstreamBearer(routeID, userID, ""); err != nil {
				return err
			}
		}
	}
	return nil
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
	if formData.UpstreamBearerToken != "" {
		if err := s.authManager.SetRouteUpstreamBearer(route.ID, formData.UpstreamBearerToken); err != nil {
			s.renderAdminDashboard(w, r, identity, newEmptyRouteFormData(), "", err.Error(), http.StatusBadRequest)
			return
		}
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
	http.Redirect(w, r, adminRedirectURLWithTab("build", "", notice, ""), http.StatusFound)
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
	http.Redirect(w, r, adminRedirectURLWithTab("build", route.ID, notice, ""), http.StatusFound)
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
	s.decorateRouteSecretFormData(&selected)
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
		globalBearer, userBearers := s.authManager.RouteUpstreamBearerConfigured(route.ID)
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
			UpstreamBearerConfigured: globalBearer,
			UserUpstreamBearerCount:  len(userBearers),
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
		ShowRouteEditor:     errText != "" || len(routes) == 0 || strings.TrimSpace(r.URL.Query().Get("route")) != "" || r.URL.Query().Get("new") == "1",
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

func (s *Server) decorateRouteSecretFormData(form *routeFormData) {
	if form == nil {
		return
	}
	routeID := strings.TrimSpace(form.OriginalID)
	if routeID == "" {
		routeID = strings.TrimSpace(form.ID)
	}
	if routeID == "" {
		return
	}
	globalBearer, userBearers := s.authManager.RouteUpstreamBearerConfigured(routeID)
	form.UpstreamBearerConfigured = globalBearer
	form.UserUpstreamBearerConfigured = userBearers
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
		UpstreamBearerToken:   strings.TrimSpace(r.FormValue("upstream_bearer_token")),
		ClearUpstreamBearer:   formCheckbox(r, "clear_upstream_bearer"),
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
		UpstreamBearerToken:   strings.TrimSpace(r.FormValue("deployment_upstream_bearer_token")),
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
	applyKnownDeploymentDefaults(&formData)

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

func applyKnownDeploymentDefaults(formData *deploymentFormData) {
	if formData == nil || formData.Transport != "http" || !isN8NMCPImage(formData.Image) {
		return
	}

	envPort := envLineValue(formData.Environment, "PORT")
	port := "3000"
	if isPortString(envPort) {
		port = envPort
	}
	if formData.InternalPort == "" || formData.InternalPort == "8080" {
		formData.InternalPort = port
	}
	formData.Environment = ensureEnvLine(formData.Environment, "MCP_MODE", "http")
	formData.Environment = ensureEnvLine(formData.Environment, "PORT", port)
	if formData.ResourceDocumentation == "" {
		formData.ResourceDocumentation = "https://github.com/czlonkowski/n8n-mcp"
	}
	if formData.Notes == "" {
		formData.Notes = "n8n-mcp nutzt intern standardmaessig Port 3000. Wenn AUTH_TOKEN im Container gesetzt ist, denselben Wert als Gateway Upstream Bearer speichern."
	}
}

func isN8NMCPImage(image string) bool {
	image = strings.ToLower(strings.TrimSpace(image))
	return strings.Contains(image, "czlonkowski/n8n-mcp") || strings.Contains(image, "/n8n-mcp") || strings.HasPrefix(image, "n8n-mcp")
}

func isPortString(value string) bool {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	return err == nil && port > 0 && port <= 65535
}

func envLineValue(raw string, key string) string {
	key = strings.TrimSpace(key)
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := splitKeyValueLine(line, "env")
		if ok && name == key {
			return value
		}
	}
	return ""
}

func ensureEnvLine(raw string, key string, value string) string {
	if envLineValue(raw, key) != "" {
		return normalizeMultiline(raw)
	}
	line := key + "=" + value
	raw = normalizeMultiline(raw)
	if raw == "" {
		return line
	}
	return raw + "\n" + line
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
	if strings.HasPrefix(r.URL.Path, "/admin/artifacts") || strings.HasPrefix(r.URL.Path, "/admin/stdio") {
		return "build"
	}
	if strings.HasPrefix(r.URL.Path, "/admin/users") || strings.HasPrefix(r.URL.Path, "/admin/groups") {
		return "users"
	}
	tab := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tab")))
	switch tab {
	case "deployments", "users", "build":
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

func upstreamBearerConfigured(form routeFormData, userID string) bool {
	if len(form.UserUpstreamBearerConfigured) == 0 {
		return false
	}
	return form.UserUpstreamBearerConfigured[userID]
}

func renderAdminHTML(w http.ResponseWriter, status int, data dashboardData) {
	t := template.Must(template.New("admin").Funcs(template.FuncMap{
		"accessDecision":           accessDecision,
		"has":                      hasString,
		"upstreamBearerConfigured": upstreamBearerConfigured,
	}).Parse(adminDashboardTemplate))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
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
  ` + webui.GoogleFonts + `
  ` + webui.Style + `
</head>
<body>
  <div class="admin-shell">
    <aside class="admin-rail">
      <a class="wordmark" href="/admin"><span class="mark">GW</span> {{.Title}}</a>
      <div class="rail-group">
        <div class="rail-title">Steuerung</div>
        <a class="rail-link {{if eq .ActiveTab "routes"}}is-active{{end}}" href="/admin">MCP-Routen</a>
        <a class="rail-link {{if eq .ActiveTab "deployments"}}is-active{{end}}" href="/admin?tab=deployments">Deployments</a>
        <a class="rail-link {{if eq .ActiveTab "build"}}is-active{{end}}" href="/admin?tab=build">Build &amp; Stdio</a>
      </div>
      <div class="rail-group">
        <div class="rail-title">Zugriff</div>
        <a class="rail-link {{if eq .ActiveTab "users"}}is-active{{end}}" href="/admin?tab=users">Nutzer &amp; Gruppen</a>
      </div>
      <div class="rail-group">
        <div class="rail-title">Werkzeuge</div>
        <details>
          <summary style="font-size:.86rem; padding:.5rem;">Import / Export</summary>
          <div class="stack-sm" style="margin-top:.7rem;">
            <p class="hint">Full Export enth&auml;lt ggf. interne Tokens. Redacted Export ist zum Teilen gedacht.</p>
            <div class="cluster">
              <a class="btn btn-sm" href="/admin/routes/export">Full Export</a>
              <a class="btn btn-sm btn-ghost" href="/admin/routes/export?redacted=true">Redacted</a>
            </div>
            <hr>
            <form method="post" action="/admin/routes/import" enctype="multipart/form-data" class="stack-sm">
              <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
              <div class="field" style="margin-top:0;">
                <label for="routes_file">YAML-Datei importieren</label>
                <input id="routes_file" name="routes_file" type="file" accept=".yaml,.yml,text/yaml">
              </div>
              <div class="field">
                <label for="routes_yaml">Oder YAML einf&uuml;gen</label>
                <textarea id="routes_yaml" name="routes_yaml" placeholder="routes: []" rows="3"></textarea>
                <p class="hint">Ersetzt die aktuelle Routen-Konfiguration nach erfolgreicher Validierung.</p>
              </div>
              <button type="submit" class="btn btn-sm">Importieren</button>
            </form>
          </div>
        </details>
      </div>
      <div class="rail-foot">
        <div class="cluster">
          <a class="navlink" style="padding:0;" href="/">Katalog</a>
          <a class="navlink" style="padding:0;" href="/docs">Docs</a>
          <a class="navlink" style="padding:0;" href="/account">Account</a>
        </div>
        <div class="mono" style="margin-top:.5rem;">{{.AdminEmail}}</div>
      </div>
    </aside>
    <div class="admin-main">
      <div class="admin-topbar">
        <div class="breadcrumb">Admin <span>/</span> <strong>{{if eq .ActiveTab "deployments"}}Deployments{{else if eq .ActiveTab "build"}}Build &amp; Stdio{{else if eq .ActiveTab "users"}}Nutzer &amp; Gruppen{{else}}Routes{{end}}</strong></div>
      </div>
      <div class="admin-content">

    {{if .Notice}}<div class="callout success">{{.Notice}}</div>{{end}}
    {{if .Error}}<div class="callout danger">{{.Error}}</div>{{end}}

    <div class="stat-row">
      <div class="stat-tile"><div class="label">Public Base URL</div><div class="value" style="font-size:1rem;">{{.PublicBaseURL}}</div></div>
      <div class="stat-tile"><div class="label">Routes / Deployments</div><div class="value">{{len .Routes}} / {{len .Deployments}}</div></div>
      <div class="stat-tile"><div class="label">Self-Signup</div><div class="value" style="font-size:1.1rem;">{{if .SelfSignupEnabled}}Aktiviert{{else}}Deaktiviert{{end}}</div></div>
      <div class="stat-tile"><div class="label">Docker Management</div><div class="value" style="font-size:1.1rem;">{{if .DockerEnabled}}Aktiviert{{else}}Deaktiviert{{end}}</div></div>
    </div>

    {{if eq .ActiveTab "routes"}}

    <div class="toolbar">
      <div>
        <h2>MCP Routes</h2>
        <p class="hint">Oeffentliche Routen erscheinen im Katalog. Private Routen bleiben verborgen und sind nur per direkter URL fuer berechtigte Nutzer sichtbar.</p>
      </div>
      <a class="btn btn-primary btn-sm dirty-guard" data-next="__new__" href="/admin?new=1">+ Neue Route</a>
    </div>

    {{if .ShowRouteEditor}}
    <div class="editor-shell">
      <aside class="route-compact-list">
        <div class="compact-list-head">
          <a class="btn btn-ghost btn-sm dirty-guard" data-next="__browse__" href="/admin">&larr; Uebersicht</a>
          <a class="btn btn-sm dirty-guard" data-next="__new__" href="/admin?new=1">+ Neu</a>
        </div>
        {{range .Routes}}
          <a class="compact-row {{if eq .ID $.SelectedRoute.OriginalID}}is-active{{end}} dirty-guard" data-next="{{.ID}}" href="/admin?route={{.ID}}">
            <span class="dot"></span><span class="name">{{.DisplayName}}</span><span class="chip">{{.Transport}}</span>
          </a>
        {{else}}
          <div class="compact-row" style="cursor:default;"><span class="name hint">Noch keine Routen</span></div>
        {{end}}
      </aside>

      <div class="editor-center">
        <form class="panel editor-panel" id="routeForm" method="post" action="/admin/routes/save" enctype="multipart/form-data">
          <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
          <input type="hidden" name="original_id" value="{{.SelectedRoute.OriginalID}}">
          <input type="hidden" name="next_route" id="next_route" value="">
          <div class="panel-head">
            <div>
              <h3>{{if .SelectedRoute.OriginalID}}{{.SelectedRoute.DisplayName}}{{else}}Neue Route{{end}}</h3>
              <span class="hint" id="rf-dirty-hint" hidden>&#9679; Ungespeicherte Aenderungen</span>
            </div>
            {{if .SelectedRoute.OriginalID}}
              {{if eq .SelectedRoute.AccessMode "admin"}}<span class="pill pill-danger">Nur Admins</span>{{else if eq .SelectedRoute.AccessMode "restricted"}}<span class="pill pill-warning">Eingeschraenkt</span>{{else}}<span class="pill pill-neutral">Alle Nutzer</span>{{end}}
            {{end}}
          </div>
          <div class="panel-body">
            {{if .Error}}<div class="callout danger">{{.Error}}</div>{{end}}
            <p class="hint">Die Route-ID ist optional. Wenn sie leer bleibt, erzeugt der Gateway sie aus dem Display Name oder Path Prefix.</p>

            <div class="fieldset-title" style="margin-top:.9rem;">Grunddaten</div>
            <div class="field-grid">
              <div class="field" style="margin-top:0;">
                <label for="display_name">Anzeigename</label>
                <input id="display_name" name="display_name" type="text" value="{{.SelectedRoute.DisplayName}}" placeholder="German Legal">
              </div>
              <div class="field" style="margin-top:0;">
                <label for="path_prefix">Pfad-Praefix</label>
                <input id="path_prefix" name="path_prefix" type="text" class="mono" value="{{.SelectedRoute.PathPrefix}}" placeholder="/german-legal">
              </div>
            </div>
            <div class="field">
              <label for="id">Route ID <span class="hint">(optional, leer = Autofill)</span></label>
              <input id="id" name="id" type="text" class="mono" value="{{.SelectedRoute.ID}}" placeholder="auto, z.B. german-legal">
            </div>
            <div class="field">
              <label for="route_transport">Transport</label>
              <select id="route_transport" name="transport">
                <option value="http" {{if eq .SelectedRoute.Transport "http"}}selected{{end}}>HTTP / Streamable HTTP</option>
                <option value="stdio" {{if eq .SelectedRoute.Transport "stdio"}}selected{{end}}>Native STDIO</option>
                <option value="openapi" {{if eq .SelectedRoute.Transport "openapi"}}selected{{end}}>OpenAPI -&gt; MCP Tools</option>
              </select>
              <p class="hint" data-dyn-hint="http">Der Gateway spricht das MCP-Protokoll direkt per Streamable HTTP mit dem Upstream-Server.</p>
              <p class="hint" data-dyn-hint="stdio">Der Gateway startet den MCP-Server als lokalen Prozess -- kein Netzwerk-Upstream noetig.</p>
              <p class="hint" data-dyn-hint="openapi">Der Gateway liest eine OpenAPI-Spec und stellt jede Operation als eigenes MCP-Tool bereit.</p>
            </div>
            <div class="field">
              <label for="scopes_supported">Scopes</label>
              <input id="scopes_supported" name="scopes_supported" type="text" class="mono" value="{{.SelectedRoute.ScopesSupported}}" placeholder="mcp">
            </div>

            <div data-dyn-group="http">
              <div class="fieldset-title">Upstream (HTTP)</div>
              <div class="field" style="margin-top:0;">
                <label for="upstream">Upstream Base URL</label>
                <input id="upstream" name="upstream" type="url" class="mono" value="{{.SelectedRoute.Upstream}}" placeholder="http://n8n-mcp:8080">
              </div>
              <div class="field">
                <label for="upstream_mcp_path">Upstream MCP Path</label>
                <input id="upstream_mcp_path" name="upstream_mcp_path" type="text" class="mono" value="{{.SelectedRoute.UpstreamMCPPath}}" placeholder="/mcp">
              </div>
            </div>

            <details data-dyn-group="stdio">
              <summary>Prozess (STDIO)</summary>
              <div style="margin-top:.8rem;">
                <div class="field" style="margin-top:0;">
                  <label for="stdio_command">Executable / Command</label>
                  <input id="stdio_command" name="stdio_command" type="text" class="mono" value="{{.SelectedRoute.StdioCommand}}" placeholder="/tools/portainer-mcp">
                </div>
                <div class="field">
                  <label for="stdio_args">Argumente <span class="hint">(ein Argument pro Zeile)</span></label>
                  <textarea id="stdio_args" name="stdio_args" class="mono" placeholder="-server&#10;https://portainer:9443&#10;-token&#10;...">{{.SelectedRoute.StdioArgs}}</textarea>
                </div>
                <div class="field">
                  <label for="stdio_env">STDIO Environment</label>
                  <textarea id="stdio_env" name="stdio_env" class="mono" placeholder="ANNAS_SECRET_KEY=...&#10;ANNAS_DOWNLOAD_PATH=/data/downloads">{{.SelectedRoute.StdioEnv}}</textarea>
                </div>
                <div class="field">
                  <label for="stdio_working_dir">Working Directory</label>
                  <input id="stdio_working_dir" name="stdio_working_dir" type="text" class="mono" value="{{.SelectedRoute.StdioWorkingDir}}" placeholder="/tools">
                </div>
                <div class="callout" style="margin-top:.8rem; font-size:.82rem;">Der Gateway startet und ueberwacht diesen Prozess selbst -- kein separater Upstream-Server noetig.</div>
              </div>
            </details>

            <details data-dyn-group="openapi">
              <summary>OpenAPI Tool-Bridge</summary>
              <div style="margin-top:.8rem;">
                <div class="field" style="margin-top:0;">
                  <label for="openapi_spec_file">OpenAPI Spec importieren</label>
                  <input id="openapi_spec_file" name="openapi_spec_file" type="file" accept=".yaml,.yml,.json,application/yaml,application/json">
                  <p class="hint">Optionaler Upload. Der Gateway prueft die Spec und speichert sie im konfigurierten OpenAPI Store.</p>
                </div>
                <div class="field">
                  <label for="openapi_spec_path">OpenAPI Spec Path</label>
                  <input id="openapi_spec_path" name="openapi_spec_path" type="text" class="mono" value="{{.SelectedRoute.OpenAPISpecPath}}" placeholder="/data/openapi/example.yaml">
                  <p class="hint">Absoluter Pfad im Gateway-Container. Wird durch Upload automatisch befuellt.</p>
                </div>
                <div class="field">
                  <label for="openapi_spec_url">OpenAPI Spec URL</label>
                  <input id="openapi_spec_url" name="openapi_spec_url" type="url" class="mono" value="{{.SelectedRoute.OpenAPISpecURL}}" placeholder="https://api.example.com/openapi.yaml">
                </div>
                <div class="field">
                  <label for="openapi_base_url">OpenAPI Base URL</label>
                  <input id="openapi_base_url" name="openapi_base_url" type="url" class="mono" value="{{.SelectedRoute.OpenAPIBaseURL}}" placeholder="https://api.example.com">
                  <p class="hint">Ziel-API, gegen die die generierten Tools Requests ausfuehren.</p>
                </div>
                <div class="field">
                  <label for="openapi_headers">API Headers <span class="hint">(statisch, fuer jeden Request)</span></label>
                  <textarea id="openapi_headers" name="openapi_headers" class="mono" placeholder="X-Api-Key: ...">{{.SelectedRoute.OpenAPIHeaders}}</textarea>
                </div>
                <div class="field">
                  <label for="openapi_timeout_seconds">Timeout (Sekunden)</label>
                  <input id="openapi_timeout_seconds" name="openapi_timeout_seconds" type="text" class="mono" value="{{.SelectedRoute.OpenAPITimeoutSeconds}}" placeholder="30">
                </div>
              </div>
            </details>

            <div data-dyn-group="http">
              <div class="fieldset-title">Verbindung &amp; Weiterleitung</div>
              <div class="field" style="margin-top:0;">
                <label for="mcp_http_session_mode">Session Mode</label>
                <input id="mcp_http_session_mode" name="mcp_http_session_mode" type="text" class="mono" value="{{.SelectedRoute.MCPHTTPSessionMode}}" placeholder="stateful oder stateless">
              </div>
              <label class="checkbox-row">
                <input id="pass_authorization_header" name="pass_authorization_header" type="checkbox" {{if .SelectedRoute.PassAuthorization}}checked{{end}}>
                <span>
                  Inbound Authorization an Upstream weiterreichen
                  <p class="hint" style="margin-top:.2rem;">Aus lassen, wenn der Gateway interne Header wie <code>Authorization: Bearer ...</code> setzen soll.</p>
                </span>
              </label>
              <details style="margin-top:.85rem;">
                <summary>Upstream Bearer Auth</summary>
                <div style="margin-top:.8rem;">
                  <p class="hint">Fuer MCP-Server wie n8n-mcp, die zusaetzlich zum Gateway-OAuth einen internen Bearer erwarten. Werte werden verschluesselt gespeichert und nicht nach <code>routes.yaml</code> exportiert.</p>
                  <div class="field">
                    <label for="upstream_bearer_token">Globaler Upstream Bearer</label>
                    <input id="upstream_bearer_token" name="upstream_bearer_token" type="password" placeholder="{{if .SelectedRoute.UpstreamBearerConfigured}}Token ist gesetzt; leer lassen zum Beibehalten{{else}}n8n AUTH_TOKEN oder anderer Upstream-Bearer{{end}}">
                    <p class="hint">{{if .SelectedRoute.UpstreamBearerConfigured}}Aktuell ist ein globaler Upstream-Bearer gesetzt.{{else}}Kein globaler Upstream-Bearer gesetzt.{{end}} Nutzer-spezifische Tokens haben Vorrang.</p>
                  </div>
                  <label class="checkbox-row">
                    <input id="clear_upstream_bearer" name="clear_upstream_bearer" type="checkbox">
                    <span>Globalen Upstream Bearer loeschen</span>
                  </label>
                  <table style="margin-top:.8rem;">
                    <thead><tr><th>Nutzer</th><th>Status</th><th>Neuer Bearer</th><th>Loeschen</th></tr></thead>
                    <tbody>
                      {{range .Users}}
                        {{$hasBearer := upstreamBearerConfigured $.SelectedRoute .ID}}
                        <tr>
                          <td>{{.Email}}</td>
                          <td>{{if $hasBearer}}gesetzt{{else}}default/global{{end}}</td>
                          <td>
                            <input type="hidden" name="upstream_bearer_user_id" value="{{.ID}}">
                            <input name="upstream_bearer_user_token" type="password" placeholder="{{if $hasBearer}}Leer lassen zum Beibehalten{{else}}Optionaler Nutzer-Bearer{{end}}">
                          </td>
                          <td style="text-align:center;"><input name="clear_user_upstream_bearer" type="checkbox" value="{{.ID}}" {{if not $hasBearer}}disabled{{end}}></td>
                        </tr>
                      {{end}}
                    </tbody>
                  </table>
                </div>
              </details>
              <div class="field">
                <label for="upstream_environment">Upstream Environment Metadata</label>
                <textarea id="upstream_environment" name="upstream_environment" class="mono" placeholder="AUTH_TOKEN=replace-me&#10;PORT=8080">{{.SelectedRoute.UpstreamEnvironment}}</textarea>
                <p class="hint">Nur Metadaten zur Dokumentation des Upstreams.</p>
              </div>
            </div>

            <div class="field" data-dyn-group="http openapi">
              <label for="forward_headers">Forward Headers <span class="hint">(pro angemeldetem Nutzer, mit Platzhaltern wie <code>{email}</code>)</span></label>
              <textarea id="forward_headers" name="forward_headers" class="mono" placeholder="X-MCP-User: {email}">{{.SelectedRoute.ForwardHeaders}}</textarea>
            </div>

            <details style="margin-top:.85rem;">
              <summary>Sichtbarkeit, Zugriff &amp; Berechtigungen</summary>
              <div style="margin-top:.8rem;">
                <div class="field-grid">
                  <div class="field" style="margin-top:0;">
                    <label for="access_visibility">Katalog-Sichtbarkeit</label>
                    <select id="access_visibility" name="access_visibility">
                      <option value="public" {{if eq .SelectedRoute.AccessVisibility "public"}}selected{{end}}>Oeffentlicher Katalog</option>
                      <option value="private" {{if eq .SelectedRoute.AccessVisibility "private"}}selected{{end}}>Verborgen (nur Link)</option>
                    </select>
                  </div>
                  <div class="field" style="margin-top:0;">
                    <label for="access_mode">Zugriffsmodus</label>
                    <select id="access_mode" name="access_mode">
                      <option value="public" {{if eq .SelectedRoute.AccessMode "public"}}selected{{end}}>Alle angemeldeten Nutzer</option>
                      <option value="restricted" {{if eq .SelectedRoute.AccessMode "restricted"}}selected{{end}}>Eingeschraenkt (Gruppen/Nutzer)</option>
                      <option value="admin" {{if eq .SelectedRoute.AccessMode "admin"}}selected{{end}}>Nur Admins</option>
                    </select>
                  </div>
                </div>
                <div class="field">
                  <label for="resource_documentation">Resource Documentation URL</label>
                  <input id="resource_documentation" name="resource_documentation" type="url" value="{{.SelectedRoute.ResourceDocumentation}}" placeholder="https://github.com/your-server/docs">
                </div>
                <div class="field">
                  <label for="notes">Notes / Beschreibung</label>
                  <textarea id="notes" name="notes" placeholder="Kurzbeschreibung, Setup-Hinweise, Reverse-Proxy-Anforderungen...">{{.SelectedRoute.Notes}}</textarea>
                </div>
                <details style="margin-top:.8rem;">
                  <summary>Berechtigungsmatrix fuer Nutzer und Gruppen</summary>
                  <div style="margin-top:.8rem;">
                    <p class="hint">Default nutzt den Modus oben. Allow gilt bei restricted Routen, Deny ist eine harte Sperre und gilt auch fuer Admins.</p>
                    <table>
                      <thead><tr><th>Typ</th><th>Name</th><th>Berechtigung</th></tr></thead>
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
                  </div>
                </details>
              </div>
            </details>

            <div style="display:flex; justify-content:space-between; gap:.6rem; margin-top:1.1rem;">
              {{if .SelectedRoute.OriginalID}}
                <button type="submit" form="routeDeleteForm" class="btn btn-danger btn-sm">Route loeschen</button>
              {{else}}<span></span>{{end}}
              <div style="display:flex; gap:.5rem;">
                <a class="btn btn-sm discard-link" href="/admin?{{if .SelectedRoute.OriginalID}}route={{.SelectedRoute.OriginalID}}{{else}}new=1{{end}}">Verwerfen</a>
                <button type="submit" class="btn btn-primary btn-sm">Speichern</button>
              </div>
            </div>
          </div>
        </form>
        {{if .SelectedRoute.OriginalID}}
          <form id="routeDeleteForm" method="post" action="/admin/routes/delete" style="display:none;">
            <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
            <input type="hidden" name="route_id" value="{{.SelectedRoute.OriginalID}}">
          </form>
        {{end}}
      </div>
    </div>
    {{else}}
    <div class="table-card" style="margin-top:1rem;">
      <table>
        <thead><tr><th>Route</th><th>Zugriff</th><th>Session</th><th></th></tr></thead>
        <tbody>
          {{range .Routes}}
            <tr>
              <td>
                <div class="row-title">{{.DisplayName}}</div>
                <div class="row-sub mono">{{.PathPrefix}} <span class="transport-chip">{{.Transport}}</span></div>
              </td>
              <td>
                {{if eq .AccessMode "admin"}}<span class="pill pill-danger">Nur Admins</span>{{else if eq .AccessMode "restricted"}}<span class="pill pill-warning">Eingeschraenkt</span>{{else}}<span class="pill pill-neutral">Alle Nutzer</span>{{end}}
                {{if eq .AccessVisibility "private"}}<span class="pill pill-neutral" style="margin-left:.3rem;">Privat</span>{{end}}
              </td>
              <td><span class="mono hint">{{if .MCPHTTPSessionMode}}{{.MCPHTTPSessionMode}}{{else}}&mdash;{{end}}</span></td>
              <td style="text-align:right;"><a class="btn btn-sm btn-ghost" href="/admin?route={{.ID}}">Bearbeiten</a></td>
            </tr>
          {{else}}
            <tr><td colspan="4" class="hint">Noch keine MCP-Routen angelegt.</td></tr>
          {{end}}
        </tbody>
      </table>
    </div>
    {{end}}

    {{else if eq .ActiveTab "deployments"}}

    <div class="split">
      <div class="stack">
        <div>
          <h2>Managed Deployments</h2>
          <p class="hint">Container werden nur verwaltet, wenn Docker Management aktiv ist und der Gateway Zugriff auf den Docker Host hat.</p>
        </div>
        {{if .DockerError}}<div class="callout danger">{{.DockerError}}</div>{{end}}
        {{if .Deployments}}
          <div class="table-card">
            <table>
              <thead><tr><th>Deployment</th><th>Status</th><th></th></tr></thead>
              <tbody>
                {{range .Deployments}}
                  <tr>
                    <td>
                      <div class="row-title">{{.DisplayName}}</div>
                      <div class="row-sub mono">{{if eq .Transport "stdio"}}stdio{{else}}{{.ContainerName}}:{{.InternalPort}}{{end}} &middot; {{.RouteID}}</div>
                      <div class="row-sub">{{if eq .Transport "stdio"}}Command: <code>{{.Command}}</code>{{else}}Image: <code>{{.Image}}</code>{{end}}</div>
                      {{if .Networks}}<div class="row-sub">Networks: <code>{{.Networks}}</code></div>{{end}}
                    </td>
                    <td><span class="pill {{if eq .State "running"}}pill-success{{else}}pill-danger{{end}}">{{.State}}</span></td>
                    <td style="text-align:right; white-space:nowrap;">
                      {{if ne .Transport "stdio"}}
                        <form method="post" action="/admin/deployments/start" style="display:inline;">
                          <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                          <input type="hidden" name="route_id" value="{{.RouteID}}">
                          <button type="submit" class="btn btn-sm btn-ghost">Start</button>
                        </form>
                        <form method="post" action="/admin/deployments/stop" style="display:inline;">
                          <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                          <input type="hidden" name="route_id" value="{{.RouteID}}">
                          <button type="submit" class="btn btn-sm btn-ghost">Stop</button>
                        </form>
                        <form method="post" action="/admin/deployments/remove" style="display:inline;">
                          <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                          <input type="hidden" name="route_id" value="{{.RouteID}}">
                          <button type="submit" class="btn btn-sm btn-danger">Entfernen</button>
                        </form>
                      {{end}}
                      <a class="btn btn-sm btn-ghost" href="/admin?route={{.RouteID}}">Route</a>
                    </td>
                  </tr>
                {{end}}
              </tbody>
            </table>
          </div>
        {{else}}
          <div class="empty"><p class="muted">Noch keine vom Gateway verwalteten Deployments.</p></div>
        {{end}}
      </div>

      <div class="panel">
        <div class="panel-head"><h3>MCP Deployment anlegen</h3></div>
        <div class="panel-body">
          <p class="hint">{{if .DockerEnabled}}Erzeugt entweder einen HTTP-MCP-Docker-Container oder eine native STDIO-Route im Gateway-Prozess.{{else}}Docker Management ist deaktiviert. Native STDIO-Routen funktionieren trotzdem, wenn das Executable im Gateway-Container vorhanden oder gemountet ist.{{end}}</p>
          <form method="post" action="/admin/deployments/create" id="deploymentForm">
            <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
            <div class="field" style="margin-top:.9rem;">
              <label for="deploy_transport">Transport</label>
              <select id="deploy_transport" name="transport">
                <option value="http" {{if eq .DeploymentForm.Transport "http"}}selected{{end}}>HTTP / Streamable HTTP Container</option>
                <option value="stdio" {{if eq .DeploymentForm.Transport "stdio"}}selected{{end}}>Native STDIO Command</option>
              </select>
              <p class="hint">STDIO startet der Gateway selbst pro MCP-Session. Kein extra Adapter-Container.</p>
            </div>
            <div class="field-grid">
              <div class="field" style="margin-top:0;">
                <label for="deploy_display_name">Display Name</label>
                <input id="deploy_display_name" name="display_name" type="text" value="{{.DeploymentForm.DisplayName}}" placeholder="n8n MCP">
              </div>
              <div class="field" style="margin-top:0;">
                <label for="deploy_id">Route ID</label>
                <input id="deploy_id" name="id" type="text" class="mono" value="{{.DeploymentForm.ID}}" placeholder="auto">
              </div>
            </div>
            <div class="field">
              <label for="deploy_path_prefix">Path Prefix</label>
              <input id="deploy_path_prefix" name="path_prefix" type="text" class="mono" value="{{.DeploymentForm.PathPrefix}}" placeholder="/n8n">
            </div>

            <div data-dyn-group="http">
              <div class="fieldset-title">Docker-Container</div>
              <div class="field" style="margin-top:0;">
                <label for="deploy_image">Docker Image</label>
                <input id="deploy_image" name="image" type="text" class="mono" value="{{.DeploymentForm.Image}}" placeholder="ghcr.io/czlonkowski/n8n-mcp:latest">
              </div>
              <div class="field-grid">
                <div class="field" style="margin-top:0;">
                  <label for="deploy_container_name">Container Name</label>
                  <input id="deploy_container_name" name="container_name" type="text" class="mono" value="{{.DeploymentForm.ContainerName}}" placeholder="auto aus Route ID">
                </div>
                <div class="field" style="margin-top:0;">
                  <label for="deploy_internal_port">Interner Port</label>
                  <input id="deploy_internal_port" name="internal_port" type="text" class="mono" value="{{.DeploymentForm.InternalPort}}" placeholder="8080">
                </div>
              </div>
              <div class="field">
                <label for="deploy_upstream_mcp_path">Upstream MCP Path</label>
                <input id="deploy_upstream_mcp_path" name="upstream_mcp_path" type="text" class="mono" value="{{.DeploymentForm.UpstreamMCPPath}}" placeholder="/mcp">
              </div>
              <div class="field">
                <label for="deploy_networks">Docker Networks</label>
                <textarea id="deploy_networks" name="networks" class="mono" placeholder="mcp-shared&#10;mcp-internal">{{.DeploymentForm.Networks}}</textarea>
                <p class="hint">Mindestens ein gemeinsames Docker-Netz mit dem Gateway ist empfohlen, damit <code>http://container:port</code> aufloest.</p>
              </div>
              <div class="field">
                <label for="deployment_upstream_bearer_token">Gateway Upstream Bearer</label>
                <input id="deployment_upstream_bearer_token" name="deployment_upstream_bearer_token" type="password" placeholder="Optional: derselbe Wert wie AUTH_TOKEN bei n8n-mcp">
                <p class="hint">Verschluesselt gespeichert, vom Gateway als <code>Authorization: Bearer ...</code> zum Upstream gesendet.</p>
              </div>
            </div>

            <details data-dyn-group="stdio">
              <summary>Prozess (STDIO)</summary>
              <div style="margin-top:.8rem;">
                <div class="field" style="margin-top:0;">
                  <label for="deploy_stdio_command">Executable / Command</label>
                  <input id="deploy_stdio_command" name="stdio_command" type="text" class="mono" value="{{.DeploymentForm.StdioCommand}}" placeholder="/tools/portainer-mcp">
                  <p class="hint">Pfad oder Command, der innerhalb des Gateway-Containers existiert. Fuer Host-Dateien bitte als Volume in den Gateway mounten.</p>
                </div>
                <div class="field">
                  <label for="deploy_stdio_args">Argumente</label>
                  <textarea id="deploy_stdio_args" name="stdio_args" class="mono" placeholder="-server&#10;https://portainer:9443&#10;-token&#10;...">{{.DeploymentForm.StdioArgs}}</textarea>
                </div>
                <div class="field">
                  <label for="deploy_stdio_env">STDIO Environment</label>
                  <textarea id="deploy_stdio_env" name="stdio_env" class="mono" placeholder="ANNAS_SECRET_KEY=...&#10;ANNAS_DOWNLOAD_PATH=/data/downloads">{{.DeploymentForm.StdioEnv}}</textarea>
                </div>
                <div class="field">
                  <label for="deploy_stdio_working_dir">Working Directory</label>
                  <input id="deploy_stdio_working_dir" name="stdio_working_dir" type="text" class="mono" value="{{.DeploymentForm.StdioWorkingDir}}" placeholder="/tools">
                </div>
              </div>
            </details>

            <details style="margin-top:.85rem;">
              <summary>Weitere Details</summary>
              <div style="margin-top:.8rem;">
                <div class="field-grid">
                  <div class="field" style="margin-top:0;">
                    <label for="deploy_scopes">Scopes</label>
                    <input id="deploy_scopes" name="scopes_supported" type="text" class="mono" value="{{.DeploymentForm.ScopesSupported}}" placeholder="mcp">
                  </div>
                  <div class="field" style="margin-top:0;">
                    <label for="deploy_restart_policy">Restart Policy</label>
                    <input id="deploy_restart_policy" name="restart_policy" type="text" class="mono" value="{{.DeploymentForm.RestartPolicy}}" placeholder="unless-stopped">
                  </div>
                </div>
                <div class="field">
                  <label for="deploy_environment">Environment</label>
                  <textarea id="deploy_environment" name="environment" class="mono" placeholder="MCP_MODE=http&#10;PORT=3000&#10;AUTH_TOKEN=secret-for-upstream">{{.DeploymentForm.Environment}}</textarea>
                </div>
                <div class="field">
                  <label for="deploy_resource_documentation">Resource Documentation URL</label>
                  <input id="deploy_resource_documentation" name="resource_documentation" type="url" value="{{.DeploymentForm.ResourceDocumentation}}" placeholder="https://github.com/example/mcp">
                </div>
                <div class="field">
                  <label for="deploy_notes">Notes</label>
                  <textarea id="deploy_notes" name="notes" placeholder="Deployment-Hinweise...">{{.DeploymentForm.Notes}}</textarea>
                </div>
              </div>
            </details>

            <div style="margin-top:1.1rem;">
              <button type="submit" class="btn btn-primary btn-sm">Deployment erstellen &amp; Route anlegen</button>
            </div>
          </form>
        </div>
      </div>
    </div>

    {{else if eq .ActiveTab "build"}}

    <div class="build-chooser">
      <button type="button" class="build-choice is-active" data-build-choice="stdio">
        <span class="build-choice-title">STDIO MCP installieren</span>
        <span class="build-choice-desc">Fertiges Binary/Release per GitHub, Download-URL oder Upload als lokal gestarteten MCP-Prozess einbinden.</span>
      </button>
      <button type="button" class="build-choice" data-build-choice="image">
        <span class="build-choice-title">Image aus Artefakt bauen</span>
        <span class="build-choice-desc">Ein heruntergeladenes oder hochgeladenes Artefakt zu einem eigenen Docker-Image verpacken.</span>
      </button>
    </div>

    <div class="panel" data-build-panel="stdio">
      <div class="panel-head">
        <h3>STDIO MCP installieren</h3>
        <span class="pill {{if .StdioInstallEnabled}}pill-success{{else}}pill-neutral{{end}}">{{if .StdioInstallEnabled}}Aktiviert{{else}}Deaktiviert{{end}}</span>
      </div>
      <div class="panel-body">
        {{if .StdioInstallEnabled}}
          <p class="hint">Installiert fertige STDIO-MCP-Artefakte nach <code>{{.StdioInstallStore}}</code>. Maximalgroesse: {{.StdioInstallMaxMB}} MB. Env-Werte werden verschluesselt im Auth-Store gespeichert.</p>
        {{else}}
          <p class="hint">Der STDIO Installer ist deaktiviert. Setze <code>MCP_GATEWAY_STDIO_INSTALL_ENABLED=true</code>, wenn Admins Uploads, GitHub-Releases oder Download-Links installieren duerfen.</p>
        {{end}}
        <form method="post" action="/admin/stdio/install" enctype="multipart/form-data" id="stdioInstallForm">
          <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
          <div class="field" style="margin-top:.9rem;">
            <label for="stdio_install_source_kind">Quelle</label>
            <select id="stdio_install_source_kind" name="stdio_install_source_kind">
              <option value="github" {{if eq .StdioInstallForm.SourceKind "github"}}selected{{end}}>GitHub Release</option>
              <option value="url" {{if eq .StdioInstallForm.SourceKind "url"}}selected{{end}}>HTTPS Download</option>
              <option value="upload" {{if eq .StdioInstallForm.SourceKind "upload"}}selected{{end}}>File Upload</option>
            </select>
            <p class="hint" data-dyn-hint="github">Laedt automatisch das passende Release-Asset aus einem GitHub-Repo.</p>
            <p class="hint" data-dyn-hint="url">Laedt das Artefakt direkt von einer HTTPS-URL. SHA-256 ist Pflicht.</p>
            <p class="hint" data-dyn-hint="upload">Artefakt wird direkt hochgeladen. SHA-256 ist Pflicht.</p>
          </div>
          <div class="field-grid">
            <div class="field" style="margin-top:0;">
              <label for="stdio_install_id">Route ID</label>
              <input id="stdio_install_id" name="stdio_install_id" type="text" class="mono" value="{{.StdioInstallForm.ID}}" placeholder="annas">
            </div>
            <div class="field" style="margin-top:0;">
              <label for="stdio_install_display_name">Display Name</label>
              <input id="stdio_install_display_name" name="stdio_install_display_name" type="text" value="{{.StdioInstallForm.DisplayName}}" placeholder="Anna's MCP">
            </div>
            <div class="field" style="margin-top:0;">
              <label for="stdio_install_path_prefix">Path Prefix</label>
              <input id="stdio_install_path_prefix" name="stdio_install_path_prefix" type="text" class="mono" value="{{.StdioInstallForm.PathPrefix}}" placeholder="/annas">
            </div>
            <div class="field" style="margin-top:0;">
              <label for="stdio_install_scopes">Scopes</label>
              <input id="stdio_install_scopes" name="stdio_install_scopes_supported" type="text" class="mono" value="{{.StdioInstallForm.ScopesSupported}}" placeholder="mcp">
            </div>
          </div>

          <div data-dyn-group="github">
            <div class="fieldset-title">Quelle: GitHub Release</div>
            <div class="field" style="margin-top:0;">
              <label for="stdio_install_github_repo">GitHub Repo URL</label>
              <input id="stdio_install_github_repo" name="stdio_install_github_repo" type="url" class="mono" value="{{.StdioInstallForm.GitHubRepo}}" placeholder="https://github.com/iosifache/annas-mcp">
            </div>
            <div class="field-grid">
              <div class="field" style="margin-top:0;">
                <label for="stdio_install_github_version">Version</label>
                <input id="stdio_install_github_version" name="stdio_install_github_version" type="text" class="mono" value="{{.StdioInstallForm.GitHubVersion}}" placeholder="latest oder v0.0.5">
              </div>
              <div class="field" style="margin-top:0;">
                <label for="stdio_install_asset_pattern">Asset Pattern <span class="hint">(optional)</span></label>
                <input id="stdio_install_asset_pattern" name="stdio_install_asset_pattern" type="text" class="mono" value="{{.StdioInstallForm.AssetPattern}}" placeholder="linux_amd64">
              </div>
            </div>
          </div>
          <div data-dyn-group="url">
            <div class="fieldset-title">Quelle: HTTPS Download</div>
            <div class="field" style="margin-top:0;">
              <label for="stdio_install_download_url">Download URL</label>
              <input id="stdio_install_download_url" name="stdio_install_download_url" type="url" class="mono" value="{{.StdioInstallForm.DownloadURL}}" placeholder="https://github.com/org/repo/releases/download/v1/server_linux_amd64.tar.xz">
            </div>
          </div>
          <div data-dyn-group="upload">
            <div class="fieldset-title">Quelle: File Upload</div>
            <div class="field" style="margin-top:0;">
              <label for="stdio_install_file">Artefakt hochladen</label>
              <input id="stdio_install_file" name="stdio_install_file" type="file">
            </div>
          </div>
          <div class="field" data-dyn-group="url upload">
            <label for="stdio_install_sha256">SHA-256 <span class="hint">(Pflicht)</span></label>
            <input id="stdio_install_sha256" name="stdio_install_sha256" type="text" class="mono" value="{{.StdioInstallForm.SHA256}}" placeholder="64 hex chars oder sha256:...">
          </div>
          <div class="field" data-dyn-group="github">
            <label for="stdio_install_sha256_gh">SHA-256 <span class="hint">(optional, wenn GitHub Digest bereitstellt)</span></label>
            <input id="stdio_install_sha256_gh" name="stdio_install_sha256" type="text" class="mono" value="{{.StdioInstallForm.SHA256}}" placeholder="optional bei GitHub mit digest">
          </div>

          <div class="fieldset-title">Entpacken &amp; Start</div>
          <div class="field-grid">
            <div class="field" style="margin-top:0;">
              <label for="stdio_install_extract_mode">Entpacken</label>
              <select id="stdio_install_extract_mode" name="stdio_install_extract_mode">
                <option value="auto" {{if eq .StdioInstallForm.ExtractMode "auto"}}selected{{end}}>Auto</option>
                <option value="none" {{if eq .StdioInstallForm.ExtractMode "none"}}selected{{end}}>Nicht entpacken</option>
                <option value="tar.gz" {{if eq .StdioInstallForm.ExtractMode "tar.gz"}}selected{{end}}>tar.gz</option>
                <option value="tar.xz" {{if eq .StdioInstallForm.ExtractMode "tar.xz"}}selected{{end}}>tar.xz</option>
                <option value="zip" {{if eq .StdioInstallForm.ExtractMode "zip"}}selected{{end}}>zip</option>
              </select>
            </div>
            <div class="field" style="margin-top:0;">
              <label for="stdio_install_executable_path">Executable im Archiv</label>
              <input id="stdio_install_executable_path" name="stdio_install_executable_path" type="text" class="mono" value="{{.StdioInstallForm.ExecutablePath}}" placeholder="annas-mcp oder path/in/archive/annas-mcp">
            </div>
          </div>
          <div class="field">
            <label for="stdio_install_args">Start-Argumente <span class="hint">(ein Argument pro Zeile)</span></label>
            <textarea id="stdio_install_args" name="stdio_install_args" class="mono" placeholder="mcp">{{.StdioInstallForm.Args}}</textarea>
          </div>

          <details style="margin-top:.85rem;">
            <summary>Zusatzordner &amp; Environment Secrets</summary>
            <div style="margin-top:.8rem;">
              <label>Zusatzordner</label>
              <table>
                <thead><tr><th>Relativer Ordner unter der Installation</th></tr></thead>
                <tbody>
                  {{range .StdioInstallForm.ExtraFolders}}
                    <tr><td><input name="stdio_install_folder" type="text" value="{{.}}" placeholder="downloads"></td></tr>
                  {{end}}
                </tbody>
              </table>
              <p class="hint">Leer lassen, wenn keine Ordner benoetigt werden. Absolute Pfade und <code>..</code> werden abgelehnt.</p>
              <label style="margin-top:.9rem;">Environment Secrets</label>
              <table>
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
              <p class="hint">Diese Werte landen nicht in <code>routes.yaml</code>, sondern verschluesselt in <code>auth-store.enc</code> und werden erst beim STDIO-Prozessstart injiziert.</p>
            </div>
          </details>

          <div style="display:flex; justify-content:flex-end; margin-top:1.1rem;">
            <button type="submit" class="btn btn-primary btn-sm">STDIO MCP installieren &amp; Route anlegen</button>
          </div>
        </form>
      </div>
    </div>

    <div class="panel" data-build-panel="image" hidden>
      <div class="panel-head">
        <h3>Image aus Artefakt bauen</h3>
        <span class="pill {{if .BuildEnabled}}pill-success{{else}}pill-neutral{{end}}">{{if .BuildEnabled}}Aktiviert{{else}}Deaktiviert{{end}}</span>
      </div>
      <div class="panel-body">
        {{if .BuildEnabled}}
          <p class="hint">Builds sind aktiv. Downloads sind auf erlaubte Hosts beschraenkt: <code>{{.BuildHosts}}</code>. Maximalgroesse: {{.BuildMaxMB}} MB.</p>
        {{else}}
          <p class="hint">Builds sind deaktiviert. Setze <code>MCP_GATEWAY_BUILD_ENABLED=true</code>, wenn Admins verifizierte Artefakte in eigene Images bauen duerfen.</p>
        {{end}}
        <form method="post" action="/admin/artifacts/build" enctype="multipart/form-data" id="buildForm">
          <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
          <div class="field" style="margin-top:.9rem;">
            <label for="build_source_kind">Quelle</label>
            <select id="build_source_kind" name="source_kind">
              <option value="url" {{if eq .BuildForm.SourceKind "url"}}selected{{end}}>HTTPS Download</option>
              <option value="upload" {{if eq .BuildForm.SourceKind "upload"}}selected{{end}}>File Upload</option>
            </select>
          </div>
          <div class="field">
            <label for="build_image_tag">Image Tag</label>
            <input id="build_image_tag" name="image_tag" type="text" class="mono" value="{{.BuildForm.ImageTag}}" placeholder="local/portainer-mcp:0.7.0">
          </div>

          <div data-dyn-group="url">
            <div class="fieldset-title">Quelle: HTTPS Download</div>
            <div class="field" style="margin-top:0;">
              <label for="build_download_url">GitHub Release / HTTPS URL</label>
              <input id="build_download_url" name="download_url" type="url" class="mono" value="{{.BuildForm.DownloadURL}}" placeholder="https://github.com/org/repo/releases/download/v1/server-linux-amd64.tar.gz">
              <p class="hint">Nur HTTPS. Standardmaessig sind GitHub-Release-Hosts erlaubt; private/LAN-Ziele werden blockiert, wenn freie Hosts aktiviert werden.</p>
            </div>
          </div>
          <div data-dyn-group="upload">
            <div class="fieldset-title">Quelle: File Upload</div>
            <div class="field" style="margin-top:0;">
              <label for="build_artifact_file">Artefakt hochladen</label>
              <input id="build_artifact_file" name="artifact_file" type="file">
            </div>
          </div>
          <div class="field">
            <label for="build_sha256">SHA-256 Checksum <span class="hint">(Pflicht bei Upload und Download)</span></label>
            <input id="build_sha256" name="sha256" type="text" class="mono" value="{{.BuildForm.SHA256}}" placeholder="64 hex chars oder sha256:...">
            <p class="hint">Verifiziert wird das Originalartefakt vor dem Entpacken.</p>
          </div>

          <div class="fieldset-title">Image-Details</div>
          <div class="field-grid">
            <div class="field" style="margin-top:0;">
              <label for="build_extract_mode">Entpacken</label>
              <select id="build_extract_mode" name="extract_mode">
                <option value="none" {{if eq .BuildForm.ExtractMode "none"}}selected{{end}}>Nicht entpacken</option>
                <option value="tar.gz" {{if eq .BuildForm.ExtractMode "tar.gz"}}selected{{end}}>tar.gz</option>
                <option value="zip" {{if eq .BuildForm.ExtractMode "zip"}}selected{{end}}>zip</option>
              </select>
            </div>
            <div class="field" style="margin-top:0;">
              <label for="build_artifact_path">Pfad im Archiv</label>
              <input id="build_artifact_path" name="artifact_path" type="text" class="mono" value="{{.BuildForm.ArtifactPath}}" placeholder="portainer-mcp">
              <p class="hint">Pflicht bei Archiven. Absolute Pfade, Symlinks und Traversal werden abgelehnt.</p>
            </div>
          </div>
          <div class="field-grid">
            <div class="field" style="margin-top:0;">
              <label for="build_base_image">Base Image</label>
              <input id="build_base_image" name="base_image" type="text" class="mono" value="{{.BuildForm.BaseImage}}" placeholder="debian:bookworm-slim">
              <p class="hint">Erlaubt: <code>{{.BuildBaseImages}}</code></p>
            </div>
            <div class="field" style="margin-top:0;">
              <label for="build_internal_port">EXPOSE Port</label>
              <input id="build_internal_port" name="internal_port" type="text" class="mono" value="{{.BuildForm.InternalPort}}" placeholder="8080">
            </div>
          </div>
          <div class="field">
            <label for="build_entrypoint_args">Feste Start-Argumente <span class="hint">(optional, ein Argument pro Zeile)</span></label>
            <textarea id="build_entrypoint_args" name="entrypoint_args" class="mono" placeholder="mcp&#10;--port&#10;8080">{{.BuildForm.EntrypointArgs}}</textarea>
            <p class="hint">Wird als JSON-ENTRYPOINT erzeugt, nicht als Shell-Command.</p>
          </div>

          <div style="display:flex; justify-content:flex-end; margin-top:1.1rem;">
            <button type="submit" class="btn btn-primary btn-sm">Verifizieren &amp; Image bauen</button>
          </div>
          <p class="hint" style="margin-top:.6rem;">Der Dockerfile-Inhalt wird vom Gateway erzeugt. Es werden keine frei eingegebenen Shell-Kommandos in den Build uebernommen.</p>
        </form>
      </div>
    </div>

    {{else if eq .ActiveTab "users"}}

    <div class="split">
      <div class="stack">
        <div class="toolbar">
          <div>
            <h2>Benutzer</h2>
            <p class="hint">Schlanke Uebersicht. Details, Gruppen, Passwort und registrierte Clients oeffnest du pro Nutzer.</p>
          </div>
        </div>
        <div class="table-card">
          <table>
            <thead><tr><th>Email</th><th>Rolle</th><th>Gruppen</th><th>Clients</th><th></th></tr></thead>
            <tbody>
            {{range .Users}}
              <tr>
                <td><div class="row-title">{{.Email}}</div><div class="row-sub mono">{{.ID}}</div></td>
                <td>{{if .IsAdmin}}<span class="pill pill-info">Admin</span>{{else}}<span class="pill pill-neutral">Nutzer</span>{{end}}</td>
                <td>{{if .Groups}}{{.Groups}}{{else}}<span class="hint">keine</span>{{end}}</td>
                <td class="mono">{{.DeviceCount}}</td>
                <td style="text-align:right;"><a class="btn btn-sm btn-ghost" href="/admin?tab=users&amp;user={{.ID}}">Details</a></td>
              </tr>
            {{else}}
              <tr><td colspan="5" class="hint">Noch keine Nutzer vorhanden.</td></tr>
            {{end}}
            </tbody>
          </table>
        </div>

        {{with .SelectedUser}}
          {{$selected := .}}
          <div class="panel">
            <div class="panel-head">
              <h3>{{.Email}}</h3>
              {{if .IsAdmin}}<span class="pill pill-info">Admin</span>{{end}}
            </div>
            <div class="panel-body stack">
              <div class="kv-mini">
                <span><span class="k">ID</span> <code>{{.ID}}</code></span>
                <span><span class="k">Gruppen</span> {{if .Groups}}{{.Groups}}{{else}}keine{{end}}</span>
                <span><span class="k">Erstellt</span> {{.CreatedAt}} &middot; Aktualisiert {{.UpdatedAt}}</span>
              </div>

              <details open>
                <summary>Nutzerrechte und Gruppen</summary>
                <div class="stack" style="margin-top:.8rem;">
                  <form method="post" action="/admin/users/groups">
                    <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                    <input type="hidden" name="user_id" value="{{.ID}}">
                    <label>Gruppen</label>
                    <div class="field-grid" style="margin-top:.4rem;">
                      {{range $.Groups}}
                        <label class="checkbox-row" style="margin-top:0;"><input type="checkbox" name="group_ids" value="{{.ID}}" {{if has $selected.GroupIDs .ID}}checked{{end}}><span>{{.Name}}</span></label>
                      {{else}}
                        <p class="hint">Noch keine Gruppen angelegt.</p>
                      {{end}}
                    </div>
                    <button type="submit" class="btn btn-sm" style="margin-top:.8rem;">Gruppen speichern</button>
                  </form>

                  <form method="post" action="/admin/users/admin">
                    <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                    <input type="hidden" name="user_id" value="{{.ID}}">
                    <input type="hidden" name="is_admin" value="{{if .IsAdmin}}false{{else}}true{{end}}">
                    <button type="submit" class="btn btn-sm">{{if .IsAdmin}}Admin-Rolle entfernen{{else}}Admin-Rolle geben{{end}}</button>
                  </form>
                </div>
              </details>

              <details>
                <summary>Passwort und Konto</summary>
                <div class="stack" style="margin-top:.8rem;">
                  <form method="post" action="/admin/users/password">
                    <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                    <input type="hidden" name="user_id" value="{{.ID}}">
                    <div class="field" style="margin-top:0;">
                      <label for="password_{{.ID}}">Passwort zuruecksetzen</label>
                      <input id="password_{{.ID}}" name="password" type="password" minlength="10" placeholder="Neues Passwort" required>
                    </div>
                    <button type="submit" class="btn btn-sm" style="margin-top:.6rem;">Passwort setzen</button>
                  </form>

                  <form method="post" action="/admin/users/delete">
                    <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                    <input type="hidden" name="user_id" value="{{.ID}}">
                    <button type="submit" class="btn btn-sm btn-danger">Nutzer loeschen</button>
                  </form>
                </div>
              </details>

              <details open>
                <summary>Registrierte Clients / Geraete</summary>
                {{if .Devices}}
                  <table style="margin-top:.8rem;">
                    <thead><tr><th>Client</th><th>Resource</th><th>Zuletzt</th><th>Gueltig bis</th><th></th></tr></thead>
                    <tbody>
                      {{range .Devices}}
                        <tr>
                          <td><div class="row-title">{{.ClientName}}</div><div class="row-sub mono">{{.ClientID}}</div></td>
                          <td><code>{{.Resource}}</code><div class="row-sub">Scopes: {{.Scope}} &middot; Tokens: {{.TokenCount}}</div></td>
                          <td>{{.LastUsedAt}}</td>
                          <td>{{.RefreshExpiresAt}}</td>
                          <td>
                            <form method="post" action="/admin/users/devices/delete">
                              <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                              <input type="hidden" name="user_id" value="{{$selected.ID}}">
                              <input type="hidden" name="device_id" value="{{.ID}}">
                              <button type="submit" class="btn btn-sm btn-danger">Widerrufen</button>
                            </form>
                          </td>
                        </tr>
                      {{end}}
                    </tbody>
                  </table>
                {{else}}
                  <p class="hint" style="margin-top:.7rem;">Dieser Nutzer hat noch keine OAuth-Clients autorisiert.</p>
                {{end}}
              </details>
            </div>
          </div>
        {{else}}
          <div class="empty"><p class="muted">Waehle einen Nutzer aus, um Gruppen, Rolle, Passwort und registrierte Clients zu verwalten.</p></div>
        {{end}}
      </div>

      <div class="stack">
        <div class="panel">
          <div class="panel-head"><h3>Gruppen</h3></div>
          <div class="panel-body stack">
            <form method="post" action="/admin/groups/create">
              <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
              <div class="field" style="margin-top:0;">
                <label for="group_name">Neue Gruppe</label>
                <input id="group_name" name="name" type="text" placeholder="Legal Team" required>
              </div>
              <button type="submit" class="btn btn-sm" style="margin-top:.6rem;">Gruppe anlegen</button>
            </form>
            <div class="stack-sm">
              {{range .Groups}}
                <div class="table-card" style="padding:.8rem 1rem; display:flex; align-items:center; justify-content:space-between; gap:.8rem;">
                  <div>
                    <div class="row-title">{{.Name}}</div>
                    <div class="row-sub mono">{{.ID}} &middot; {{.MemberCount}} Mitglieder</div>
                  </div>
                  <form method="post" action="/admin/groups/delete">
                    <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                    <input type="hidden" name="group_id" value="{{.ID}}">
                    <button type="submit" class="btn btn-sm btn-danger">L&ouml;schen</button>
                  </form>
                </div>
              {{else}}
                <p class="hint">Noch keine Gruppen angelegt.</p>
              {{end}}
            </div>
          </div>
        </div>

        <div class="panel">
          <div class="panel-head"><h3>Neuen Nutzer anlegen</h3></div>
          <div class="panel-body">
            <p class="hint">Auch moeglich, wenn Self-Signup deaktiviert ist.</p>
            <form method="post" action="/admin/users/create" style="margin-top:.8rem;">
              <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
              <div class="field" style="margin-top:0;">
                <label for="user_email">Email</label>
                <input id="user_email" name="email" type="email" required>
              </div>
              <div class="field">
                <label for="user_password">Passwort</label>
                <input id="user_password" name="password" type="password" minlength="10" required>
              </div>
              <label class="checkbox-row"><input id="user_is_admin" name="is_admin" type="checkbox"><span>Admin-Rechte direkt vergeben</span></label>
              <button type="submit" class="btn btn-sm" style="margin-top:.8rem;">Nutzer anlegen</button>
            </form>
          </div>
        </div>
      </div>
    </div>

    {{end}}

      </div>
    </div>
  </div>

  <div class="confirm-overlay" id="confirm-overlay" hidden>
    <div class="confirm-card">
      <h3>Ungespeicherte &Auml;nderungen</h3>
      <p class="muted" style="margin-top:.4rem;">Diese Route hat ungespeicherte &Auml;nderungen. Was m&ouml;chtest du tun, bevor du wechselst?</p>
      <div class="confirm-actions">
        <button type="button" class="btn btn-sm" id="confirm-cancel">Abbrechen</button>
        <button type="button" class="btn btn-sm btn-danger" id="confirm-discard">Verwerfen &amp; wechseln</button>
        <button type="button" class="btn btn-sm btn-primary" id="confirm-save">Speichern &amp; wechseln</button>
      </div>
    </div>
  </div>

  ` + webui.DynGroupScript + `
  <script>
    (function () {
      wireDynGroup('route_transport');
      wireDynGroup('deploy_transport');
      wireDynGroup('stdio_install_source_kind');
      wireDynGroup('build_source_kind');

      // ---- Build & Stdio: choose which panel to show ----
      var choices = document.querySelectorAll('.build-choice');
      var buildPanels = document.querySelectorAll('[data-build-panel]');
      choices.forEach(function (choice) {
        choice.addEventListener('click', function () {
          var mode = choice.getAttribute('data-build-choice');
          choices.forEach(function (c) { c.classList.toggle('is-active', c === choice); });
          buildPanels.forEach(function (p) { p.hidden = p.getAttribute('data-build-panel') !== mode; });
        });
      });

      // ---- route editor: dirty tracking + ask before switching away ----
      var form = document.getElementById('routeForm');
      if (!form) return;
      var dirtyHint = document.getElementById('rf-dirty-hint');
      var nextRouteInput = document.getElementById('next_route');
      var isDirty = false;

      function setDirty(v) { isDirty = v; if (dirtyHint) dirtyHint.hidden = !v; }
      form.addEventListener('input', function () { setDirty(true); });
      form.addEventListener('change', function () { setDirty(true); });

      document.querySelectorAll('.discard-link').forEach(function (a) {
        a.addEventListener('click', function () { isDirty = false; });
      });

      var overlay = document.getElementById('confirm-overlay');
      var pendingHref = null, pendingNext = null;
      function showConfirm(href, next) { pendingHref = href; pendingNext = next; overlay.hidden = false; }
      function hideConfirm() { pendingHref = null; pendingNext = null; overlay.hidden = true; }

      document.querySelectorAll('.dirty-guard').forEach(function (a) {
        a.addEventListener('click', function (e) {
          if (!isDirty) return;
          e.preventDefault();
          showConfirm(a.getAttribute('href'), a.getAttribute('data-next'));
        });
      });

      var cancelBtn = document.getElementById('confirm-cancel');
      var discardBtn = document.getElementById('confirm-discard');
      var saveBtn = document.getElementById('confirm-save');
      if (cancelBtn) cancelBtn.addEventListener('click', hideConfirm);
      if (discardBtn) discardBtn.addEventListener('click', function () {
        var href = pendingHref;
        isDirty = false;
        hideConfirm();
        if (href) window.location.href = href;
      });
      if (saveBtn) saveBtn.addEventListener('click', function () {
        if (nextRouteInput) nextRouteInput.value = pendingNext || '';
        isDirty = false;
        overlay.hidden = true;
        form.requestSubmit();
      });

      window.addEventListener('beforeunload', function (e) {
        if (isDirty) { e.preventDefault(); e.returnValue = ''; }
      });
    })();
  </script>
</body>
</html>
`
