package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName = "mcp_gateway_session"
	csrfCookieName    = "mcp_gateway_csrf"
)

var (
	ErrNotAuthenticated = errors.New("not authenticated")
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenExpired     = errors.New("token expired")
	ErrInvalidClient    = errors.New("invalid client")
	ErrInvalidGrant     = errors.New("invalid grant")
)

type Config struct {
	StorePath            string
	MasterKey            []byte
	AccessTokenTTL       time.Duration
	RefreshTokenTTL      time.Duration
	AuthorizationCodeTTL time.Duration
	SessionTTL           time.Duration
	PublicBaseURL        string
	PortalTitle          string
	AllowSelfSignup      bool
	BootstrapEmail       string
	BootstrapPassword    string
	AllowedEmails        []string
	AllowedEmailDomains  []string
}

type Manager struct {
	cfg Config

	mu   sync.Mutex
	data *storeData
}

type Identity struct {
	UserID  string
	Email   string
	IsAdmin bool
}

type contextKey string

const identityContextKey contextKey = "mcp_gateway_identity"

type storeData struct {
	Users         map[string]*userRecord         `json:"users"`
	EmailIndex    map[string]string              `json:"email_index"`
	Sessions      map[string]*sessionRecord      `json:"sessions"`
	Clients       map[string]*clientRecord       `json:"clients"`
	AuthCodes     map[string]*authCodeRecord     `json:"auth_codes"`
	AccessTokens  map[string]*accessTokenRecord  `json:"access_tokens"`
	RefreshTokens map[string]*refreshTokenRecord `json:"refresh_tokens"`
}

type encryptedStoreFile struct {
	Version    int    `json:"version"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type userRecord struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
	IsAdmin      bool   `json:"is_admin"`
	CreatedAt    int64  `json:"created_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

type sessionRecord struct {
	Token     string `json:"token"`
	UserID    string `json:"user_id"`
	ExpiresAt int64  `json:"expires_at"`
}

type clientRecord struct {
	ID                      string   `json:"id"`
	Name                    string   `json:"name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	CreatedAt               int64    `json:"created_at"`
}

type authCodeRecord struct {
	Code                string `json:"code"`
	ClientID            string `json:"client_id"`
	UserID              string `json:"user_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	Resource            string `json:"resource"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	ExpiresAt           int64  `json:"expires_at"`
}

type accessTokenRecord struct {
	Token     string `json:"token"`
	ClientID  string `json:"client_id"`
	UserID    string `json:"user_id"`
	Scope     string `json:"scope"`
	Resource  string `json:"resource"`
	ExpiresAt int64  `json:"expires_at"`
	IssuedAt  int64  `json:"issued_at"`
}

type refreshTokenRecord struct {
	Token     string `json:"token"`
	ClientID  string `json:"client_id"`
	UserID    string `json:"user_id"`
	Scope     string `json:"scope"`
	Resource  string `json:"resource"`
	ExpiresAt int64  `json:"expires_at"`
	IssuedAt  int64  `json:"issued_at"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type authorizeParams struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	State               string
	Scope               string
	Resource            string
	CodeChallenge       string
	CodeChallengeMethod string
}

func NewManager(cfg Config) (*Manager, error) {
	manager := &Manager{
		cfg: cfg,
		data: &storeData{
			Users:         make(map[string]*userRecord),
			EmailIndex:    make(map[string]string),
			Sessions:      make(map[string]*sessionRecord),
			Clients:       make(map[string]*clientRecord),
			AuthCodes:     make(map[string]*authCodeRecord),
			AccessTokens:  make(map[string]*accessTokenRecord),
			RefreshTokens: make(map[string]*refreshTokenRecord),
		},
	}

	if err := manager.load(); err != nil {
		return nil, err
	}
	if err := manager.ensureBootstrapUser(cfg.BootstrapEmail, cfg.BootstrapPassword); err != nil {
		return nil, err
	}

	return manager, nil
}

func (m *Manager) ChallengeHeader(resourceMetadataURL string, scope string) string {
	if strings.TrimSpace(scope) == "" {
		return fmt.Sprintf(`Bearer realm="mcp-oauth-gateway", resource_metadata="%s"`, resourceMetadataURL)
	}
	return fmt.Sprintf(`Bearer realm="mcp-oauth-gateway", resource_metadata="%s", scope="%s"`, resourceMetadataURL, scope)
}

func (m *Manager) HandleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}

	baseURL := m.baseURL(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                 baseURL,
		"authorization_endpoint": baseURL + "/authorize",
		"token_endpoint":         baseURL + "/token",
		"registration_endpoint":  baseURL + "/register",
		"registration_endpoint_auth_methods_supported": []string{"none"},
		"response_types_supported":                     []string{"code"},
		"grant_types_supported":                        []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported":        []string{"none"},
		"code_challenge_methods_supported":             []string{"S256"},
		"scopes_supported":                             []string{"mcp"},
		"subject_types_supported":                      []string{"public"},
		"client_id_metadata_document_supported":        false,
	})
}

func (m *Manager) HandleOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	m.HandleAuthorizationServerMetadata(w, r)
}

func (m *Manager) WriteProtectedResourceMetadata(w http.ResponseWriter, r *http.Request, resourceURL string, scopes []string, authorizationServers []string, documentationURL string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}

	if len(authorizationServers) == 0 {
		authorizationServers = []string{m.baseURL(r)}
	}
	payload := map[string]any{
		"resource":                 resourceURL,
		"authorization_servers":    authorizationServers,
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         scopes,
	}
	if strings.TrimSpace(documentationURL) != "" {
		payload["resource_documentation"] = documentationURL
	}

	writeJSON(w, http.StatusOK, payload)
}

func (m *Manager) HandleClientRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		ClientName              string   `json:"client_name"`
		RedirectURIs            []string `json:"redirect_uris"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid JSON payload")
		return
	}

	client, err := m.registerClient(payload.ClientName, payload.RedirectURIs, payload.GrantTypes, payload.ResponseTypes, payload.TokenEndpointAuthMethod)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  client.ID,
		"client_name":                client.Name,
		"redirect_uris":              client.RedirectURIs,
		"grant_types":                client.GrantTypes,
		"response_types":             client.ResponseTypes,
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		"client_id_issued_at":        client.CreatedAt,
	})
}

func (m *Manager) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		m.handleAuthorizeGet(w, r)
	case http.MethodPost:
		m.handleAuthorizePost(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
	}
}

func (m *Manager) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}

	setNoStoreHeaders(w)

	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}

	switch r.FormValue("grant_type") {
	case "authorization_code":
		m.handleAuthorizationCodeExchange(w, r)
	case "refresh_token":
		m.handleRefreshTokenExchange(w, r)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

func (m *Manager) HandleAccountRegister(w http.ResponseWriter, r *http.Request) {
	if !m.cfg.AllowSelfSignup {
		http.Error(w, "self-signup is disabled", http.StatusForbidden)
		return
	}

	switch r.Method {
	case http.MethodGet:
		csrfToken := ensureCSRFCookie(w, r)
		renderHTML(w, registerTemplate, map[string]any{
			"CSRFToken": csrfToken,
			"Next":      r.URL.Query().Get("next"),
			"Title":     m.cfg.PortalTitle,
		})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if !validateCSRFCookie(r) {
			http.Error(w, "invalid CSRF token", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")
		next := sanitizeNext(r.FormValue("next"))

		user, err := m.registerUser(email, password)
		if err != nil {
			renderHTML(w, registerTemplate, map[string]any{
				"CSRFToken": ensureCSRFCookie(w, r),
				"Next":      next,
				"Error":     err.Error(),
				"Email":     email,
				"Title":     m.cfg.PortalTitle,
			})
			return
		}
		if err := m.startSession(w, r, user.ID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if next == "" {
			next = "/account"
		}
		http.Redirect(w, r, next, http.StatusFound)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
	}
}

func (m *Manager) HandleAccountLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		renderHTML(w, loginTemplate, map[string]any{
			"CSRFToken": ensureCSRFCookie(w, r),
			"Next":      r.URL.Query().Get("next"),
			"Title":     m.cfg.PortalTitle,
		})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if !validateCSRFCookie(r) {
			http.Error(w, "invalid CSRF token", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")
		next := sanitizeNext(r.FormValue("next"))

		user, err := m.authenticateUser(email, password)
		if err != nil {
			renderHTML(w, loginTemplate, map[string]any{
				"CSRFToken": ensureCSRFCookie(w, r),
				"Next":      next,
				"Error":     "Invalid email or password",
				"Email":     email,
				"Title":     m.cfg.PortalTitle,
			})
			return
		}
		if err := m.startSession(w, r, user.ID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if next == "" {
			next = "/account"
		}
		http.Redirect(w, r, next, http.StatusFound)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
	}
}

func (m *Manager) HandleAccountLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRFCookie(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		_ = m.deleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		Secure:   requestIsSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/account/login", http.StatusFound)
}

func (m *Manager) HandleAccount(w http.ResponseWriter, r *http.Request) {
	identity, err := m.identityFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/account/login?next="+url.QueryEscape("/account"), http.StatusFound)
		return
	}

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}

	renderHTML(w, accountTemplate, map[string]any{
		"CSRFToken": ensureCSRFCookie(w, r),
		"Email":     identity.Email,
		"IsAdmin":   identity.IsAdmin,
		"Title":     m.cfg.PortalTitle,
	})
}

func (m *Manager) ValidateAccessToken(token, resource string) (*Identity, error) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)

	record, ok := m.data.AccessTokens[token]
	if !ok {
		return nil, ErrInvalidToken
	}
	if record.ExpiresAt <= now.Unix() {
		delete(m.data.AccessTokens, token)
		_ = m.saveLocked()
		return nil, ErrTokenExpired
	}
	if normalizeResource(record.Resource) != normalizeResource(resource) {
		return nil, ErrInvalidToken
	}

	user, ok := m.data.Users[record.UserID]
	if !ok {
		return nil, ErrInvalidToken
	}

	return &Identity{
		UserID:  user.ID,
		Email:   user.Email,
		IsAdmin: user.IsAdmin,
	}, nil
}

func WithIdentity(ctx context.Context, identity *Identity) context.Context {
	return context.WithValue(ctx, identityContextKey, identity)
}

func IdentityFromContext(ctx context.Context) *Identity {
	value := ctx.Value(identityContextKey)
	identity, _ := value.(*Identity)
	return identity
}

func BaseURLFromRequest(r *http.Request) string {
	scheme := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}

	return scheme + "://" + host
}

func requestIsSecure(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") || r.TLS != nil
}

func (m *Manager) baseURL(r *http.Request) string {
	if strings.TrimSpace(m.cfg.PublicBaseURL) != "" {
		return strings.TrimRight(strings.TrimSpace(m.cfg.PublicBaseURL), "/")
	}
	return BaseURLFromRequest(r)
}

func (m *Manager) load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	payload, err := os.ReadFile(m.cfg.StorePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to read auth store: %w", err)
	}

	var stored encryptedStoreFile
	if err := json.Unmarshal(payload, &stored); err != nil {
		return fmt.Errorf("failed to decode auth store metadata: %w", err)
	}

	nonce, err := base64.RawStdEncoding.DecodeString(stored.Nonce)
	if err != nil {
		return fmt.Errorf("failed to decode auth store nonce: %w", err)
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(stored.Ciphertext)
	if err != nil {
		return fmt.Errorf("failed to decode auth store ciphertext: %w", err)
	}

	plaintext, err := decrypt(m.cfg.MasterKey, nonce, ciphertext)
	if err != nil {
		return fmt.Errorf("failed to decrypt auth store: %w", err)
	}

	var data storeData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return fmt.Errorf("failed to decode auth store: %w", err)
	}

	if data.Users == nil {
		data.Users = make(map[string]*userRecord)
	}
	if data.EmailIndex == nil {
		data.EmailIndex = make(map[string]string)
	}
	if data.Sessions == nil {
		data.Sessions = make(map[string]*sessionRecord)
	}
	if data.Clients == nil {
		data.Clients = make(map[string]*clientRecord)
	}
	if data.AuthCodes == nil {
		data.AuthCodes = make(map[string]*authCodeRecord)
	}
	if data.AccessTokens == nil {
		data.AccessTokens = make(map[string]*accessTokenRecord)
	}
	if data.RefreshTokens == nil {
		data.RefreshTokens = make(map[string]*refreshTokenRecord)
	}

	m.data = &data
	m.cleanupLocked(time.Now())
	return nil
}

func (m *Manager) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(m.cfg.StorePath), 0o755); err != nil {
		return fmt.Errorf("failed to create auth store directory: %w", err)
	}

	plaintext, err := json.Marshal(m.data)
	if err != nil {
		return fmt.Errorf("failed to encode auth store: %w", err)
	}

	nonce, ciphertext, err := encrypt(m.cfg.MasterKey, plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt auth store: %w", err)
	}

	stored := encryptedStoreFile{
		Version:    1,
		Nonce:      base64.RawStdEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext),
	}

	payload, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode auth store file: %w", err)
	}

	tempPath := m.cfg.StorePath + ".tmp"
	if err := os.WriteFile(tempPath, payload, 0o600); err != nil {
		return fmt.Errorf("failed to write auth store: %w", err)
	}
	if err := os.Rename(tempPath, m.cfg.StorePath); err != nil {
		return fmt.Errorf("failed to replace auth store: %w", err)
	}
	return nil
}

func (m *Manager) cleanupLocked(now time.Time) {
	nowUnix := now.Unix()

	for token, session := range m.data.Sessions {
		if session.ExpiresAt <= nowUnix {
			delete(m.data.Sessions, token)
		}
	}
	for code, record := range m.data.AuthCodes {
		if record.ExpiresAt <= nowUnix {
			delete(m.data.AuthCodes, code)
		}
	}
	for token, record := range m.data.AccessTokens {
		if record.ExpiresAt <= nowUnix {
			delete(m.data.AccessTokens, token)
		}
	}
	for token, record := range m.data.RefreshTokens {
		if record.ExpiresAt <= nowUnix {
			delete(m.data.RefreshTokens, token)
		}
	}
}

func (m *Manager) registerClient(name string, redirectURIs, grantTypes, responseTypes []string, authMethod string) (*clientRecord, error) {
	if strings.TrimSpace(name) == "" {
		name = "MCP Client"
	}
	if len(redirectURIs) == 0 {
		return nil, fmt.Errorf("redirect_uris must not be empty")
	}
	for _, redirectURI := range redirectURIs {
		if err := validateRedirectURI(redirectURI); err != nil {
			return nil, err
		}
	}

	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}
	if authMethod == "" {
		authMethod = "none"
	}
	if authMethod != "none" {
		return nil, fmt.Errorf("only token_endpoint_auth_method=none is supported")
	}

	now := time.Now()
	client := &clientRecord{
		ID:                      randomToken(24),
		Name:                    name,
		RedirectURIs:            dedupeStrings(redirectURIs),
		GrantTypes:              dedupeStrings(grantTypes),
		ResponseTypes:           dedupeStrings(responseTypes),
		TokenEndpointAuthMethod: authMethod,
		CreatedAt:               now.Unix(),
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)
	m.data.Clients[client.ID] = client
	if err := m.saveLocked(); err != nil {
		return nil, err
	}
	return client, nil
}

func (m *Manager) handleAuthorizeGet(w http.ResponseWriter, r *http.Request) {
	params, client, err := m.parseAuthorizeRequest(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	identity, _ := m.identityFromSession(r)
	if identity == nil {
		http.Redirect(w, r, "/account/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}

	csrfToken := ensureCSRFCookie(w, r)
	renderHTML(w, authorizeTemplate, map[string]any{
		"ClientName":          client.Name,
		"Resource":            params.Resource,
		"Scope":               params.Scope,
		"State":               params.State,
		"CSRFToken":           csrfToken,
		"ClientID":            params.ClientID,
		"RedirectURI":         params.RedirectURI,
		"ResponseType":        params.ResponseType,
		"CodeChallenge":       params.CodeChallenge,
		"CodeChallengeMethod": params.CodeChallengeMethod,
		"ResourceValue":       params.Resource,
		"ScopeValue":          params.Scope,
		"Email":               identity.Email,
		"Title":               m.cfg.PortalTitle,
	})
}

func (m *Manager) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !validateCSRFCookie(r) {
		http.Error(w, "invalid CSRF token", http.StatusBadRequest)
		return
	}

	identity, err := m.identityFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/account/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}

	values := url.Values{}
	for _, key := range []string{"client_id", "redirect_uri", "response_type", "state", "scope", "resource", "code_challenge", "code_challenge_method"} {
		values.Set(key, r.FormValue(key))
	}

	params, _, err := m.parseAuthorizeRequest(values)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if r.FormValue("action") != "approve" {
		target, buildErr := buildOAuthErrorRedirectURL(params.RedirectURI, "access_denied", params.State)
		if buildErr != nil {
			http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
			return
		}
		completeBrowserRedirect(w, target, "Access denied")
		return
	}

	code, err := m.createAuthorizationCode(identity.UserID, params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	target, err := buildOAuthCodeRedirectURL(params.RedirectURI, code, params.State)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	completeBrowserRedirect(w, target, "Authorization complete")
}

func (m *Manager) parseAuthorizeRequest(values url.Values) (*authorizeParams, *clientRecord, error) {
	params := &authorizeParams{
		ClientID:            strings.TrimSpace(values.Get("client_id")),
		RedirectURI:         strings.TrimSpace(values.Get("redirect_uri")),
		ResponseType:        strings.TrimSpace(values.Get("response_type")),
		State:               strings.TrimSpace(values.Get("state")),
		Scope:               strings.TrimSpace(values.Get("scope")),
		Resource:            strings.TrimSpace(values.Get("resource")),
		CodeChallenge:       strings.TrimSpace(values.Get("code_challenge")),
		CodeChallengeMethod: strings.TrimSpace(values.Get("code_challenge_method")),
	}

	if params.ClientID == "" || params.RedirectURI == "" {
		return nil, nil, fmt.Errorf("client_id and redirect_uri are required")
	}
	if params.ResponseType != "code" {
		return nil, nil, fmt.Errorf("response_type must be code")
	}
	if params.Resource == "" {
		return nil, nil, fmt.Errorf("resource is required")
	}
	if params.CodeChallenge == "" || params.CodeChallengeMethod != "S256" {
		return nil, nil, fmt.Errorf("PKCE with code_challenge_method=S256 is required")
	}

	client, err := m.lookupClient(params.ClientID)
	if err != nil {
		return nil, nil, err
	}
	if !slices.Contains(client.RedirectURIs, params.RedirectURI) {
		return nil, nil, fmt.Errorf("redirect_uri is not registered for this client")
	}
	if err := validateAbsoluteResource(params.Resource); err != nil {
		return nil, nil, err
	}
	if params.Scope == "" {
		params.Scope = "mcp"
	}

	return params, client, nil
}

func (m *Manager) lookupClient(clientID string) (*clientRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(time.Now())

	client, ok := m.data.Clients[clientID]
	if !ok {
		return nil, ErrInvalidClient
	}
	return client, nil
}

func (m *Manager) createAuthorizationCode(userID string, params *authorizeParams) (string, error) {
	now := time.Now()
	record := &authCodeRecord{
		Code:                randomToken(32),
		ClientID:            params.ClientID,
		UserID:              userID,
		RedirectURI:         params.RedirectURI,
		Scope:               params.Scope,
		Resource:            params.Resource,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		ExpiresAt:           now.Add(m.cfg.AuthorizationCodeTTL).Unix(),
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)
	m.data.AuthCodes[record.Code] = record
	return record.Code, m.saveLocked()
}

func (m *Manager) handleAuthorizationCodeExchange(w http.ResponseWriter, r *http.Request) {
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	code := strings.TrimSpace(r.FormValue("code"))
	redirectURI := strings.TrimSpace(r.FormValue("redirect_uri"))
	codeVerifier := strings.TrimSpace(r.FormValue("code_verifier"))
	resource := strings.TrimSpace(r.FormValue("resource"))

	if clientID == "" || code == "" || redirectURI == "" || codeVerifier == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id, code, redirect_uri and code_verifier are required")
		return
	}

	response, err := m.exchangeAuthorizationCode(clientID, code, redirectURI, codeVerifier, resource)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidClient):
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		case errors.Is(err, ErrInvalidGrant), errors.Is(err, ErrTokenExpired):
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		default:
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		}
		return
	}

	writeJSON(w, http.StatusOK, response)
}

func (m *Manager) exchangeAuthorizationCode(clientID, code, redirectURI, codeVerifier, resource string) (*tokenResponse, error) {
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)

	client, ok := m.data.Clients[clientID]
	if !ok {
		return nil, ErrInvalidClient
	}
	record, ok := m.data.AuthCodes[code]
	if !ok {
		return nil, ErrInvalidGrant
	}
	if record.ExpiresAt <= now.Unix() {
		delete(m.data.AuthCodes, code)
		_ = m.saveLocked()
		return nil, ErrTokenExpired
	}
	if record.ClientID != client.ID || record.RedirectURI != redirectURI {
		return nil, ErrInvalidGrant
	}
	if resource != "" && normalizeResource(resource) != normalizeResource(record.Resource) {
		return nil, ErrInvalidGrant
	}
	if !validatePKCE(record.CodeChallenge, codeVerifier) {
		return nil, ErrInvalidGrant
	}

	delete(m.data.AuthCodes, code)
	tokenSet := m.issueTokenSetLocked(now, record.UserID, client.ID, record.Scope, record.Resource)
	if err := m.saveLocked(); err != nil {
		return nil, err
	}
	return tokenSet, nil
}

func (m *Manager) handleRefreshTokenExchange(w http.ResponseWriter, r *http.Request) {
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	refreshToken := strings.TrimSpace(r.FormValue("refresh_token"))
	resource := strings.TrimSpace(r.FormValue("resource"))

	if clientID == "" || refreshToken == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id and refresh_token are required")
		return
	}

	response, err := m.refreshToken(clientID, refreshToken, resource)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidClient):
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		case errors.Is(err, ErrInvalidGrant), errors.Is(err, ErrTokenExpired):
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		default:
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		}
		return
	}

	writeJSON(w, http.StatusOK, response)
}

func (m *Manager) refreshToken(clientID, refreshToken, resource string) (*tokenResponse, error) {
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)

	client, ok := m.data.Clients[clientID]
	if !ok {
		return nil, ErrInvalidClient
	}
	record, ok := m.data.RefreshTokens[refreshToken]
	if !ok {
		return nil, ErrInvalidGrant
	}
	if record.ExpiresAt <= now.Unix() {
		delete(m.data.RefreshTokens, refreshToken)
		_ = m.saveLocked()
		return nil, ErrTokenExpired
	}
	if record.ClientID != client.ID {
		return nil, ErrInvalidGrant
	}
	if resource != "" && normalizeResource(resource) != normalizeResource(record.Resource) {
		return nil, ErrInvalidGrant
	}

	delete(m.data.RefreshTokens, refreshToken)
	tokenSet := m.issueTokenSetLocked(now, record.UserID, client.ID, record.Scope, record.Resource)
	if err := m.saveLocked(); err != nil {
		return nil, err
	}
	return tokenSet, nil
}

func (m *Manager) issueTokenSetLocked(now time.Time, userID, clientID, scope, resource string) *tokenResponse {
	accessToken := randomToken(32)
	refreshToken := randomToken(48)

	m.data.AccessTokens[accessToken] = &accessTokenRecord{
		Token:     accessToken,
		ClientID:  clientID,
		UserID:    userID,
		Scope:     scope,
		Resource:  resource,
		ExpiresAt: now.Add(m.cfg.AccessTokenTTL).Unix(),
		IssuedAt:  now.Unix(),
	}
	m.data.RefreshTokens[refreshToken] = &refreshTokenRecord{
		Token:     refreshToken,
		ClientID:  clientID,
		UserID:    userID,
		Scope:     scope,
		Resource:  resource,
		ExpiresAt: now.Add(m.cfg.RefreshTokenTTL).Unix(),
		IssuedAt:  now.Unix(),
	}

	return &tokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(m.cfg.AccessTokenTTL.Seconds()),
		RefreshToken: refreshToken,
		Scope:        scope,
	}
}

func (m *Manager) registerUser(email, password string) (*userRecord, error) {
	return m.createUser(email, password, false, true)
}

func (m *Manager) ensureBootstrapUser(email, password string) error {
	email = normalizeEmail(email)
	if email == "" && password == "" {
		return nil
	}
	if email == "" || password == "" {
		return fmt.Errorf("bootstrap email and password must both be configured")
	}
	if !strings.Contains(email, "@") {
		return fmt.Errorf("bootstrap email must be a valid email address")
	}
	if len(password) < 10 {
		return fmt.Errorf("bootstrap password must be at least 10 characters long")
	}

	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)

	if userID, exists := m.data.EmailIndex[email]; exists {
		if existing, ok := m.data.Users[userID]; ok {
			if !existing.IsAdmin {
				existing.IsAdmin = true
				existing.UpdatedAt = now.Unix()
				return m.saveLocked()
			}
			return nil
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash bootstrap password: %w", err)
	}

	user := &userRecord{
		ID:           randomToken(18),
		Email:        email,
		PasswordHash: string(hash),
		IsAdmin:      true,
		CreatedAt:    now.Unix(),
		UpdatedAt:    now.Unix(),
	}

	m.data.Users[user.ID] = user
	m.data.EmailIndex[email] = user.ID
	return m.saveLocked()
}

func (m *Manager) emailAllowed(email string) bool {
	if len(m.cfg.AllowedEmails) == 0 && len(m.cfg.AllowedEmailDomains) == 0 {
		return true
	}
	for _, allowed := range m.cfg.AllowedEmails {
		if email == strings.ToLower(strings.TrimSpace(allowed)) {
			return true
		}
	}
	at := strings.LastIndex(email, "@")
	if at == -1 {
		return false
	}
	domain := email[at+1:]
	for _, allowed := range m.cfg.AllowedEmailDomains {
		if domain == strings.ToLower(strings.TrimSpace(allowed)) {
			return true
		}
	}
	return false
}

func (m *Manager) authenticateUser(email, password string) (*userRecord, error) {
	email = normalizeEmail(email)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(time.Now())

	userID, ok := m.data.EmailIndex[email]
	if !ok {
		return nil, ErrNotAuthenticated
	}
	user, ok := m.data.Users[userID]
	if !ok {
		return nil, ErrNotAuthenticated
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, ErrNotAuthenticated
	}
	return user, nil
}

func (m *Manager) startSession(w http.ResponseWriter, r *http.Request, userID string) error {
	now := time.Now()
	session := &sessionRecord{
		Token:     randomToken(32),
		UserID:    userID,
		ExpiresAt: now.Add(m.cfg.SessionTTL).Unix(),
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)
	m.data.Sessions[session.Token] = session
	if err := m.saveLocked(); err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    session.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsSecure(r),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(session.ExpiresAt, 0),
	})
	return nil
}

func (m *Manager) deleteSession(token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data.Sessions, token)
	return m.saveLocked()
}

func (m *Manager) identityFromSession(r *http.Request) (*Identity, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, ErrNotAuthenticated
	}

	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)

	session, ok := m.data.Sessions[cookie.Value]
	if !ok {
		return nil, ErrNotAuthenticated
	}
	if session.ExpiresAt <= now.Unix() {
		delete(m.data.Sessions, cookie.Value)
		_ = m.saveLocked()
		return nil, ErrNotAuthenticated
	}
	user, ok := m.data.Users[session.UserID]
	if !ok {
		return nil, ErrNotAuthenticated
	}
	return &Identity{
		UserID:  user.ID,
		Email:   user.Email,
		IsAdmin: user.IsAdmin,
	}, nil
}

func validateRedirectURI(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid redirect_uri: %s", raw)
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1") {
		return nil
	}
	return fmt.Errorf("redirect_uri must use https or localhost http")
}

func validateAbsoluteResource(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("resource must be an absolute URL")
	}
	return nil
}

func normalizeResource(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	parsed.Fragment = ""
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return strings.TrimRight(parsed.String(), "/")
}

func validatePKCE(codeChallenge, verifier string) bool {
	sum := sha256.Sum256([]byte(verifier))
	calculated := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtleConstantTimeEqual(calculated, codeChallenge)
}

func subtleConstantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func encrypt(key, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	return nonce, gcm.Seal(nil, nonce, plaintext, nil), nil
}

func decrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func randomToken(numBytes int) string {
	buf := make([]byte, numBytes)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func ensureCSRFCookie(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie(csrfCookieName); err == nil && strings.TrimSpace(cookie.Value) != "" {
		return cookie.Value
	}

	token := randomToken(18)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   requestIsSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
	return token
}

func validateCSRFCookie(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return false
	}
	formToken := strings.TrimSpace(r.FormValue("csrf_token"))
	return subtleConstantTimeEqual(cookie.Value, formToken)
}

func sanitizeNext(next string) string {
	next = strings.TrimSpace(next)
	if next == "" {
		return ""
	}
	if strings.HasPrefix(next, "http://") || strings.HasPrefix(next, "https://") {
		return ""
	}
	if !strings.HasPrefix(next, "/") {
		return ""
	}
	return next
}

func buildOAuthCodeRedirectURL(redirectURI, code, state string) (string, error) {
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("code", code)
	if state != "" {
		query.Set("state", state)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func buildOAuthErrorRedirectURL(redirectURI, errCode, state string) (string, error) {
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("error", errCode)
	if state != "" {
		query.Set("state", state)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func completeBrowserRedirect(w http.ResponseWriter, targetURL, title string) {
	renderRedirectHTML(w, title, targetURL)
}

func writeOAuthError(w http.ResponseWriter, status int, errCode, description string) {
	writeJSON(w, status, map[string]any{
		"error":             errCode,
		"error_description": description,
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func renderHTML(w http.ResponseWriter, tmpl string, data map[string]any) {
	t := template.Must(template.New("page").Parse(layoutTemplate + tmpl))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; img-src 'self' data:; frame-ancestors 'none'")
	_ = t.Execute(w, data)
}

func renderRedirectHTML(w http.ResponseWriter, title, targetURL string) {
	t := template.Must(template.New("redirect").Parse(redirectTemplate))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; navigate-to 'self' *")
	_ = t.Execute(w, map[string]any{
		"Title":         title,
		"TargetURL":     template.URL(targetURL),
		"TargetURLJS":   template.JS(strconv.Quote(targetURL)),
		"TargetDisplay": targetURL,
	})
}

func setNoStoreHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

const layoutTemplate = `
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  <style>
    :root { color-scheme: light; font-family: ui-sans-serif, system-ui, sans-serif; }
    body { margin: 2rem auto; max-width: 44rem; padding: 0 1rem; line-height: 1.5; color: #122033; }
    h1 { font-size: 1.8rem; margin-bottom: 0.5rem; }
    .card { border: 1px solid #d3dae6; border-radius: 16px; padding: 1.25rem; box-shadow: 0 10px 25px rgba(18,32,51,0.06); }
    .muted { color: #596579; }
    .error { color: #8f1d1d; margin-bottom: 1rem; }
    .success { color: #116236; margin-bottom: 1rem; }
    label { display: block; margin: 0.85rem 0 0.25rem; font-weight: 600; }
    input[type="email"], input[type="password"], input[type="text"] {
      width: 100%; border: 1px solid #c2cbd8; border-radius: 10px; padding: 0.75rem 0.85rem; font: inherit;
      box-sizing: border-box;
    }
    button {
      margin-top: 1rem; background: #173b67; color: white; border: none; border-radius: 10px; padding: 0.75rem 1rem;
      font: inherit; cursor: pointer;
    }
    a { color: #173b67; }
    form { margin: 0; }
    code { background: #f2f5f9; padding: 0.1rem 0.35rem; border-radius: 6px; }
  </style>
</head>
<body>
  <div class="card">
    {{template "body" .}}
  </div>
</body>
</html>
`

const registerTemplate = `
{{define "body"}}
<h1>{{.Title}} Registration</h1>
<p class="muted">Create an account for the shared MCP OAuth gateway.</p>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
<form method="post" action="/account/register">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <input type="hidden" name="next" value="{{.Next}}">
  <label for="email">Email</label>
  <input id="email" name="email" type="email" value="{{.Email}}" required autocomplete="email">
  <label for="password">Password</label>
  <input id="password" name="password" type="password" required minlength="10" autocomplete="new-password">
  <button type="submit">Create account</button>
</form>
<p class="muted">Already registered? <a href="/account/login{{if .Next}}?next={{.Next}}{{end}}">Sign in</a></p>
{{end}}
`

const loginTemplate = `
{{define "body"}}
<h1>{{.Title}} Sign In</h1>
<p class="muted">Use your account to authorize MCP clients for protected upstream servers.</p>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
<form method="post" action="/account/login">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <input type="hidden" name="next" value="{{.Next}}">
  <label for="email">Email</label>
  <input id="email" name="email" type="email" value="{{.Email}}" required autocomplete="email">
  <label for="password">Password</label>
  <input id="password" name="password" type="password" required autocomplete="current-password">
  <button type="submit">Sign in</button>
</form>
{{if .Next}}<p class="muted">After sign-in you will return to the pending authorization request automatically.</p>{{end}}
{{end}}
`

const accountTemplate = `
{{define "body"}}
<h1>{{.Title}} Account</h1>
<p>Signed in as <strong>{{.Email}}</strong>.</p>
<p class="muted">This account can authorize MCP clients against the shared gateway for multiple upstream MCP servers.</p>
{{if .IsAdmin}}<p class="muted"><a href="/admin">Open the admin dashboard</a></p>{{end}}
<form method="post" action="/account/logout">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <button type="submit">Sign out</button>
</form>
{{end}}
`

const authorizeTemplate = `
{{define "body"}}
<h1>{{.Title}} Authorization</h1>
<p><strong>{{.ClientName}}</strong> wants access to:</p>
<p><code>{{.Resource}}</code></p>
<p class="muted">Requested scopes: <code>{{.Scope}}</code></p>
<p class="muted">Signed in as {{.Email}}</p>
<form method="post" action="/authorize">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <input type="hidden" name="client_id" value="{{.ClientID}}">
  <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
  <input type="hidden" name="response_type" value="{{.ResponseType}}">
  <input type="hidden" name="state" value="{{.State}}">
  <input type="hidden" name="scope" value="{{.ScopeValue}}">
  <input type="hidden" name="resource" value="{{.ResourceValue}}">
  <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
  <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
  <button type="submit" name="action" value="approve">Approve</button>
  <button type="submit" name="action" value="deny">Deny</button>
</form>
{{end}}
`

const redirectTemplate = `
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="referrer" content="no-referrer">
  <title>{{.Title}}</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; color: #122033; }
    code { background: #f2f5f9; padding: 0.1rem 0.35rem; border-radius: 6px; word-break: break-all; }
  </style>
  <script>
    (function () {
      var target = {{.TargetURLJS}};
      try { window.location.replace(target); } catch (e) {}
      try {
        if (window.top && window.top !== window) {
          window.top.location.href = target;
          return;
        }
      } catch (e) {}
      setTimeout(function () {
        try { window.location.href = target; } catch (e) {}
      }, 50);
    }());
  </script>
</head>
<body>
  <p>Redirecting... If nothing happens, <a href="{{.TargetURL}}">continue here</a>.</p>
  <p><code>{{.TargetDisplay}}</code></p>
</body>
</html>
`
