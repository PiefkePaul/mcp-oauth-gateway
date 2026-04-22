package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID         string
	Email      string
	IsAdmin    bool
	GroupIDs   []string
	GroupNames []string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type Group struct {
	ID          string
	Name        string
	MemberCount int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type UserDevice struct {
	ID               string
	ClientID         string
	ClientName       string
	Resource         string
	Scope            string
	RedirectURIs     []string
	TokenCount       int
	CreatedAt        time.Time
	LastUsedAt       time.Time
	RefreshExpiresAt time.Time
}

func (m *Manager) EnsureCSRFToken(w http.ResponseWriter, r *http.Request) string {
	return ensureCSRFCookie(w, r)
}

func (m *Manager) ValidateCSRF(r *http.Request) bool {
	return validateCSRFCookie(r)
}

func (m *Manager) CurrentIdentity(r *http.Request) (*Identity, error) {
	return m.identityFromSession(r)
}

func (m *Manager) ListUsers() []User {
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)

	users := make([]User, 0, len(m.data.Users))
	for _, user := range m.data.Users {
		users = append(users, m.userSummaryLocked(user))
	}
	slices.SortFunc(users, func(a, b User) int {
		switch {
		case a.Email < b.Email:
			return -1
		case a.Email > b.Email:
			return 1
		default:
			return 0
		}
	})
	return users
}

func (m *Manager) UserByID(userID string) (User, bool) {
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)

	user, ok := m.data.Users[userID]
	if !ok {
		return User{}, false
	}
	return m.userSummaryLocked(user), true
}

func (m *Manager) CreateUser(email, password string, isAdmin bool) (*User, error) {
	record, err := m.createUser(email, password, isAdmin, false)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	summary := m.userSummaryLocked(record)
	return &summary, nil
}

func (m *Manager) ListGroups() []Group {
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)

	groups := make([]Group, 0, len(m.data.Groups))
	for _, group := range m.data.Groups {
		groups = append(groups, m.groupSummaryLocked(group))
	}
	slices.SortFunc(groups, func(a, b Group) int {
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return groups
}

func (m *Manager) CreateGroup(name string) (*Group, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("group name is required")
	}

	now := time.Now()
	record := &groupRecord{
		ID:        randomToken(14),
		Name:      name,
		CreatedAt: now.Unix(),
		UpdatedAt: now.Unix(),
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)
	if m.groupNameExistsLocked(name, "") {
		return nil, fmt.Errorf("a group with this name already exists")
	}
	m.data.Groups[record.ID] = record
	if err := m.saveLocked(); err != nil {
		return nil, err
	}
	summary := m.groupSummaryLocked(record)
	return &summary, nil
}

func (m *Manager) DeleteGroup(groupID string) error {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)

	if _, ok := m.data.Groups[groupID]; !ok {
		return fmt.Errorf("group not found")
	}
	delete(m.data.Groups, groupID)
	for _, user := range m.data.Users {
		user.GroupIDs = removeString(user.GroupIDs, groupID)
		user.UpdatedAt = now.Unix()
	}
	return m.saveLocked()
}

func (m *Manager) SetUserGroups(userID string, groupIDs []string) error {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)

	user, ok := m.data.Users[userID]
	if !ok {
		return fmt.Errorf("user not found")
	}
	user.GroupIDs = filterExistingGroupIDs(groupIDs, m.data.Groups)
	user.UpdatedAt = now.Unix()
	return m.saveLocked()
}

func (m *Manager) SetUserPassword(userID, password string) error {
	if len(password) < 10 {
		return fmt.Errorf("password must be at least 10 characters long")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)

	user, ok := m.data.Users[userID]
	if !ok {
		return fmt.Errorf("user not found")
	}

	user.PasswordHash = string(hash)
	user.UpdatedAt = now.Unix()
	return m.saveLocked()
}

func (m *Manager) SetUserAdmin(userID string, isAdmin bool) error {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)

	user, ok := m.data.Users[userID]
	if !ok {
		return fmt.Errorf("user not found")
	}
	if user.IsAdmin && !isAdmin && m.adminCountLocked() <= 1 {
		return fmt.Errorf("at least one admin user must remain")
	}

	user.IsAdmin = isAdmin
	user.UpdatedAt = now.Unix()
	return m.saveLocked()
}

func (m *Manager) DeleteUser(userID string) error {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)

	user, ok := m.data.Users[userID]
	if !ok {
		return fmt.Errorf("user not found")
	}
	if user.IsAdmin && m.adminCountLocked() <= 1 {
		return fmt.Errorf("at least one admin user must remain")
	}

	delete(m.data.Users, userID)
	delete(m.data.EmailIndex, user.Email)
	for token, session := range m.data.Sessions {
		if session.UserID == userID {
			delete(m.data.Sessions, token)
		}
	}
	for code, record := range m.data.AuthCodes {
		if record.UserID == userID {
			delete(m.data.AuthCodes, code)
		}
	}
	for token, record := range m.data.AccessTokens {
		if record.UserID == userID {
			delete(m.data.AccessTokens, token)
		}
	}
	for token, record := range m.data.RefreshTokens {
		if record.UserID == userID {
			delete(m.data.RefreshTokens, token)
		}
	}
	return m.saveLocked()
}

func (m *Manager) ListUserDevices(userID string) []UserDevice {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)
	return m.userDevicesLocked(userID)
}

func (m *Manager) RevokeUserDevice(userID, deviceID string) error {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return fmt.Errorf("device_id is required")
	}

	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)

	if _, ok := m.data.Users[userID]; !ok {
		return fmt.Errorf("user not found")
	}

	removed := false
	for token, record := range m.data.RefreshTokens {
		if record.UserID == userID && grantDeviceID(record.UserID, record.ClientID, record.Resource) == deviceID {
			delete(m.data.RefreshTokens, token)
			removed = true
		}
	}
	for token, record := range m.data.AccessTokens {
		if record.UserID == userID && grantDeviceID(record.UserID, record.ClientID, record.Resource) == deviceID {
			delete(m.data.AccessTokens, token)
			removed = true
		}
	}
	for code, record := range m.data.AuthCodes {
		if record.UserID == userID && grantDeviceID(record.UserID, record.ClientID, record.Resource) == deviceID {
			delete(m.data.AuthCodes, code)
			removed = true
		}
	}
	if !removed {
		return fmt.Errorf("device not found")
	}
	return m.saveLocked()
}

func (m *Manager) createUser(email, password string, isAdmin bool, enforceAllowlist bool) (*userRecord, error) {
	email = normalizeEmail(email)
	if !stringsContainsAt(email) {
		return nil, fmt.Errorf("please provide a valid email address")
	}
	if len(password) < 10 {
		return nil, fmt.Errorf("password must be at least 10 characters long")
	}
	if enforceAllowlist && !m.emailAllowed(email) {
		return nil, fmt.Errorf("this email address is not allowed to register on this gateway")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now()
	user := &userRecord{
		ID:           randomToken(18),
		Email:        email,
		PasswordHash: string(hash),
		IsAdmin:      isAdmin,
		CreatedAt:    now.Unix(),
		UpdatedAt:    now.Unix(),
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(now)
	if _, exists := m.data.EmailIndex[email]; exists {
		return nil, fmt.Errorf("a user with this email already exists")
	}
	m.data.Users[user.ID] = user
	m.data.EmailIndex[email] = user.ID
	if err := m.saveLocked(); err != nil {
		return nil, err
	}
	return user, nil
}

func (m *Manager) adminCountLocked() int {
	count := 0
	for _, user := range m.data.Users {
		if user.IsAdmin {
			count++
		}
	}
	return count
}

func (m *Manager) userSummaryLocked(user *userRecord) User {
	groupIDs := filterExistingGroupIDs(user.GroupIDs, m.data.Groups)
	return User{
		ID:         user.ID,
		Email:      user.Email,
		IsAdmin:    user.IsAdmin,
		GroupIDs:   groupIDs,
		GroupNames: m.groupNamesLocked(groupIDs),
		CreatedAt:  time.Unix(user.CreatedAt, 0),
		UpdatedAt:  time.Unix(user.UpdatedAt, 0),
	}
}

func (m *Manager) groupSummaryLocked(group *groupRecord) Group {
	count := 0
	for _, user := range m.data.Users {
		if slices.Contains(user.GroupIDs, group.ID) {
			count++
		}
	}
	return Group{
		ID:          group.ID,
		Name:        group.Name,
		MemberCount: count,
		CreatedAt:   time.Unix(group.CreatedAt, 0),
		UpdatedAt:   time.Unix(group.UpdatedAt, 0),
	}
}

func (m *Manager) userDevicesLocked(userID string) []UserDevice {
	type accumulator struct {
		device UserDevice
	}

	devicesByID := map[string]*accumulator{}
	for _, record := range m.data.RefreshTokens {
		if record.UserID != userID {
			continue
		}
		deviceID := grantDeviceID(record.UserID, record.ClientID, record.Resource)
		acc := devicesByID[deviceID]
		if acc == nil {
			client := m.data.Clients[record.ClientID]
			device := UserDevice{
				ID:               deviceID,
				ClientID:         record.ClientID,
				ClientName:       record.ClientID,
				Resource:         record.Resource,
				Scope:            record.Scope,
				TokenCount:       0,
				CreatedAt:        time.Unix(record.IssuedAt, 0),
				LastUsedAt:       time.Unix(record.IssuedAt, 0),
				RefreshExpiresAt: time.Unix(record.ExpiresAt, 0),
			}
			if client != nil {
				device.ClientName = client.Name
				device.RedirectURIs = append([]string(nil), client.RedirectURIs...)
			}
			acc = &accumulator{device: device}
			devicesByID[deviceID] = acc
		}
		issuedAt := time.Unix(record.IssuedAt, 0)
		expiresAt := time.Unix(record.ExpiresAt, 0)
		if issuedAt.Before(acc.device.CreatedAt) {
			acc.device.CreatedAt = issuedAt
		}
		if issuedAt.After(acc.device.LastUsedAt) {
			acc.device.LastUsedAt = issuedAt
		}
		if expiresAt.After(acc.device.RefreshExpiresAt) {
			acc.device.RefreshExpiresAt = expiresAt
		}
		acc.device.TokenCount++
	}

	devices := make([]UserDevice, 0, len(devicesByID))
	for _, acc := range devicesByID {
		devices = append(devices, acc.device)
	}
	slices.SortFunc(devices, func(a, b UserDevice) int {
		return b.LastUsedAt.Compare(a.LastUsedAt)
	})
	return devices
}

func grantDeviceID(userID, clientID, resource string) string {
	sum := sha256.Sum256([]byte(userID + "\x00" + clientID + "\x00" + resource))
	return base64.RawURLEncoding.EncodeToString(sum[:18])
}

func (m *Manager) groupNamesLocked(groupIDs []string) []string {
	names := make([]string, 0, len(groupIDs))
	for _, groupID := range groupIDs {
		if group, ok := m.data.Groups[groupID]; ok {
			names = append(names, group.Name)
		}
	}
	slices.Sort(names)
	return names
}

func (m *Manager) groupNameExistsLocked(name, exceptID string) bool {
	needle := strings.ToLower(strings.TrimSpace(name))
	for id, group := range m.data.Groups {
		if id == exceptID {
			continue
		}
		if strings.ToLower(strings.TrimSpace(group.Name)) == needle {
			return true
		}
	}
	return false
}

func filterExistingGroupIDs(groupIDs []string, groups map[string]*groupRecord) []string {
	if len(groupIDs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(groupIDs))
	out := make([]string, 0, len(groupIDs))
	for _, groupID := range groupIDs {
		groupID = strings.TrimSpace(groupID)
		if groupID == "" {
			continue
		}
		if _, exists := groups[groupID]; !exists {
			continue
		}
		if _, exists := seen[groupID]; exists {
			continue
		}
		seen[groupID] = struct{}{}
		out = append(out, groupID)
	}
	return out
}

func removeString(values []string, target string) []string {
	out := values[:0]
	for _, value := range values {
		if value != target {
			out = append(out, value)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func stringsContainsAt(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == '@' {
			return true
		}
	}
	return false
}
