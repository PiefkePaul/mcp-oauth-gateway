package auth

import (
	"fmt"
	"net/http"
	"slices"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID        string
	Email     string
	IsAdmin   bool
	CreatedAt time.Time
	UpdatedAt time.Time
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
		users = append(users, userSummary(user))
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

func (m *Manager) CreateUser(email, password string, isAdmin bool) (*User, error) {
	record, err := m.createUser(email, password, isAdmin, false)
	if err != nil {
		return nil, err
	}
	summary := userSummary(record)
	return &summary, nil
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

func userSummary(user *userRecord) User {
	return User{
		ID:        user.ID,
		Email:     user.Email,
		IsAdmin:   user.IsAdmin,
		CreatedAt: time.Unix(user.CreatedAt, 0),
		UpdatedAt: time.Unix(user.UpdatedAt, 0),
	}
}

func stringsContainsAt(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == '@' {
			return true
		}
	}
	return false
}
