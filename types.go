// Package keyenv provides a Go SDK for the KeyEnv secrets management service.
package keyenv

import "time"

// Config holds the configuration options for the KeyEnv client.
type Config struct {
	// Token is the service token for authentication (required).
	Token string

	// BaseURL is the API base URL (optional, defaults to https://api.keyenv.dev).
	BaseURL string

	// Timeout is the HTTP request timeout (optional, defaults to 30s).
	Timeout time.Duration

	// CacheTTL is the cache time-to-live duration (optional, 0 means disabled).
	CacheTTL time.Duration
}

// User represents a KeyEnv user.
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	AvatarURL string    `json:"avatar_url,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Project represents a KeyEnv project.
type Project struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Description  string        `json:"description,omitempty"`
	TeamID       string        `json:"team_id"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
	Environments []Environment `json:"environments,omitempty"`
}

// Environment represents a KeyEnv environment within a project.
type Environment struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Description    string     `json:"description,omitempty"`
	ProjectID      string     `json:"project_id"`
	InheritsFromID *string    `json:"inherits_from_id,omitempty"`
	Order          int        `json:"order"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// Secret represents a secret's metadata without the value.
type Secret struct {
	ID            string     `json:"id"`
	Key           string     `json:"key"`
	Description   *string    `json:"description,omitempty"`
	EnvironmentID string     `json:"environment_id"`
	SecretType    string     `json:"secret_type,omitempty"`
	Version       int        `json:"version"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// SecretWithValue represents a secret including its decrypted value.
type SecretWithValue struct {
	Secret
	Value string `json:"value"`
}

// SecretWithInheritance represents a secret with inheritance information.
type SecretWithInheritance struct {
	Secret
	InheritedFrom *string `json:"inherited_from,omitempty"`
}

// SecretWithValueAndInheritance represents a secret with value and inheritance info.
type SecretWithValueAndInheritance struct {
	Secret
	Value         string  `json:"value"`
	InheritedFrom *string `json:"inherited_from,omitempty"`
}

// SecretInput represents input for creating or importing a secret.
type SecretInput struct {
	Key         string  `json:"key"`
	Value       string  `json:"value"`
	Description *string `json:"description,omitempty"`
}

// BulkImportOptions holds options for bulk import operations.
type BulkImportOptions struct {
	// Overwrite controls whether existing secrets should be updated.
	Overwrite bool `json:"overwrite"`
}

// BulkImportResult contains the results of a bulk import operation.
type BulkImportResult struct {
	Created int `json:"created"`
	Updated int `json:"updated"`
	Skipped int `json:"skipped"`
}

// Permission represents a user's permission for an environment.
type Permission struct {
	ID              string    `json:"id"`
	UserID          string    `json:"user_id"`
	UserEmail       string    `json:"user_email"`
	EnvironmentID   string    `json:"environment_id"`
	EnvironmentName string    `json:"environment_name,omitempty"`
	Role            string    `json:"role"`
	CanWrite        bool      `json:"can_write"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// PermissionInput represents input for setting a permission.
type PermissionInput struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

// MyPermissionsResponse contains the current user's permissions.
type MyPermissionsResponse struct {
	Permissions []Permission `json:"permissions"`
	IsTeamAdmin bool         `json:"is_team_admin"`
}

// DefaultPermission represents default permission settings for an environment.
type DefaultPermission struct {
	EnvironmentName string `json:"environment_name"`
	DefaultRole     string `json:"default_role"`
}

// SecretHistory represents a historical version of a secret.
type SecretHistory struct {
	ID         string    `json:"id"`
	SecretID   string    `json:"secret_id"`
	Key        string    `json:"key"`
	Version    int       `json:"version"`
	ChangedBy  *string   `json:"changed_by,omitempty"`
	ChangeType string    `json:"change_type"`
	CreatedAt  time.Time `json:"created_at"`
}

// Team represents a KeyEnv team.
type Team struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ServiceToken represents information about a service token.
type ServiceToken struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	ProjectID   string    `json:"project_id"`
	ProjectName string    `json:"project_name,omitempty"`
	Permissions []string  `json:"permissions"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// CurrentUserResponse contains information about the current authenticated user or token.
type CurrentUserResponse struct {
	Type         string        `json:"type"` // "user" or "service_token"
	User         *User         `json:"user,omitempty"`
	ServiceToken *ServiceToken `json:"service_token,omitempty"`
}

// cacheEntry represents a cached value with expiration.
type cacheEntry struct {
	data      interface{}
	expiresAt time.Time
}
