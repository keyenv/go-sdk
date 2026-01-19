// Package keyenv provides a Go SDK for the KeyEnv secrets management service.
package keyenv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultBaseURL is the default API endpoint.
	DefaultBaseURL = "https://api.keyenv.dev"

	// DefaultTimeout is the default HTTP request timeout.
	DefaultTimeout = 30 * time.Second

	// Version is the SDK version.
	Version = "1.0.0"
)

// Client is the KeyEnv API client.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
	cacheTTL   time.Duration

	// cache stores cached responses
	cache   map[string]cacheEntry
	cacheMu sync.RWMutex
}

// New creates a new KeyEnv client with the given configuration.
func New(config Config) (*Client, error) {
	if config.Token == "" {
		return nil, fmt.Errorf("keyenv: token is required")
	}

	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	timeout := config.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	return &Client{
		baseURL: baseURL,
		token:   config.Token,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		cacheTTL: config.CacheTTL,
		cache:    make(map[string]cacheEntry),
	}, nil
}

// request makes an HTTP request to the KeyEnv API.
func (c *Client) request(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	url := c.baseURL + path

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("keyenv: failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("keyenv: failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "keyenv-go/"+Version)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keyenv: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("keyenv: failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var apiErr struct {
			Error   string `json:"error"`
			Message string `json:"message"`
			Code    string `json:"code"`
		}
		if err := json.Unmarshal(respBody, &apiErr); err == nil {
			msg := apiErr.Error
			if msg == "" {
				msg = apiErr.Message
			}
			if msg == "" {
				msg = http.StatusText(resp.StatusCode)
			}
			return nil, &Error{
				Status:  resp.StatusCode,
				Message: msg,
				Code:    apiErr.Code,
			}
		}
		return nil, &Error{
			Status:  resp.StatusCode,
			Message: http.StatusText(resp.StatusCode),
		}
	}

	return respBody, nil
}

// get makes a GET request.
func (c *Client) get(ctx context.Context, path string) ([]byte, error) {
	return c.request(ctx, http.MethodGet, path, nil)
}

// post makes a POST request.
func (c *Client) post(ctx context.Context, path string, body interface{}) ([]byte, error) {
	return c.request(ctx, http.MethodPost, path, body)
}

// put makes a PUT request.
func (c *Client) put(ctx context.Context, path string, body interface{}) ([]byte, error) {
	return c.request(ctx, http.MethodPut, path, body)
}

// delete makes a DELETE request.
func (c *Client) delete(ctx context.Context, path string) ([]byte, error) {
	return c.request(ctx, http.MethodDelete, path, nil)
}

// getCached gets a cached value if it exists and is not expired.
func (c *Client) getCached(key string) (interface{}, bool) {
	if c.cacheTTL == 0 {
		return nil, false
	}

	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()

	entry, ok := c.cache[key]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.data, true
}

// setCache stores a value in the cache.
func (c *Client) setCache(key string, data interface{}) {
	if c.cacheTTL == 0 {
		return
	}

	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	c.cache[key] = cacheEntry{
		data:      data,
		expiresAt: time.Now().Add(c.cacheTTL),
	}
}

// ClearCache clears the cache for a specific project/environment combination.
func (c *Client) ClearCache(projectID, environment string) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	prefix := fmt.Sprintf("secrets:%s:%s", projectID, environment)
	for key := range c.cache {
		if strings.HasPrefix(key, prefix) {
			delete(c.cache, key)
		}
	}
}

// ClearAllCache clears all cached data.
func (c *Client) ClearAllCache() {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	c.cache = make(map[string]cacheEntry)
}

// GetCurrentUser returns information about the current authenticated user or service token.
func (c *Client) GetCurrentUser(ctx context.Context) (*CurrentUserResponse, error) {
	data, err := c.get(ctx, "/me")
	if err != nil {
		return nil, err
	}

	var resp CurrentUserResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("keyenv: failed to parse response: %w", err)
	}

	return &resp, nil
}

// ListProjects returns all projects accessible to the current user or service token.
func (c *Client) ListProjects(ctx context.Context) ([]Project, error) {
	data, err := c.get(ctx, "/projects")
	if err != nil {
		return nil, err
	}

	var resp struct {
		Projects []Project `json:"projects"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("keyenv: failed to parse response: %w", err)
	}

	return resp.Projects, nil
}

// GetProject returns a project by ID including its environments.
func (c *Client) GetProject(ctx context.Context, projectID string) (*Project, error) {
	data, err := c.get(ctx, "/projects/"+projectID)
	if err != nil {
		return nil, err
	}

	var project Project
	if err := json.Unmarshal(data, &project); err != nil {
		return nil, fmt.Errorf("keyenv: failed to parse response: %w", err)
	}

	return &project, nil
}

// ListEnvironments returns all environments in a project.
func (c *Client) ListEnvironments(ctx context.Context, projectID string) ([]Environment, error) {
	data, err := c.get(ctx, "/projects/"+projectID+"/environments")
	if err != nil {
		return nil, err
	}

	var resp struct {
		Environments []Environment `json:"environments"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("keyenv: failed to parse response: %w", err)
	}

	return resp.Environments, nil
}

// ListSecrets returns secret keys (without values) for an environment.
func (c *Client) ListSecrets(ctx context.Context, projectID, environment string) ([]SecretWithInheritance, error) {
	path := fmt.Sprintf("/projects/%s/environments/%s/secrets", projectID, environment)
	data, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Secrets []SecretWithInheritance `json:"secrets"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("keyenv: failed to parse response: %w", err)
	}

	return resp.Secrets, nil
}

// ExportSecrets returns all secrets with their values for an environment.
func (c *Client) ExportSecrets(ctx context.Context, projectID, environment string) ([]SecretWithValueAndInheritance, error) {
	cacheKey := fmt.Sprintf("secrets:%s:%s:export", projectID, environment)

	// Check cache
	if cached, ok := c.getCached(cacheKey); ok {
		return cached.([]SecretWithValueAndInheritance), nil
	}

	path := fmt.Sprintf("/projects/%s/environments/%s/secrets/export", projectID, environment)
	data, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Secrets []SecretWithValueAndInheritance `json:"secrets"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("keyenv: failed to parse response: %w", err)
	}

	// Store in cache
	c.setCache(cacheKey, resp.Secrets)

	return resp.Secrets, nil
}

// ExportSecretsAsMap returns secrets as a key-value map.
func (c *Client) ExportSecretsAsMap(ctx context.Context, projectID, environment string) (map[string]string, error) {
	secrets, err := c.ExportSecrets(ctx, projectID, environment)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string, len(secrets))
	for _, s := range secrets {
		result[s.Key] = s.Value
	}

	return result, nil
}

// GetSecret returns a single secret by key.
func (c *Client) GetSecret(ctx context.Context, projectID, environment, key string) (*SecretWithValue, error) {
	path := fmt.Sprintf("/projects/%s/environments/%s/secrets/%s", projectID, environment, key)
	data, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}

	var secret SecretWithValue
	if err := json.Unmarshal(data, &secret); err != nil {
		return nil, fmt.Errorf("keyenv: failed to parse response: %w", err)
	}

	return &secret, nil
}

// SetSecret creates or updates a secret.
func (c *Client) SetSecret(ctx context.Context, projectID, environment, key, value string) error {
	return c.SetSecretWithDescription(ctx, projectID, environment, key, value, nil)
}

// SetSecretWithDescription creates or updates a secret with a description.
func (c *Client) SetSecretWithDescription(ctx context.Context, projectID, environment, key, value string, description *string) error {
	path := fmt.Sprintf("/projects/%s/environments/%s/secrets/%s", projectID, environment, key)

	body := map[string]interface{}{
		"value": value,
	}
	if description != nil {
		body["description"] = *description
	}

	// Try PUT first (update), then POST (create) if not found
	_, err := c.put(ctx, path, body)
	if err != nil {
		if keyenvErr, ok := err.(*Error); ok && keyenvErr.IsNotFound() {
			// Secret doesn't exist, create it
			createBody := map[string]interface{}{
				"key":   key,
				"value": value,
			}
			if description != nil {
				createBody["description"] = *description
			}
			createPath := fmt.Sprintf("/projects/%s/environments/%s/secrets", projectID, environment)
			_, createErr := c.post(ctx, createPath, createBody)
			if createErr != nil {
				return createErr
			}
		} else {
			return err
		}
	}

	// Clear cache for this environment
	c.ClearCache(projectID, environment)

	return nil
}

// DeleteSecret deletes a secret by key.
func (c *Client) DeleteSecret(ctx context.Context, projectID, environment, key string) error {
	path := fmt.Sprintf("/projects/%s/environments/%s/secrets/%s", projectID, environment, key)
	_, err := c.delete(ctx, path)
	if err != nil {
		return err
	}

	// Clear cache for this environment
	c.ClearCache(projectID, environment)

	return nil
}

// BulkImport imports multiple secrets at once.
func (c *Client) BulkImport(ctx context.Context, projectID, environment string, secrets []SecretInput, options BulkImportOptions) (*BulkImportResult, error) {
	path := fmt.Sprintf("/projects/%s/environments/%s/secrets/bulk", projectID, environment)

	body := map[string]interface{}{
		"secrets":   secrets,
		"overwrite": options.Overwrite,
	}

	data, err := c.post(ctx, path, body)
	if err != nil {
		return nil, err
	}

	var result BulkImportResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("keyenv: failed to parse response: %w", err)
	}

	// Clear cache for this environment
	c.ClearCache(projectID, environment)

	return &result, nil
}

// LoadEnv loads secrets into environment variables.
// Returns the number of secrets loaded.
func (c *Client) LoadEnv(ctx context.Context, projectID, environment string) (int, error) {
	secrets, err := c.ExportSecrets(ctx, projectID, environment)
	if err != nil {
		return 0, err
	}

	for _, s := range secrets {
		if err := os.Setenv(s.Key, s.Value); err != nil {
			return 0, fmt.Errorf("keyenv: failed to set environment variable %s: %w", s.Key, err)
		}
	}

	return len(secrets), nil
}

// GenerateEnvFile generates a .env file content string.
func (c *Client) GenerateEnvFile(ctx context.Context, projectID, environment string) (string, error) {
	secrets, err := c.ExportSecrets(ctx, projectID, environment)
	if err != nil {
		return "", err
	}

	var builder strings.Builder
	for _, s := range secrets {
		// Escape special characters in values
		value := s.Value
		needsQuotes := strings.ContainsAny(value, " \t\n\"'\\$")

		if needsQuotes {
			// Use double quotes and escape special characters
			value = strings.ReplaceAll(value, "\\", "\\\\")
			value = strings.ReplaceAll(value, "\"", "\\\"")
			value = strings.ReplaceAll(value, "\n", "\\n")
			value = strings.ReplaceAll(value, "$", "\\$")
			builder.WriteString(fmt.Sprintf("%s=\"%s\"\n", s.Key, value))
		} else {
			builder.WriteString(fmt.Sprintf("%s=%s\n", s.Key, value))
		}
	}

	return builder.String(), nil
}

// ListPermissions returns permissions for an environment.
func (c *Client) ListPermissions(ctx context.Context, projectID, environment string) ([]Permission, error) {
	path := fmt.Sprintf("/projects/%s/environments/%s/permissions", projectID, environment)
	data, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Permissions []Permission `json:"permissions"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("keyenv: failed to parse response: %w", err)
	}

	return resp.Permissions, nil
}

// SetPermission sets a user's permission for an environment.
func (c *Client) SetPermission(ctx context.Context, projectID, environment, userID, role string) error {
	path := fmt.Sprintf("/projects/%s/environments/%s/permissions/%s", projectID, environment, userID)

	body := map[string]string{
		"role": role,
	}

	_, err := c.put(ctx, path, body)
	return err
}

// DeletePermission removes a user's permission for an environment.
func (c *Client) DeletePermission(ctx context.Context, projectID, environment, userID string) error {
	path := fmt.Sprintf("/projects/%s/environments/%s/permissions/%s", projectID, environment, userID)
	_, err := c.delete(ctx, path)
	return err
}

// BulkSetPermissions sets multiple permissions at once.
func (c *Client) BulkSetPermissions(ctx context.Context, projectID, environment string, permissions []PermissionInput) error {
	path := fmt.Sprintf("/projects/%s/environments/%s/permissions/bulk", projectID, environment)

	body := map[string]interface{}{
		"permissions": permissions,
	}

	_, err := c.post(ctx, path, body)
	return err
}

// GetMyPermissions returns the current user's permissions for a project.
func (c *Client) GetMyPermissions(ctx context.Context, projectID string) (*MyPermissionsResponse, error) {
	path := fmt.Sprintf("/projects/%s/permissions/me", projectID)
	data, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}

	var resp MyPermissionsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("keyenv: failed to parse response: %w", err)
	}

	return &resp, nil
}

// GetProjectDefaults returns the default permissions for a project.
func (c *Client) GetProjectDefaults(ctx context.Context, projectID string) ([]DefaultPermission, error) {
	path := fmt.Sprintf("/projects/%s/defaults", projectID)
	data, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Defaults []DefaultPermission `json:"defaults"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("keyenv: failed to parse response: %w", err)
	}

	return resp.Defaults, nil
}

// SetProjectDefaults sets the default permissions for a project.
func (c *Client) SetProjectDefaults(ctx context.Context, projectID string, defaults []DefaultPermission) error {
	path := fmt.Sprintf("/projects/%s/defaults", projectID)

	body := map[string]interface{}{
		"defaults": defaults,
	}

	_, err := c.put(ctx, path, body)
	return err
}

// GetSecretHistory returns the version history of a secret.
func (c *Client) GetSecretHistory(ctx context.Context, projectID, environment, key string) ([]SecretHistory, error) {
	path := fmt.Sprintf("/projects/%s/environments/%s/secrets/%s/history", projectID, environment, key)
	data, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}

	var resp struct {
		History []SecretHistory `json:"history"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("keyenv: failed to parse response: %w", err)
	}

	return resp.History, nil
}
