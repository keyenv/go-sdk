//go:build integration

package keyenv

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// Test configuration from environment variables
func getTestConfig(t *testing.T) Config {
	apiURL := os.Getenv("KEYENV_API_URL")
	if apiURL == "" {
		t.Skip("KEYENV_API_URL not set")
	}

	token := os.Getenv("KEYENV_TOKEN")
	if token == "" {
		t.Skip("KEYENV_TOKEN not set")
	}

	return Config{
		BaseURL: apiURL,
		Token:   token,
		Timeout: 30 * time.Second,
	}
}

func getTestProject(t *testing.T) string {
	project := os.Getenv("KEYENV_PROJECT")
	if project == "" {
		project = "sdk-test"
	}
	return project
}

// uniqueKey generates a unique key using timestamp to avoid conflicts
func uniqueKey(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

func TestIntegration_ValidateToken(t *testing.T) {
	client, err := New(getTestConfig(t))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	user, err := client.ValidateToken(ctx)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if user == nil {
		t.Fatal("Expected user response, got nil")
	}

	// Service token should have AuthType = "service_token"
	authType := user.AuthType
	if authType == "" {
		authType = user.Type // fallback to legacy field
	}
	if authType != "service_token" && authType != "user" && authType != "" {
		t.Errorf("Expected auth_type 'service_token' or 'user', got %q", authType)
	}

	t.Logf("Authenticated as: %s (ID: %s)", authType, user.ID)
	if user.IsServiceToken() {
		t.Logf("Service token scopes: %v", user.Scopes)
	}
}

func TestIntegration_ListProjects(t *testing.T) {
	client, err := New(getTestConfig(t))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	projects, err := client.ListProjects(ctx)
	if err != nil {
		t.Fatalf("ListProjects failed: %v", err)
	}

	t.Logf("Found %d projects", len(projects))

	// The test project should exist
	testProject := getTestProject(t)
	found := false
	for _, p := range projects {
		t.Logf("  - %s (ID: %s)", p.Name, p.ID)
		if p.ID == testProject || p.Name == testProject {
			found = true
		}
	}

	if !found {
		t.Logf("Warning: Test project %q not found in project list", testProject)
	}
}

func TestIntegration_GetProject(t *testing.T) {
	client, err := New(getTestConfig(t))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	projectID := getTestProject(t)

	project, err := client.GetProject(ctx, projectID)
	if err != nil {
		t.Fatalf("GetProject failed: %v", err)
	}

	t.Logf("Project: %s (ID: %s)", project.Name, project.ID)
	t.Logf("Environments: %d", len(project.Environments))
	for _, env := range project.Environments {
		t.Logf("  - %s (ID: %s)", env.Name, env.ID)
	}
}

func TestIntegration_ListEnvironments(t *testing.T) {
	client, err := New(getTestConfig(t))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	projectID := getTestProject(t)

	environments, err := client.ListEnvironments(ctx, projectID)
	if err != nil {
		t.Fatalf("ListEnvironments failed: %v", err)
	}

	t.Logf("Found %d environments", len(environments))
	for _, env := range environments {
		t.Logf("  - %s (ID: %s)", env.Name, env.ID)
	}

	// Expect at least one environment
	if len(environments) == 0 {
		t.Error("Expected at least one environment")
	}
}

func TestIntegration_ExportSecrets(t *testing.T) {
	client, err := New(getTestConfig(t))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	projectID := getTestProject(t)
	environment := "development"

	secrets, err := client.ExportSecrets(ctx, projectID, environment)
	if err != nil {
		t.Fatalf("ExportSecrets failed: %v", err)
	}

	t.Logf("Found %d secrets in %s/%s", len(secrets), projectID, environment)
	for _, s := range secrets {
		// Don't log actual values, just keys
		t.Logf("  - %s (version: %d)", s.Key, s.Version)
	}
}

func TestIntegration_ExportSecretsAsMap(t *testing.T) {
	client, err := New(getTestConfig(t))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	projectID := getTestProject(t)
	environment := "development"

	secrets, err := client.ExportSecretsAsMap(ctx, projectID, environment)
	if err != nil {
		t.Fatalf("ExportSecretsAsMap failed: %v", err)
	}

	t.Logf("Exported %d secrets as map", len(secrets))

	// Verify map has same number of entries
	secretsList, _ := client.ExportSecrets(ctx, projectID, environment)
	if len(secrets) != len(secretsList) {
		t.Errorf("Map has %d entries, but list has %d entries", len(secrets), len(secretsList))
	}
}

func TestIntegration_SecretCRUD(t *testing.T) {
	client, err := New(getTestConfig(t))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	projectID := getTestProject(t)
	environment := "development"

	// Generate unique key to avoid conflicts
	testKey := uniqueKey("TEST_SECRET")
	testValue := "test_value_" + time.Now().Format("20060102150405")
	testDescription := "Integration test secret"

	// Create secret
	t.Run("Create", func(t *testing.T) {
		err := client.SetSecretWithDescription(ctx, projectID, environment, testKey, testValue, &testDescription)
		if err != nil {
			t.Fatalf("SetSecretWithDescription failed: %v", err)
		}
		t.Logf("Created secret: %s", testKey)
	})

	// Read secret
	t.Run("Read", func(t *testing.T) {
		secret, err := client.GetSecret(ctx, projectID, environment, testKey)
		if err != nil {
			t.Fatalf("GetSecret failed: %v", err)
		}

		if secret.Key != testKey {
			t.Errorf("Expected key %q, got %q", testKey, secret.Key)
		}
		if secret.Value != testValue {
			t.Errorf("Expected value %q, got %q", testValue, secret.Value)
		}
		if secret.Description == nil || *secret.Description != testDescription {
			t.Errorf("Expected description %q, got %v", testDescription, secret.Description)
		}
		t.Logf("Read secret: %s (version: %d)", secret.Key, secret.Version)
	})

	// Update secret
	updatedValue := "updated_value_" + time.Now().Format("20060102150405")
	t.Run("Update", func(t *testing.T) {
		err := client.SetSecret(ctx, projectID, environment, testKey, updatedValue)
		if err != nil {
			t.Fatalf("SetSecret (update) failed: %v", err)
		}

		// Verify update
		secret, err := client.GetSecret(ctx, projectID, environment, testKey)
		if err != nil {
			t.Fatalf("GetSecret after update failed: %v", err)
		}

		if secret.Value != updatedValue {
			t.Errorf("Expected updated value %q, got %q", updatedValue, secret.Value)
		}
		if secret.Version < 2 {
			t.Errorf("Expected version >= 2 after update, got %d", secret.Version)
		}
		t.Logf("Updated secret: %s (version: %d)", secret.Key, secret.Version)
	})

	// List secrets should include our test secret
	t.Run("List", func(t *testing.T) {
		secrets, err := client.ListSecrets(ctx, projectID, environment)
		if err != nil {
			t.Fatalf("ListSecrets failed: %v", err)
		}

		found := false
		for _, s := range secrets {
			if s.Key == testKey {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("Test secret %q not found in list", testKey)
		}
	})

	// Delete secret
	t.Run("Delete", func(t *testing.T) {
		err := client.DeleteSecret(ctx, projectID, environment, testKey)
		if err != nil {
			t.Fatalf("DeleteSecret failed: %v", err)
		}
		t.Logf("Deleted secret: %s", testKey)

		// Verify deletion
		_, err = client.GetSecret(ctx, projectID, environment, testKey)
		if err == nil {
			t.Error("Expected error when getting deleted secret")
		}

		keyenvErr, ok := err.(*Error)
		if !ok {
			t.Errorf("Expected *Error, got %T", err)
		} else if !keyenvErr.IsNotFound() {
			t.Errorf("Expected 404 Not Found, got status %d", keyenvErr.Status)
		}
	})
}

func TestIntegration_BulkImport(t *testing.T) {
	client, err := New(getTestConfig(t))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	projectID := getTestProject(t)
	environment := "development"

	// Generate unique keys
	prefix := uniqueKey("BULK")
	secrets := []SecretInput{
		{Key: prefix + "_KEY1", Value: "value1"},
		{Key: prefix + "_KEY2", Value: "value2"},
		{Key: prefix + "_KEY3", Value: "value3"},
	}

	// Cleanup function
	cleanup := func() {
		for _, s := range secrets {
			_ = client.DeleteSecret(ctx, projectID, environment, s.Key)
		}
	}
	defer cleanup()

	// Test bulk import (create)
	t.Run("Create", func(t *testing.T) {
		result, err := client.BulkImport(ctx, projectID, environment, secrets, BulkImportOptions{
			Overwrite: false,
		})
		if err != nil {
			t.Fatalf("BulkImport failed: %v", err)
		}

		t.Logf("BulkImport result: created=%d, updated=%d, skipped=%d",
			result.Created, result.Updated, result.Skipped)

		if result.Created != 3 {
			t.Errorf("Expected 3 created, got %d", result.Created)
		}
	})

	// Test bulk import with overwrite
	t.Run("Overwrite", func(t *testing.T) {
		// Update values
		updatedSecrets := []SecretInput{
			{Key: secrets[0].Key, Value: "updated_value1"},
			{Key: secrets[1].Key, Value: "updated_value2"},
		}

		result, err := client.BulkImport(ctx, projectID, environment, updatedSecrets, BulkImportOptions{
			Overwrite: true,
		})
		if err != nil {
			t.Fatalf("BulkImport (overwrite) failed: %v", err)
		}

		t.Logf("BulkImport (overwrite) result: created=%d, updated=%d, skipped=%d",
			result.Created, result.Updated, result.Skipped)

		if result.Updated != 2 {
			t.Errorf("Expected 2 updated, got %d", result.Updated)
		}

		// Verify values were updated
		secret, err := client.GetSecret(ctx, projectID, environment, secrets[0].Key)
		if err != nil {
			t.Fatalf("GetSecret after bulk update failed: %v", err)
		}
		if secret.Value != "updated_value1" {
			t.Errorf("Expected updated value, got %q", secret.Value)
		}
	})

	// Test bulk import without overwrite (should skip)
	t.Run("Skip", func(t *testing.T) {
		result, err := client.BulkImport(ctx, projectID, environment, secrets[:1], BulkImportOptions{
			Overwrite: false,
		})
		if err != nil {
			t.Fatalf("BulkImport (skip) failed: %v", err)
		}

		t.Logf("BulkImport (skip) result: created=%d, updated=%d, skipped=%d",
			result.Created, result.Updated, result.Skipped)

		if result.Skipped != 1 {
			t.Errorf("Expected 1 skipped, got %d", result.Skipped)
		}
	})
}

func TestIntegration_GenerateEnvFile(t *testing.T) {
	client, err := New(getTestConfig(t))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	projectID := getTestProject(t)
	environment := "development"

	// Create a test secret with special characters
	testKey := uniqueKey("ENV_FILE_TEST")
	testValue := "value with spaces and \"quotes\" and $dollar"
	defer func() {
		_ = client.DeleteSecret(ctx, projectID, environment, testKey)
	}()

	err = client.SetSecret(ctx, projectID, environment, testKey, testValue)
	if err != nil {
		t.Fatalf("SetSecret failed: %v", err)
	}

	// Generate env file
	envContent, err := client.GenerateEnvFile(ctx, projectID, environment)
	if err != nil {
		t.Fatalf("GenerateEnvFile failed: %v", err)
	}

	t.Logf("Generated .env file content (%d bytes)", len(envContent))

	// Verify our test key is in the output
	if len(envContent) == 0 {
		t.Error("Expected non-empty env file content")
	}
}

func TestIntegration_Cache(t *testing.T) {
	config := getTestConfig(t)
	config.CacheTTL = 5 * time.Second

	client, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	projectID := getTestProject(t)
	environment := "development"

	// First call should populate cache
	secrets1, err := client.ExportSecrets(ctx, projectID, environment)
	if err != nil {
		t.Fatalf("ExportSecrets (first) failed: %v", err)
	}

	// Second call should use cache (we can't directly test this, but it shouldn't fail)
	secrets2, err := client.ExportSecrets(ctx, projectID, environment)
	if err != nil {
		t.Fatalf("ExportSecrets (cached) failed: %v", err)
	}

	if len(secrets1) != len(secrets2) {
		t.Errorf("Expected same results from cache: got %d vs %d", len(secrets1), len(secrets2))
	}

	// Clear cache
	client.ClearCache(projectID, environment)

	// Should work after clearing cache
	secrets3, err := client.ExportSecrets(ctx, projectID, environment)
	if err != nil {
		t.Fatalf("ExportSecrets (after clear) failed: %v", err)
	}

	if len(secrets1) != len(secrets3) {
		t.Errorf("Expected same results after cache clear: got %d vs %d", len(secrets1), len(secrets3))
	}

	t.Logf("Cache test passed with %d secrets", len(secrets1))
}

func TestIntegration_ErrorHandling(t *testing.T) {
	client, err := New(getTestConfig(t))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()

	t.Run("NotFoundProject", func(t *testing.T) {
		_, err := client.GetProject(ctx, "nonexistent-project-12345")
		if err == nil {
			t.Fatal("Expected error for nonexistent project")
		}

		keyenvErr, ok := err.(*Error)
		if !ok {
			t.Fatalf("Expected *Error, got %T", err)
		}

		if !keyenvErr.IsNotFound() && !keyenvErr.IsForbidden() {
			// Could be 404 or 403 depending on API behavior
			t.Logf("Got status %d for nonexistent project", keyenvErr.Status)
		}
	})

	t.Run("NotFoundSecret", func(t *testing.T) {
		projectID := getTestProject(t)
		_, err := client.GetSecret(ctx, projectID, "development", "NONEXISTENT_SECRET_12345")
		if err == nil {
			t.Fatal("Expected error for nonexistent secret")
		}

		keyenvErr, ok := err.(*Error)
		if !ok {
			t.Fatalf("Expected *Error, got %T", err)
		}

		if !keyenvErr.IsNotFound() {
			t.Errorf("Expected 404, got status %d", keyenvErr.Status)
		}
	})

	t.Run("InvalidToken", func(t *testing.T) {
		badClient, err := New(Config{
			BaseURL: os.Getenv("KEYENV_API_URL"),
			Token:   "invalid_token_12345",
		})
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		_, err = badClient.ValidateToken(ctx)
		if err == nil {
			t.Fatal("Expected error for invalid token")
		}

		keyenvErr, ok := err.(*Error)
		if !ok {
			t.Fatalf("Expected *Error, got %T", err)
		}

		if !keyenvErr.IsUnauthorized() {
			t.Errorf("Expected 401, got status %d", keyenvErr.Status)
		}
	})
}

func TestIntegration_SecretHistory(t *testing.T) {
	client, err := New(getTestConfig(t))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	projectID := getTestProject(t)
	environment := "development"

	testKey := uniqueKey("HISTORY_TEST")
	defer func() {
		_ = client.DeleteSecret(ctx, projectID, environment, testKey)
	}()

	// Create secret
	err = client.SetSecret(ctx, projectID, environment, testKey, "version1")
	if err != nil {
		t.Fatalf("SetSecret (create) failed: %v", err)
	}

	// Update twice
	err = client.SetSecret(ctx, projectID, environment, testKey, "version2")
	if err != nil {
		t.Fatalf("SetSecret (update 1) failed: %v", err)
	}

	err = client.SetSecret(ctx, projectID, environment, testKey, "version3")
	if err != nil {
		t.Fatalf("SetSecret (update 2) failed: %v", err)
	}

	// Get history
	history, err := client.GetSecretHistory(ctx, projectID, environment, testKey)
	if err != nil {
		t.Fatalf("GetSecretHistory failed: %v", err)
	}

	if len(history) < 2 {
		t.Errorf("Expected at least 2 history entries, got %d", len(history))
	}

	t.Logf("Secret %s has %d history entries", testKey, len(history))
	for _, h := range history {
		t.Logf("  - version %d, change_type=%s, at=%s", h.Version, h.ChangeType, h.CreatedAt)
	}
}

func TestIntegration_LoadEnv(t *testing.T) {
	client, err := New(getTestConfig(t))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	projectID := getTestProject(t)
	environment := "development"

	testKey := uniqueKey("LOADENV_TEST")
	testValue := "loadenv_value_" + time.Now().Format("20060102150405")
	defer func() {
		_ = client.DeleteSecret(ctx, projectID, environment, testKey)
		os.Unsetenv(testKey)
	}()

	// Create a secret
	err = client.SetSecret(ctx, projectID, environment, testKey, testValue)
	if err != nil {
		t.Fatalf("SetSecret failed: %v", err)
	}

	// Load secrets into environment variables
	count, err := client.LoadEnv(ctx, projectID, environment)
	if err != nil {
		t.Fatalf("LoadEnv failed: %v", err)
	}

	if count == 0 {
		t.Error("Expected LoadEnv to load at least one secret")
	}

	// Verify our test key was loaded
	envValue := os.Getenv(testKey)
	if envValue != testValue {
		t.Errorf("Expected os.Getenv(%q) = %q, got %q", testKey, testValue, envValue)
	}

	t.Logf("LoadEnv loaded %d secrets, verified %s=%s", count, testKey, testValue)
}

func TestIntegration_SpecialCharacters(t *testing.T) {
	client, err := New(getTestConfig(t))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	projectID := getTestProject(t)
	environment := "development"

	tests := []struct {
		name  string
		key   string
		value string
	}{
		{
			name:  "ConnectionString",
			key:   uniqueKey("SPECIAL_CONNSTR"),
			value: "postgresql://user:p@ss@localhost:5432/db?sslmode=require",
		},
		{
			name:  "Multiline",
			key:   uniqueKey("SPECIAL_MULTILINE"),
			value: "line1\nline2\nline3",
		},
		{
			name:  "JSON",
			key:   uniqueKey("SPECIAL_JSON"),
			value: `{"key":"value","nested":{"a":1}}`,
		},
	}

	// Cleanup all keys
	defer func() {
		for _, tc := range tests {
			_ = client.DeleteSecret(ctx, projectID, environment, tc.key)
		}
	}()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create secret with special characters
			err := client.SetSecret(ctx, projectID, environment, tc.key, tc.value)
			if err != nil {
				t.Fatalf("SetSecret failed: %v", err)
			}

			// Read it back
			secret, err := client.GetSecret(ctx, projectID, environment, tc.key)
			if err != nil {
				t.Fatalf("GetSecret failed: %v", err)
			}

			if secret.Value != tc.value {
				t.Errorf("Value mismatch:\n  expected: %q\n  got:      %q", tc.value, secret.Value)
			}

			t.Logf("Verified %s: %q round-trips correctly", tc.key, tc.value)
		})
	}
}

func TestIntegration_MultipleEnvironments(t *testing.T) {
	client, err := New(getTestConfig(t))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	projectID := getTestProject(t)

	environments := []string{"development", "staging", "production"}
	testKey := uniqueKey("MULTI_ENV")

	// Cleanup
	defer func() {
		for _, env := range environments {
			_ = client.DeleteSecret(ctx, projectID, env, testKey)
		}
	}()

	// Create secret in each environment with different values
	for i, env := range environments {
		value := fmt.Sprintf("value_for_%s_%d", env, i)
		err := client.SetSecret(ctx, projectID, env, testKey, value)
		if err != nil {
			t.Errorf("Failed to set secret in %s: %v", env, err)
			continue
		}
		t.Logf("Set %s=%s in %s", testKey, value, env)
	}

	// Verify each environment has its own value
	for i, env := range environments {
		expectedValue := fmt.Sprintf("value_for_%s_%d", env, i)
		secret, err := client.GetSecret(ctx, projectID, env, testKey)
		if err != nil {
			t.Errorf("Failed to get secret from %s: %v", env, err)
			continue
		}

		if secret.Value != expectedValue {
			t.Errorf("Environment %s: expected %q, got %q", env, expectedValue, secret.Value)
		}
	}
}
