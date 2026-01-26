package keyenv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("creates client with valid config", func(t *testing.T) {
		client, err := New(Config{
			Token: "test-token",
		})
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, DefaultBaseURL, client.baseURL)
	})

	t.Run("returns error without token", func(t *testing.T) {
		_, err := New(Config{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token is required")
	})

	t.Run("uses custom base URL", func(t *testing.T) {
		client, err := New(Config{
			Token:   "test-token",
			BaseURL: "https://custom.api.com",
		})
		require.NoError(t, err)
		assert.Equal(t, "https://custom.api.com", client.baseURL)
	})

	t.Run("strips trailing slash from base URL", func(t *testing.T) {
		client, err := New(Config{
			Token:   "test-token",
			BaseURL: "https://custom.api.com/",
		})
		require.NoError(t, err)
		assert.Equal(t, "https://custom.api.com", client.baseURL)
	})

	t.Run("uses custom timeout", func(t *testing.T) {
		client, err := New(Config{
			Token:   "test-token",
			Timeout: 60 * time.Second,
		})
		require.NoError(t, err)
		assert.Equal(t, 60*time.Second, client.httpClient.Timeout)
	})

	t.Run("uses cache TTL", func(t *testing.T) {
		client, err := New(Config{
			Token:    "test-token",
			CacheTTL: 5 * time.Minute,
		})
		require.NoError(t, err)
		assert.Equal(t, 5*time.Minute, client.cacheTTL)
	})
}

func TestListProjects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/projects", r.URL.Path)
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

		json.NewEncoder(w).Encode(map[string]interface{}{
			"projects": []map[string]interface{}{
				{
					"id":   "proj-1",
					"name": "Project 1",
				},
				{
					"id":   "proj-2",
					"name": "Project 2",
				},
			},
		})
	}))
	defer server.Close()

	client, err := New(Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	projects, err := client.ListProjects(context.Background())
	require.NoError(t, err)
	assert.Len(t, projects, 2)
	assert.Equal(t, "proj-1", projects[0].ID)
	assert.Equal(t, "Project 1", projects[0].Name)
}

func TestGetProject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/projects/proj-1", r.URL.Path)
		assert.Equal(t, "GET", r.Method)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":   "proj-1",
			"name": "Project 1",
			"environments": []map[string]interface{}{
				{"id": "env-1", "name": "development"},
				{"id": "env-2", "name": "production"},
			},
		})
	}))
	defer server.Close()

	client, err := New(Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	project, err := client.GetProject(context.Background(), "proj-1")
	require.NoError(t, err)
	assert.Equal(t, "proj-1", project.ID)
	assert.Len(t, project.Environments, 2)
}

func TestExportSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/projects/proj-1/environments/production/secrets/export", r.URL.Path)
		assert.Equal(t, "GET", r.Method)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"secrets": []map[string]interface{}{
				{"key": "DATABASE_URL", "value": "postgres://localhost/db"},
				{"key": "API_KEY", "value": "sk_test_123"},
			},
		})
	}))
	defer server.Close()

	client, err := New(Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	secrets, err := client.ExportSecrets(context.Background(), "proj-1", "production")
	require.NoError(t, err)
	assert.Len(t, secrets, 2)
	assert.Equal(t, "DATABASE_URL", secrets[0].Key)
	assert.Equal(t, "postgres://localhost/db", secrets[0].Value)
}

func TestExportSecretsAsMap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"secrets": []map[string]interface{}{
				{"key": "DATABASE_URL", "value": "postgres://localhost/db"},
				{"key": "API_KEY", "value": "sk_test_123"},
			},
		})
	}))
	defer server.Close()

	client, err := New(Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	secrets, err := client.ExportSecretsAsMap(context.Background(), "proj-1", "production")
	require.NoError(t, err)
	assert.Equal(t, "postgres://localhost/db", secrets["DATABASE_URL"])
	assert.Equal(t, "sk_test_123", secrets["API_KEY"])
}

func TestGetSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/projects/proj-1/environments/production/secrets/DATABASE_URL", r.URL.Path)

		// API returns {"secret": {...}} wrapper
		json.NewEncoder(w).Encode(map[string]interface{}{
			"secret": map[string]interface{}{
				"id":    "secret-1",
				"key":   "DATABASE_URL",
				"value": "postgres://localhost/db",
			},
		})
	}))
	defer server.Close()

	client, err := New(Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	secret, err := client.GetSecret(context.Background(), "proj-1", "production", "DATABASE_URL")
	require.NoError(t, err)
	assert.Equal(t, "DATABASE_URL", secret.Key)
	assert.Equal(t, "postgres://localhost/db", secret.Value)
}

func TestSetSecret(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method == "PUT" {
			assert.Equal(t, "/projects/proj-1/environments/production/secrets/API_KEY", r.URL.Path)

			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			assert.Equal(t, "sk_test_new", body["value"])

			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":    "secret-1",
				"key":   "API_KEY",
				"value": "sk_test_new",
			})
		}
	}))
	defer server.Close()

	client, err := New(Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	err = client.SetSecret(context.Background(), "proj-1", "production", "API_KEY", "sk_test_new")
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)
}

func TestDeleteSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/projects/proj-1/environments/production/secrets/OLD_KEY", r.URL.Path)
		assert.Equal(t, "DELETE", r.Method)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := New(Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	err = client.DeleteSecret(context.Background(), "proj-1", "production", "OLD_KEY")
	require.NoError(t, err)
}

func TestLoadEnv(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"secrets": []map[string]interface{}{
				{"key": "TEST_VAR_1", "value": "value1"},
				{"key": "TEST_VAR_2", "value": "value2"},
			},
		})
	}))
	defer server.Close()

	// Clean up after test
	defer func() {
		os.Unsetenv("TEST_VAR_1")
		os.Unsetenv("TEST_VAR_2")
	}()

	client, err := New(Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	count, err := client.LoadEnv(context.Background(), "proj-1", "production")
	require.NoError(t, err)
	assert.Equal(t, 2, count)
	assert.Equal(t, "value1", os.Getenv("TEST_VAR_1"))
	assert.Equal(t, "value2", os.Getenv("TEST_VAR_2"))
}

func TestGenerateEnvFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"secrets": []map[string]interface{}{
				{"key": "SIMPLE", "value": "simple_value"},
				{"key": "WITH_SPACES", "value": "value with spaces"},
				{"key": "WITH_QUOTES", "value": "value \"quoted\""},
			},
		})
	}))
	defer server.Close()

	client, err := New(Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	content, err := client.GenerateEnvFile(context.Background(), "proj-1", "production")
	require.NoError(t, err)
	assert.Contains(t, content, "SIMPLE=simple_value\n")
	assert.Contains(t, content, "WITH_SPACES=\"value with spaces\"\n")
	assert.Contains(t, content, "WITH_QUOTES=\"value \\\"quoted\\\"\"\n")
}

func TestBulkImport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/projects/proj-1/environments/development/secrets/bulk", r.URL.Path)
		assert.Equal(t, "POST", r.Method)

		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		assert.True(t, body["overwrite"].(bool))

		json.NewEncoder(w).Encode(map[string]interface{}{
			"created": 2,
			"updated": 1,
			"skipped": 0,
		})
	}))
	defer server.Close()

	client, err := New(Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	result, err := client.BulkImport(context.Background(), "proj-1", "development", []SecretInput{
		{Key: "VAR1", Value: "value1"},
		{Key: "VAR2", Value: "value2"},
		{Key: "VAR3", Value: "value3"},
	}, BulkImportOptions{Overwrite: true})

	require.NoError(t, err)
	assert.Equal(t, 2, result.Created)
	assert.Equal(t, 1, result.Updated)
	assert.Equal(t, 0, result.Skipped)
}

func TestErrorHandling(t *testing.T) {
	t.Run("handles 401 unauthorized", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid token",
			})
		}))
		defer server.Close()

		client, _ := New(Config{Token: "bad-token", BaseURL: server.URL})
		_, err := client.ListProjects(context.Background())

		require.Error(t, err)
		keyenvErr, ok := err.(*Error)
		require.True(t, ok)
		assert.Equal(t, 401, keyenvErr.Status)
		assert.True(t, keyenvErr.IsUnauthorized())
	})

	t.Run("handles 404 not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Project not found",
			})
		}))
		defer server.Close()

		client, _ := New(Config{Token: "test-token", BaseURL: server.URL})
		_, err := client.GetProject(context.Background(), "nonexistent")

		require.Error(t, err)
		keyenvErr, ok := err.(*Error)
		require.True(t, ok)
		assert.Equal(t, 404, keyenvErr.Status)
		assert.True(t, keyenvErr.IsNotFound())
	})

	t.Run("handles 403 forbidden", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Access denied",
			})
		}))
		defer server.Close()

		client, _ := New(Config{Token: "test-token", BaseURL: server.URL})
		_, err := client.GetSecret(context.Background(), "proj-1", "production", "SECRET")

		require.Error(t, err)
		keyenvErr, ok := err.(*Error)
		require.True(t, ok)
		assert.Equal(t, 403, keyenvErr.Status)
		assert.True(t, keyenvErr.IsForbidden())
	})
}

func TestCaching(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(map[string]interface{}{
			"secrets": []map[string]interface{}{
				{"key": "CACHED_VAR", "value": "cached_value"},
			},
		})
	}))
	defer server.Close()

	client, err := New(Config{
		Token:    "test-token",
		BaseURL:  server.URL,
		CacheTTL: 5 * time.Minute,
	})
	require.NoError(t, err)

	// First call - should hit the server
	_, err = client.ExportSecrets(context.Background(), "proj-1", "production")
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Second call - should use cache
	_, err = client.ExportSecrets(context.Background(), "proj-1", "production")
	require.NoError(t, err)
	assert.Equal(t, 1, callCount) // Still 1

	// Clear cache
	client.ClearCache("proj-1", "production")

	// Third call - should hit the server again
	_, err = client.ExportSecrets(context.Background(), "proj-1", "production")
	require.NoError(t, err)
	assert.Equal(t, 2, callCount)
}

func TestCachingDisabled(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(map[string]interface{}{
			"secrets": []map[string]interface{}{
				{"key": "VAR", "value": "value"},
			},
		})
	}))
	defer server.Close()

	client, err := New(Config{
		Token:    "test-token",
		BaseURL:  server.URL,
		CacheTTL: 0, // Disabled
	})
	require.NoError(t, err)

	// First call
	_, err = client.ExportSecrets(context.Background(), "proj-1", "production")
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Second call - should hit server (no caching)
	_, err = client.ExportSecrets(context.Background(), "proj-1", "production")
	require.NoError(t, err)
	assert.Equal(t, 2, callCount)
}
