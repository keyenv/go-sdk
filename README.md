# KeyEnv Go SDK

Official Go SDK for [KeyEnv](https://keyenv.dev) - Secrets management made simple.

[![Go Reference](https://pkg.go.dev/badge/github.com/keyenv/go-sdk.svg)](https://pkg.go.dev/github.com/keyenv/go-sdk)
[![Go Report Card](https://goreportcard.com/badge/github.com/keyenv/go-sdk)](https://goreportcard.com/report/github.com/keyenv/go-sdk)

## Installation

```bash
go get github.com/keyenv/go-sdk
```

## Quick Start

```go
package main

import (
    "fmt"
    "os"

    "github.com/keyenv/go-sdk"
)

func main() {
    client, err := keyenv.New(keyenv.Config{
        Token: os.Getenv("KEYENV_TOKEN"),
    })
    if err != nil {
        panic(err)
    }

    // Load secrets into environment
    if _, err := client.LoadEnv(context.Background(), "your-project-id", "production"); err != nil {
        panic(err)
    }

    fmt.Println(os.Getenv("DATABASE_URL"))
}
```

## Configuration

```go
client, err := keyenv.New(keyenv.Config{
    Token:    "your-service-token",      // Required
    BaseURL:  "https://api.keyenv.dev",  // Optional, default shown
    Timeout:  30 * time.Second,          // Optional, default 30s
    CacheTTL: 5 * time.Minute,           // Optional, 0 disables caching
})
```

## Loading Secrets

### Load into Environment

The simplest way to use secrets in your application:

```go
count, err := client.LoadEnv(ctx, "project-id", "production")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Loaded %d secrets\n", count)

// Now use them
fmt.Println(os.Getenv("DATABASE_URL"))
```

### Export as Map

Get secrets as a map:

```go
secrets, err := client.ExportSecretsAsMap(ctx, "project-id", "production")
if err != nil {
    log.Fatal(err)
}
fmt.Println(secrets["DATABASE_URL"])
```

### Export with Metadata

Get secrets with full metadata:

```go
secrets, err := client.ExportSecrets(ctx, "project-id", "production")
if err != nil {
    log.Fatal(err)
}
for _, secret := range secrets {
    fmt.Printf("%s=%s\n", secret.Key, secret.Value)
}
```

## Managing Secrets

### Get a Single Secret

```go
secret, err := client.GetSecret(ctx, "project-id", "production", "DATABASE_URL")
if err != nil {
    log.Fatal(err)
}
fmt.Println(secret.Value)
```

### Set a Secret

Creates or updates a secret:

```go
err := client.SetSecret(ctx, "project-id", "production", "API_KEY", "sk_live_...")
if err != nil {
    log.Fatal(err)
}

// With description
description := "Production API key"
err = client.SetSecretWithDescription(ctx, "project-id", "production", "API_KEY", "sk_live_...", &description)
```

### Delete a Secret

```go
err := client.DeleteSecret(ctx, "project-id", "production", "OLD_KEY")
```

## Bulk Operations

### Bulk Import

```go
result, err := client.BulkImport(ctx, "project-id", "development", []keyenv.SecretInput{
    {Key: "DATABASE_URL", Value: "postgres://localhost/mydb"},
    {Key: "REDIS_URL", Value: "redis://localhost:6379"},
}, keyenv.BulkImportOptions{Overwrite: true})

fmt.Printf("Created: %d, Updated: %d\n", result.Created, result.Updated)
```

### Generate .env File

```go
content, err := client.GenerateEnvFile(ctx, "project-id", "production")
if err != nil {
    log.Fatal(err)
}
os.WriteFile(".env", []byte(content), 0644)
```

## Projects & Environments

### List Projects

```go
projects, err := client.ListProjects(ctx)
for _, project := range projects {
    fmt.Printf("%s (%s)\n", project.Name, project.ID)
}
```

### Get Project Details

```go
project, err := client.GetProject(ctx, "project-id")
fmt.Printf("Project: %s\n", project.Name)
for _, env := range project.Environments {
    fmt.Printf("  - %s\n", env.Name)
}
```

## Error Handling

```go
secret, err := client.GetSecret(ctx, "project-id", "production", "MISSING_KEY")
if err != nil {
    var keyenvErr *keyenv.Error
    if errors.As(err, &keyenvErr) {
        switch {
        case keyenvErr.IsUnauthorized():
            log.Fatal("Invalid or expired token")
        case keyenvErr.IsForbidden():
            log.Fatal("Access denied")
        case keyenvErr.IsNotFound():
            log.Fatal("Secret not found")
        default:
            log.Fatalf("Error %d: %s", keyenvErr.Status, keyenvErr.Message)
        }
    }
}
```

## Caching

Enable caching for better performance in serverless environments:

```go
client, _ := keyenv.New(keyenv.Config{
    Token:    os.Getenv("KEYENV_TOKEN"),
    CacheTTL: 5 * time.Minute,
})

// Cached for 5 minutes
secrets, _ := client.ExportSecrets(ctx, "project-id", "production")

// Clear cache manually
client.ClearCache("project-id", "production")

// Or clear all cache
client.ClearAllCache()
```

## API Reference

### Constructor Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `Token` | `string` | Yes | - | Service token |
| `BaseURL` | `string` | No | `https://api.keyenv.dev` | API base URL |
| `Timeout` | `time.Duration` | No | `30s` | Request timeout |
| `CacheTTL` | `time.Duration` | No | `0` | Cache TTL (0 = disabled) |

### Methods

| Method | Description |
|--------|-------------|
| `GetCurrentUser(ctx)` | Get current user/token info |
| `ListProjects(ctx)` | List all accessible projects |
| `GetProject(ctx, id)` | Get project with environments |
| `ListEnvironments(ctx, projectId)` | List environments |
| `ListSecrets(ctx, projectId, env)` | List secret keys (no values) |
| `ExportSecrets(ctx, projectId, env)` | Export secrets with values |
| `ExportSecretsAsMap(ctx, projectId, env)` | Export as map |
| `GetSecret(ctx, projectId, env, key)` | Get single secret |
| `SetSecret(ctx, projectId, env, key, value)` | Create or update secret |
| `SetSecretWithDescription(ctx, ...)` | Create/update with description |
| `DeleteSecret(ctx, projectId, env, key)` | Delete secret |
| `BulkImport(ctx, projectId, env, secrets, opts)` | Bulk import secrets |
| `LoadEnv(ctx, projectId, env)` | Load secrets into os.Environ |
| `GenerateEnvFile(ctx, projectId, env)` | Generate .env file content |
| `GetSecretHistory(ctx, projectId, env, key)` | Get secret version history |
| `ListPermissions(ctx, projectId, env)` | List permissions |
| `SetPermission(ctx, projectId, env, userId, role)` | Set user permission |
| `DeletePermission(ctx, projectId, env, userId)` | Delete permission |
| `BulkSetPermissions(ctx, projectId, env, perms)` | Bulk set permissions |
| `GetMyPermissions(ctx, projectId)` | Get current user's permissions |
| `GetProjectDefaults(ctx, projectId)` | Get default permissions |
| `SetProjectDefaults(ctx, projectId, defaults)` | Set default permissions |
| `ClearCache(projectId, env)` | Clear cached secrets |
| `ClearAllCache()` | Clear all cached data |

## Examples

### HTTP Server

```go
package main

import (
    "context"
    "log"
    "net/http"
    "os"

    "github.com/keyenv/go-sdk"
)

func main() {
    client, _ := keyenv.New(keyenv.Config{
        Token: os.Getenv("KEYENV_TOKEN"),
    })

    // Load secrets before starting server
    client.LoadEnv(context.Background(), os.Getenv("KEYENV_PROJECT"), "production")

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("OK"))
    })

    log.Fatal(http.ListenAndServe(":"+os.Getenv("PORT"), nil))
}
```

### Lambda Function

```go
package main

import (
    "context"
    "os"
    "time"

    "github.com/aws/aws-lambda-go/lambda"
    "github.com/keyenv/go-sdk"
)

var client *keyenv.Client

func init() {
    client, _ = keyenv.New(keyenv.Config{
        Token:    os.Getenv("KEYENV_TOKEN"),
        CacheTTL: 5 * time.Minute, // Cache across warm invocations
    })
    client.LoadEnv(context.Background(), os.Getenv("KEYENV_PROJECT"), "production")
}

func handler(ctx context.Context) (string, error) {
    return os.Getenv("API_KEY"), nil
}

func main() {
    lambda.Start(handler)
}
```

## License

MIT License - see [LICENSE](LICENSE) for details.
