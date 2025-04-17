package zoom

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthConfig_GetAuthURL(t *testing.T) {
	config := OAuthConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/oauth/callback",
	}

	url := config.GetAuthURL("test-state")

	assert.Contains(t, url, "https://zoom.us/oauth/authorize")
	assert.Contains(t, url, "client_id=test-client-id")
	assert.Contains(t, url, "redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Foauth%2Fcallback")
	assert.Contains(t, url, "response_type=code")
	assert.Contains(t, url, "state=test-state")
}

func TestOAuthConfig_ExchangeCode(t *testing.T) {
	// Mock HTTP server to simulate Zoom API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/oauth/token", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		
		// Check basic auth header
		username, password, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "test-client-id", username)
		assert.Equal(t, "test-client-secret", password)
		
		// Check form values
		err := r.ParseForm()
		require.NoError(t, err)
		assert.Equal(t, "authorization_code", r.Form.Get("grant_type"))
		assert.Equal(t, "test-code", r.Form.Get("code"))
		assert.Equal(t, "http://localhost:8080/oauth/callback", r.Form.Get("redirect_uri"))
		
		// Send response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "test-access-token",
			"refresh_token": "test-refresh-token",
			"expires_in":    3600,
			"token_type":    "bearer",
		})
	}))
	defer server.Close()
	
	// Use test server URL instead of the real Zoom API
	oauthTokenURL = server.URL + "/oauth/token"
	
	config := OAuthConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/oauth/callback",
	}
	
	token, err := config.ExchangeCode(context.Background(), "test-code")
	require.NoError(t, err)
	
	assert.Equal(t, "test-access-token", token.AccessToken)
	assert.Equal(t, "test-refresh-token", token.RefreshToken)
	assert.Equal(t, "bearer", token.TokenType)
	
	// Check that expiry is set correctly (approximately)
	expectedExpiry := time.Now().Add(3600 * time.Second)
	timeDiff := expectedExpiry.Sub(token.Expiry)
	assert.Less(t, timeDiff, 2*time.Second)
	assert.Greater(t, timeDiff, -2*time.Second)
}

func TestOAuthConfig_RefreshToken(t *testing.T) {
	// Mock HTTP server to simulate Zoom API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/oauth/token", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		
		// Check basic auth header
		username, password, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "test-client-id", username)
		assert.Equal(t, "test-client-secret", password)
		
		// Check form values
		err := r.ParseForm()
		require.NoError(t, err)
		assert.Equal(t, "refresh_token", r.Form.Get("grant_type"))
		assert.Equal(t, "test-refresh-token", r.Form.Get("refresh_token"))
		
		// Send response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "new-access-token",
			"refresh_token": "new-refresh-token",
			"expires_in":    3600,
			"token_type":    "bearer",
		})
	}))
	defer server.Close()
	
	// Use test server URL instead of the real Zoom API
	oauthTokenURL = server.URL + "/oauth/token"
	
	config := OAuthConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/oauth/callback",
	}
	
	oldToken := &Token{
		AccessToken:  "old-access-token",
		RefreshToken: "test-refresh-token",
		TokenType:    "bearer",
		Expiry:       time.Now().Add(-time.Hour), // Expired
	}
	
	newToken, err := config.RefreshToken(context.Background(), oldToken)
	require.NoError(t, err)
	
	assert.Equal(t, "new-access-token", newToken.AccessToken)
	assert.Equal(t, "new-refresh-token", newToken.RefreshToken)
	assert.Equal(t, "bearer", newToken.TokenType)
	
	// Check that expiry is set correctly (approximately)
	expectedExpiry := time.Now().Add(3600 * time.Second)
	timeDiff := expectedExpiry.Sub(newToken.Expiry)
	assert.Less(t, timeDiff, 2*time.Second)
	assert.Greater(t, timeDiff, -2*time.Second)
}

func TestMemoryTokenStore(t *testing.T) {
	store := NewMemoryTokenStore()
	token := &Token{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		TokenType:    "bearer",
		Expiry:       time.Now().Add(time.Hour),
	}
	
	// Initially should have no token
	_, err := store.GetToken()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no token found")
	
	// Save token
	err = store.SaveToken(token)
	require.NoError(t, err)
	
	// Get token back
	retrievedToken, err := store.GetToken()
	require.NoError(t, err)
	assert.Equal(t, token.AccessToken, retrievedToken.AccessToken)
	assert.Equal(t, token.RefreshToken, retrievedToken.RefreshToken)
	assert.Equal(t, token.TokenType, retrievedToken.TokenType)
	assert.Equal(t, token.Expiry.Unix(), retrievedToken.Expiry.Unix())
}

func TestFileTokenStore(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "oauth-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	
	tokenPath := filepath.Join(tempDir, "token.json")
	store, err := NewFileTokenStore(tokenPath)
	require.NoError(t, err)
	
	token := &Token{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		TokenType:    "bearer",
		Expiry:       time.Now().Add(time.Hour),
	}
	
	// Initially should have no token
	_, err = store.GetToken()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no token found")
	
	// Save token
	err = store.SaveToken(token)
	require.NoError(t, err)
	
	// File should exist
	_, err = os.Stat(tokenPath)
	require.NoError(t, err)
	
	// Get token back
	retrievedToken, err := store.GetToken()
	require.NoError(t, err)
	assert.Equal(t, token.AccessToken, retrievedToken.AccessToken)
	assert.Equal(t, token.RefreshToken, retrievedToken.RefreshToken)
	assert.Equal(t, token.TokenType, retrievedToken.TokenType)
	assert.Equal(t, token.Expiry.Unix(), retrievedToken.Expiry.Unix())
	
	// Create new store with same file, should get same token
	store2, err := NewFileTokenStore(tokenPath)
	require.NoError(t, err)
	
	retrievedToken2, err := store2.GetToken()
	require.NoError(t, err)
	assert.Equal(t, token.AccessToken, retrievedToken2.AccessToken)
}

func TestTokenRefresher(t *testing.T) {
	// Mock config that counts refresh calls
	refreshCalled := 0
	config := &mockOAuthConfig{
		refreshFunc: func(ctx context.Context, token *Token) (*Token, error) {
			refreshCalled++
			return &Token{
				AccessToken:  "new-access-token",
				RefreshToken: "new-refresh-token",
				TokenType:    "bearer",
				Expiry:       time.Now().Add(time.Hour),
			}, nil
		},
	}
	
	// Mock store
	store := NewMemoryTokenStore()
	expiredToken := &Token{
		AccessToken:  "expired-token",
		RefreshToken: "refresh-token",
		TokenType:    "bearer",
		Expiry:       time.Now().Add(-time.Hour), // Expired
	}
	err := store.SaveToken(expiredToken)
	require.NoError(t, err)
	
	// Create refresher
	refresher := NewTokenRefresher(config, store)
	
	// Test GetValidToken with expired token - should refresh
	token, err := refresher.GetValidToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "new-access-token", token.AccessToken)
	assert.Equal(t, 1, refreshCalled)
	
	// Test GetValidToken with valid token - should not refresh
	token, err = refresher.GetValidToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "new-access-token", token.AccessToken)
	assert.Equal(t, 1, refreshCalled) // Still 1, no additional refresh
}

// Mock OAuth config for testing
type mockOAuthConfig struct {
	refreshFunc func(context.Context, *Token) (*Token, error)
}

func (m *mockOAuthConfig) GetAuthURL(state string) string {
	return "https://example.com/auth?state=" + state
}

func (m *mockOAuthConfig) ExchangeCode(ctx context.Context, code string) (*Token, error) {
	return &Token{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		TokenType:    "bearer",
		Expiry:       time.Now().Add(time.Hour),
	}, nil
}

func (m *mockOAuthConfig) RefreshToken(ctx context.Context, token *Token) (*Token, error) {
	return m.refreshFunc(ctx, token)
}

func TestToken_IsExpired(t *testing.T) {
	// Test expired token
	expiredToken := &Token{
		AccessToken:  "test-token",
		ExpiresIn:    3600,
		AcquiredAt:   time.Now().Add(-2 * time.Hour).Unix(), // 2 hours ago
	}
	assert.True(t, expiredToken.IsExpired(), "Token should be expired")
	
	// Test token expiring soon (less than 5 minutes)
	expiringSoonToken := &Token{
		AccessToken:  "test-token",
		ExpiresIn:    3600,
		AcquiredAt:   time.Now().Add(-59 * time.Minute).Unix(), // 59 minutes ago, expires in 1 minute
	}
	assert.True(t, expiringSoonToken.IsExpired(), "Token expiring soon should be considered expired")
	
	// Test valid token
	validToken := &Token{
		AccessToken:  "test-token",
		ExpiresIn:    3600,
		AcquiredAt:   time.Now().Add(-30 * time.Minute).Unix(), // 30 minutes ago
	}
	assert.False(t, validToken.IsExpired(), "Token should not be expired")
}

func TestOAuthConfig(t *testing.T) {
	config := OAuthConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://localhost:8443/oauth/callback",
	}

	// Test that authorization URL contains expected values
	authURL := config.GetAuthorizationURL()
	parsedURL, err := url.Parse(authURL)
	require.NoError(t, err)
	
	query := parsedURL.Query()
	assert.Equal(t, "code", query.Get("response_type"))
	assert.Equal(t, "test-client-id", query.Get("client_id"))
	assert.Equal(t, "https://localhost:8443/oauth/callback", query.Get("redirect_uri"))
}

func TestExchangeCodeForToken(t *testing.T) {
	// Mock server to simulate Zoom API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/oauth/token", r.URL.Path)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		
		err := r.ParseForm()
		require.NoError(t, err)
		
		assert.Equal(t, "authorization_code", r.Form.Get("grant_type"))
		assert.Equal(t, "test-code", r.Form.Get("code"))
		assert.Equal(t, "https://localhost:8443/oauth/callback", r.Form.Get("redirect_uri"))
		
		// Check basic auth header
		username, password, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "test-client-id", username)
		assert.Equal(t, "test-client-secret", password)
		
		// Return mock token
		token := Token{
			AccessToken:  "mock-access-token",
			TokenType:    "bearer",
			RefreshToken: "mock-refresh-token",
			ExpiresIn:    3600,
			Scope:        "meeting:read",
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token)
	}))
	defer server.Close()
	
	// Override token endpoint for test
	TokenEndpoint = server.URL + "/oauth/token"
	
	config := OAuthConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://localhost:8443/oauth/callback",
	}
	
	token, err := config.ExchangeCodeForToken("test-code")
	require.NoError(t, err)
	
	assert.Equal(t, "mock-access-token", token.AccessToken)
	assert.Equal(t, "bearer", token.TokenType)
	assert.Equal(t, "mock-refresh-token", token.RefreshToken)
	assert.Equal(t, 3600, token.ExpiresIn)
	assert.Equal(t, "meeting:read", token.Scope)
	assert.Greater(t, token.CreatedAt, int64(0))
}

func TestRefreshToken(t *testing.T) {
	// Mock server to simulate Zoom API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/oauth/token", r.URL.Path)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		
		err := r.ParseForm()
		require.NoError(t, err)
		
		assert.Equal(t, "refresh_token", r.Form.Get("grant_type"))
		assert.Equal(t, "test-refresh-token", r.Form.Get("refresh_token"))
		
		// Check basic auth header
		username, password, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "test-client-id", username)
		assert.Equal(t, "test-client-secret", password)
		
		// Return mock token
		token := Token{
			AccessToken:  "new-access-token",
			TokenType:    "bearer",
			RefreshToken: "new-refresh-token",
			ExpiresIn:    3600,
			Scope:        "meeting:read",
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token)
	}))
	defer server.Close()
	
	// Override token endpoint for test
	TokenEndpoint = server.URL + "/oauth/token"
	
	config := OAuthConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}
	
	oldToken := &Token{
		AccessToken:  "test-access-token",
		TokenType:    "bearer",
		RefreshToken: "test-refresh-token",
		ExpiresIn:    3600,
		Scope:        "meeting:read",
		CreatedAt:    time.Now().Add(-1 * time.Hour).Unix(),
	}
	
	newToken, err := config.RefreshToken(oldToken)
	require.NoError(t, err)
	
	assert.Equal(t, "new-access-token", newToken.AccessToken)
	assert.Equal(t, "bearer", newToken.TokenType)
	assert.Equal(t, "new-refresh-token", newToken.RefreshToken)
	assert.Equal(t, 3600, newToken.ExpiresIn)
	assert.Equal(t, "meeting:read", newToken.Scope)
	assert.Greater(t, newToken.CreatedAt, oldToken.CreatedAt)
}

func TestTokenExpiration(t *testing.T) {
	// Test unexpired token
	unexpiredToken := &Token{
		AccessToken:  "test-access-token",
		ExpiresIn:    3600,
		CreatedAt:    time.Now().Unix(),
	}
	
	assert.False(t, unexpiredToken.IsExpired())
	
	// Test expired token
	expiredToken := &Token{
		AccessToken:  "test-access-token",
		ExpiresIn:    3600,
		CreatedAt:    time.Now().Add(-2 * time.Hour).Unix(),
	}
	
	assert.True(t, expiredToken.IsExpired())
	
	// Test token about to expire
	almostExpiredToken := &Token{
		AccessToken:  "test-access-token",
		ExpiresIn:    3600,
		CreatedAt:    time.Now().Add(-50 * time.Minute).Unix(),
	}
	
	assert.True(t, almostExpiredToken.IsExpired())
}

func TestGetValidToken(t *testing.T) {
	// Mock server to simulate Zoom API for token refresh
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return mock refreshed token
		token := Token{
			AccessToken:  "refreshed-access-token",
			TokenType:    "bearer",
			RefreshToken: "refreshed-refresh-token",
			ExpiresIn:    3600,
			Scope:        "meeting:read",
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token)
	}))
	defer server.Close()
	
	// Override token endpoint for test
	TokenEndpoint = server.URL + "/oauth/token"
	
	// Set up config and store
	config := OAuthConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}
	
	store := NewTokenStore()
	
	// Test with no token
	_, err := GetValidToken(config, store)
	assert.Error(t, err)
	
	// Test with valid token
	validToken := &Token{
		AccessToken:  "valid-access-token",
		TokenType:    "bearer",
		RefreshToken: "valid-refresh-token",
		ExpiresIn:    3600,
		Scope:        "meeting:read",
		CreatedAt:    time.Now().Unix(),
	}
	
	err = store.SaveToken(validToken)
	require.NoError(t, err)
	
	token, err := GetValidToken(config, store)
	assert.NoError(t, err)
	assert.Equal(t, validToken.AccessToken, token.AccessToken)
	
	// Test with expired token
	expiredToken := &Token{
		AccessToken:  "expired-access-token",
		TokenType:    "bearer",
		RefreshToken: "expired-refresh-token",
		ExpiresIn:    3600,
		Scope:        "meeting:read",
		CreatedAt:    time.Now().Add(-2 * time.Hour).Unix(),
	}
	
	err = store.SaveToken(expiredToken)
	require.NoError(t, err)
	
	token, err = GetValidToken(config, store)
	assert.NoError(t, err)
	assert.Equal(t, "refreshed-access-token", token.AccessToken)
} 