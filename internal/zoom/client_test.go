package zoom

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// MockTokenStore is a simple implementation of TokenStore for testing
type MockTokenStore struct {
	token *Token
}

func NewMockTokenStore() *MockTokenStore {
	return &MockTokenStore{
		token: &Token{
			AccessToken:  "mock-access-token",
			TokenType:    "Bearer",
			RefreshToken: "mock-refresh-token",
			ExpiresIn:    3600,
		},
	}
}

func (s *MockTokenStore) SaveToken(token *Token) error {
	s.token = token
	return nil
}

func (s *MockTokenStore) GetToken() (*Token, error) {
	return s.token, nil
}

func (s *MockTokenStore) RefreshToken() (*Token, error) {
	return s.token, nil
}

func (s *MockTokenStore) SetOAuthConfig(config *OAuthConfig) {
	// No-op for tests
}

func TestGetUser(t *testing.T) {
	// Create a mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for correct path and auth header
		if r.URL.Path != "/users/test-user-id" {
			t.Errorf("Expected path /users/test-user-id, got %s", r.URL.Path)
		}
		
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer mock-access-token" {
			t.Errorf("Expected Authorization header 'Bearer mock-access-token', got '%s'", authHeader)
		}
		
		// Verify custom_attributes param is set
		if r.URL.Query().Get("custom_attributes") != "true" {
			t.Errorf("Expected custom_attributes=true in query params")
		}
		
		// Respond with mock user data
		user := User{
			ID:        "test-user-id",
			Email:     "test@example.com",
			FirstName: "Test",
			LastName:  "User",
			CustomAttributes: []CustomAttribute{
				{
					Key:   "attribute-key-123",
					Name:  "lti_id",
					Value: "lti-user-456",
				},
			},
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(user)
	}))
	defer server.Close()
	
	// Create client with mock token store and point it to our test server
	tokenStore := NewMockTokenStore()
	client := NewClient(tokenStore)
	client.baseURL = server.URL
	
	// Get user
	user, err := client.GetUser("test-user-id")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	
	// Verify user data
	if user.ID != "test-user-id" {
		t.Errorf("Expected user ID 'test-user-id', got '%s'", user.ID)
	}
	if user.FirstName != "Test" {
		t.Errorf("Expected first name 'Test', got '%s'", user.FirstName)
	}
	if user.LastName != "User" {
		t.Errorf("Expected last name 'User', got '%s'", user.LastName)
	}
	
	// Verify custom attributes
	if len(user.CustomAttributes) != 1 {
		t.Fatalf("Expected 1 custom attribute, got %d", len(user.CustomAttributes))
	}
	
	attr := user.CustomAttributes[0]
	if attr.Name != "lti_id" {
		t.Errorf("Expected attribute name 'lti_id', got '%s'", attr.Name)
	}
	if attr.Value != "lti-user-456" {
		t.Errorf("Expected attribute value 'lti-user-456', got '%s'", attr.Value)
	}
}

func TestGetMe(t *testing.T) {
	// Create a mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for correct path
		if r.URL.Path != "/users/me" {
			t.Errorf("Expected path /users/me, got %s", r.URL.Path)
		}
		
		// Respond with mock user data
		user := User{
			ID:        "current-user-id",
			Email:     "me@example.com",
			FirstName: "Current",
			LastName:  "User",
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(user)
	}))
	defer server.Close()
	
	// Create client with mock token store and point it to our test server
	tokenStore := NewMockTokenStore()
	client := NewClient(tokenStore)
	client.baseURL = server.URL
	
	// Get current user
	user, err := client.GetMe()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	
	// Verify user data
	if user.ID != "current-user-id" {
		t.Errorf("Expected user ID 'current-user-id', got '%s'", user.ID)
	}
	if user.Email != "me@example.com" {
		t.Errorf("Expected email 'me@example.com', got '%s'", user.Email)
	}
}

func TestNewClient(t *testing.T) {
	// Create OAuthConfig
	config := &OAuthConfig{
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
		RedirectURL:  "https://example.com/oauth/callback",
	}

	// Create TokenStore
	tokenStore := NewMockTokenStore()

	// Create client
	client := NewClient(config, tokenStore)

	// Validate client setup
	assert.Equal(t, "https://api.zoom.us/v2", client.baseURL)
	assert.Equal(t, config, client.oauthConfig)
	assert.Equal(t, tokenStore, client.tokenStore)
	assert.NotNil(t, client.httpClient)
}

func TestGetAuthorizationURL(t *testing.T) {
	// Create OAuthConfig
	config := &OAuthConfig{
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
		RedirectURL:  "https://example.com/oauth/callback",
	}

	// Create TokenStore
	tokenStore := NewMockTokenStore()

	// Create client
	client := NewClient(config, tokenStore)

	// Get authorization URL
	url := client.GetAuthorizationURL()

	// Validate URL contains required parameters
	assert.Contains(t, url, "https://zoom.us/oauth/authorize")
	assert.Contains(t, url, "client_id=test_client_id")
	assert.Contains(t, url, "redirect_uri=https%3A%2F%2Fexample.com%2Foauth%2Fcallback")
	assert.Contains(t, url, "response_type=code")
}

func TestExchangeCodeForToken(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		assert.Equal(t, "/oauth/token", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		// Return a mock token response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		mockToken := map[string]interface{}{
			"access_token":  "test_access_token",
			"refresh_token": "test_refresh_token",
			"expires_in":    3600,
			"token_type":    "bearer",
		}
		json.NewEncoder(w).Encode(mockToken)
	}))
	defer server.Close()

	// Create OAuthConfig
	config := &OAuthConfig{
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
		RedirectURL:  "https://example.com/oauth/callback",
	}

	// Create TokenStore
	tokenStore := NewMockTokenStore()

	// Create client and override baseURL to point to test server
	client := NewClient(config, tokenStore)
	client.baseURL = server.URL // Override the baseURL to use our test server

	// Exchange code for token
	token, err := client.ExchangeCodeForToken("test_code")

	// Validate
	assert.NoError(t, err)
	assert.Equal(t, "test_access_token", token.AccessToken)
	assert.Equal(t, "test_refresh_token", token.RefreshToken)
	assert.Equal(t, "bearer", token.TokenType)
	assert.True(t, token.Expiry.After(time.Now()))
}

func TestRefreshAccessToken(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		assert.Equal(t, "/oauth/token", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		// Return a mock token response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		mockToken := map[string]interface{}{
			"access_token":  "new_access_token",
			"refresh_token": "new_refresh_token",
			"expires_in":    3600,
			"token_type":    "bearer",
		}
		json.NewEncoder(w).Encode(mockToken)
	}))
	defer server.Close()

	// Create OAuthConfig
	config := &OAuthConfig{
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
		RedirectURL:  "https://example.com/oauth/callback",
	}

	// Create TokenStore with expired token
	tokenStore := NewMockTokenStore()
	expiredToken := &Token{
		AccessToken:  "old_access_token",
		RefreshToken: "old_refresh_token",
		TokenType:    "bearer",
		Expiry:       time.Now().Add(-time.Hour), // Expired 1 hour ago
	}
	tokenStore.SaveToken(expiredToken)

	// Create client and override baseURL to point to test server
	client := NewClient(config, tokenStore)
	client.baseURL = server.URL // Override the baseURL to use our test server

	// Refresh token
	newToken, err := client.refreshAccessToken(expiredToken)

	// Validate
	assert.NoError(t, err)
	assert.Equal(t, "new_access_token", newToken.AccessToken)
	assert.Equal(t, "new_refresh_token", newToken.RefreshToken)
	assert.Equal(t, "bearer", newToken.TokenType)
	assert.True(t, newToken.Expiry.After(time.Now()))
}

func TestVerifyWebhookSignature(t *testing.T) {
	// Create test data
	webhookSecret := "test_webhook_secret"
	timestamp := "1617293509"
	requestBody := `{"event":"meeting.started","payload":{"object":{"id":"123456789"}}}`
	
	// Calculate expected signature (v0=sha256(webhook_secret+timestamp+requestBody))
	calculatedSignature := calculateSignature(webhookSecret, timestamp, requestBody)
	headers := map[string]string{
		"X-Zm-Request-Timestamp": timestamp,
		"X-Zm-Signature":         calculatedSignature,
	}
	
	// Test successful verification
	result := VerifyWebhookSignature(webhookSecret, headers, []byte(requestBody))
	assert.True(t, result, "Webhook signature verification should pass")
	
	// Test with incorrect signature
	headers["X-Zm-Signature"] = "v0=incorrect_signature"
	result = VerifyWebhookSignature(webhookSecret, headers, []byte(requestBody))
	assert.False(t, result, "Webhook signature verification should fail with incorrect signature")
	
	// Test with missing timestamp
	delete(headers, "X-Zm-Request-Timestamp")
	headers["X-Zm-Signature"] = calculatedSignature
	result = VerifyWebhookSignature(webhookSecret, headers, []byte(requestBody))
	assert.False(t, result, "Webhook signature verification should fail with missing timestamp")
}

func TestGetUserDetails(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request path
		expectedPath := "/users/test_user_id"
		assert.Equal(t, expectedPath, r.URL.Path)
		assert.Equal(t, "GET", r.Method)
		
		// Check authorization header
		authHeader := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer test_access_token", authHeader)
		
		// Return a mock user response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		mockUserResponse := map[string]interface{}{
			"id":         "test_user_id",
			"first_name": "Test",
			"last_name":  "User",
			"email":      "test@example.com",
			"type":       1,
		}
		json.NewEncoder(w).Encode(mockUserResponse)
	}))
	defer server.Close()
	
	// Setup mock LTI lookup
	oldLTILookup := getLTIUserForTesting
	defer func() { getLTIUserForTesting = oldLTILookup }()
	
	getLTIUserForTesting = func(client *Client, userEmail string) LTIUser {
		return LTIUser{
			ID: "lti_user_456",
		}
	}

	// Create client with token
	client := createTestClient(server.URL)
	
	// Perform GetUserDetails
	user, err := client.GetUserDetails("test_user_id")
	
	// Validate
	assert.NoError(t, err)
	assert.Equal(t, "test_user_id", user.ID)
	assert.Equal(t, "Test", user.FirstName)
	assert.Equal(t, "User", user.LastName)
	assert.Equal(t, "test@example.com", user.Email)
}

func TestGetUserWithLTI(t *testing.T) {
	// Create a test server for the user API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a mock user response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		mockUserResponse := map[string]interface{}{
			"id":         "test_user_id",
			"first_name": "Test",
			"last_name":  "User",
			"email":      "test@example.com",
			"type":       1,
		}
		json.NewEncoder(w).Encode(mockUserResponse)
	}))
	defer server.Close()
	
	// Setup mock LTI lookup
	oldLTILookup := getLTIUserForTesting
	defer func() { getLTIUserForTesting = oldLTILookup }()
	
	getLTIUserForTesting = func(client *Client, userEmail string) LTIUser {
		assert.Equal(t, "test@example.com", userEmail)
		return LTIUser{
			ID: "lti_user_456",
		}
	}

	// Create client with token
	client := createTestClient(server.URL)
	
	// Test both GetUserWithLTI methods (with ID or email)
	
	// Test with user ID
	userWithLTI, err := client.GetUserWithLTI("test_user_id", "")
	assert.NoError(t, err)
	assert.Equal(t, "test_user_id", userWithLTI.ID)
	assert.Equal(t, "test@example.com", userWithLTI.Email)
	assert.Equal(t, "lti_user_456", userWithLTI.LTI.ID)
	
	// Test with email only
	userWithLTI, err = client.GetUserWithLTI("", "test@example.com")
	assert.NoError(t, err)
	assert.Equal(t, "lti_user_456", userWithLTI.LTI.ID)
}

// Helper function to create a test client
func createTestClient(baseURL string) *Client {
	config := &OAuthConfig{
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
		RedirectURL:  "https://example.com/oauth/callback",
	}
	
	tokenStore := NewMockTokenStore()
	token := &Token{
		AccessToken:  "test_access_token",
		RefreshToken: "test_refresh_token",
		TokenType:    "bearer",
		Expiry:       time.Now().Add(time.Hour), // Valid for an hour
	}
	tokenStore.SaveToken(token)
	
	client := NewClient(config, tokenStore)
	client.baseURL = baseURL
	
	return client
} 