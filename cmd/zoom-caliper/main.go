package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/corey/zoom-caliper/internal/caliper"
	"github.com/corey/zoom-caliper/internal/server"
	"github.com/corey/zoom-caliper/internal/zoom"
	"github.com/joho/godotenv"
)

// MockTokenStore implements a simple token store for testing
type MockTokenStore struct {
	token *zoom.Token
	oauthConfig *zoom.OAuthConfig
}

func NewMockTokenStore() *MockTokenStore {
	// Create a mock token for testing
	return &MockTokenStore{
		token: &zoom.Token{
			AccessToken:  "mock_access_token",
			TokenType:    "Bearer",
			RefreshToken: "mock_refresh_token",
			ExpiresIn:    3600,
			Scope:        "user:read",
			ExpiresAt:    time.Now().Add(time.Hour),
		},
	}
}

func (s *MockTokenStore) SaveToken(token *zoom.Token) error {
	s.token = token
	return nil
}

func (s *MockTokenStore) GetToken() (*zoom.Token, error) {
	if s.token == nil {
		return nil, fmt.Errorf("no token found")
	}
	return s.token, nil
}

func (s *MockTokenStore) RefreshToken() (*zoom.Token, error) {
	// For testing, just simulate a refresh by extending expiry
	if s.token == nil {
		return nil, fmt.Errorf("no token to refresh")
	}
	s.token.ExpiresAt = time.Now().Add(time.Hour)
	return s.token, nil
}

func (s *MockTokenStore) SetOAuthConfig(config *zoom.OAuthConfig) {
	s.oauthConfig = config
}

// MemoryTokenStore implements TokenStore with in-memory storage
type MemoryTokenStore struct {
	token *zoom.Token
	oauthConfig *zoom.OAuthConfig
}

// NewMemoryTokenStore creates a new token store that stores tokens in memory
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{}
}

func (s *MemoryTokenStore) SaveToken(token *zoom.Token) error {
	s.token = token
	return nil
}

func (s *MemoryTokenStore) GetToken() (*zoom.Token, error) {
	if s.token == nil {
		return nil, fmt.Errorf("no token found")
	}
	return s.token, nil
}

func (s *MemoryTokenStore) RefreshToken() (*zoom.Token, error) {
	if s.token == nil || s.token.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}
	
	if s.oauthConfig == nil {
		return nil, fmt.Errorf("OAuth configuration not set")
	}
	
	newToken, err := s.oauthConfig.RefreshToken(s.token.RefreshToken)
	if err != nil {
		return nil, err
	}
	
	s.token = newToken
	return newToken, nil
}

func (s *MemoryTokenStore) SetOAuthConfig(config *zoom.OAuthConfig) {
	s.oauthConfig = config
}

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
	}

	// Debug: Print environment variables
	log.Printf("Environment variables:")
	log.Printf("  ZOOM_WEBHOOK_SECRET: %s", os.Getenv("ZOOM_WEBHOOK_SECRET"))
	log.Printf("  SKIP_WEBHOOK_VERIFICATION: %s", os.Getenv("SKIP_WEBHOOK_VERIFICATION"))
	
	// Load configuration from environment variables
	config := &server.Config{
		ZoomWebhookSecret: os.Getenv("ZOOM_WEBHOOK_SECRET"),
		Port:             8080,
	}

	// Validate required configuration
	if config.ZoomWebhookSecret == "" {
		log.Fatal("ZOOM_WEBHOOK_SECRET is required")
	}

	// Check for TLS certificate paths
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	
	// If TLS environment variables are set, use them
	if certFile != "" && keyFile != "" {
		config.CertFile = certFile
		config.KeyFile = keyFile
		log.Printf("TLS configuration: using cert %s and key %s", certFile, keyFile)
		
		// If using TLS, update the redirect URL to use HTTPS
		if os.Getenv("REDIRECT_URL") == "" {
			// Default redirect URL with HTTPS when TLS is enabled
			os.Setenv("REDIRECT_URL", "https://localhost:8080/oauth/callback")
		}
	} else {
		log.Println("TLS configuration: not provided, using HTTP only")
	}

	// Set up OAuth configuration
	clientID := os.Getenv("ZOOM_CLIENT_ID")
	clientSecret := os.Getenv("ZOOM_CLIENT_SECRET")
	redirectURL := os.Getenv("REDIRECT_URL")
	if clientID == "" || clientSecret == "" {
		log.Fatal("ZOOM_CLIENT_ID and ZOOM_CLIENT_SECRET are required")
	}
	if redirectURL == "" {
		redirectURL = "http://localhost:8080/oauth/callback"
	}

	oauthConfig := &zoom.OAuthConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
	}
	config.OAuthConfig = oauthConfig

	// Get token storage location from env var or use default
	tokenStorageDir := os.Getenv("TOKEN_STORAGE_DIR")
	if tokenStorageDir == "" {
		tokenStorageDir = "data/tokens"
	}

	// Initialize token store
	var tokenStore zoom.TokenStore
	var err error
	
	// Determine which token store to use based on environment
	tokenStoreType := os.Getenv("TOKEN_STORE_TYPE")
	switch tokenStoreType {
	case "memory":
		log.Println("Using in-memory token store (tokens will be lost on restart)")
		tokenStore = NewMemoryTokenStore()
	case "mock":
		log.Println("Using mock token store for testing")
		tokenStore = NewMockTokenStore()
	case "file":
		fallthrough
	default:
		log.Printf("Using file-based token store in directory: %s", tokenStorageDir)
		tokenStore, err = zoom.NewFileTokenStore(tokenStorageDir)
		if err != nil {
			log.Fatalf("Failed to create token store: %v", err)
		}
	}
	
	// Set the OAuth config on the token store for refresh operations
	tokenStore.SetOAuthConfig(oauthConfig)
	config.TokenStore = tokenStore

	// Create a client for Caliper events
	caliperEndpoint := os.Getenv("CALIPER_ENDPOINT")
	caliperApiKey := os.Getenv("CALIPER_API_KEY")
	
	// Use test client if no endpoint is provided or if test client is explicitly requested
	if caliperEndpoint == "" || os.Getenv("USE_TEST_CLIENT") == "true" {
		log.Println("Using test Caliper client (events will be logged but not sent)")
		config.CaliperClient = caliper.NewTestClient()
	} else {
		log.Printf("Using HTTP Caliper client with endpoint: %s", caliperEndpoint)
		config.CaliperClient = caliper.NewClient(caliperEndpoint, caliperApiKey)
	}

	// Create and start the server
	srv := server.NewServer(config)
	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
} 