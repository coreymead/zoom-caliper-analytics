package zoom

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type Token struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresIn    int       `json:"expires_in"`
	Scope        string    `json:"scope"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// IsExpired checks if the token has expired
func (t *Token) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// TokenStore defines the interface for storing and retrieving OAuth tokens
type TokenStore interface {
	// SaveToken persists a token
	SaveToken(token *Token) error
	
	// GetToken retrieves a valid token, refreshing if necessary
	GetToken() (*Token, error)
	
	// RefreshToken attempts to refresh an expired token
	RefreshToken() (*Token, error)
	
	// SetOAuthConfig sets the OAuth configuration for token refresh
	SetOAuthConfig(config *OAuthConfig)
}

// BaseTokenStore provides common token functionality
type BaseTokenStore struct {
	mu           sync.RWMutex
	oauthConfig  *OAuthConfig
}

// SetOAuthConfig sets the OAuth configuration 
func (s *BaseTokenStore) SetOAuthConfig(config *OAuthConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.oauthConfig = config
}

// refreshTokenIfNeeded checks if a token needs refresh and refreshes it
func (s *BaseTokenStore) refreshTokenIfNeeded(token *Token) (bool, error) {
	if token == nil {
		return false, fmt.Errorf("no token available")
	}

	// Check if token is expired or about to expire (5 min buffer)
	if time.Now().Add(5 * time.Minute).After(token.ExpiresAt) {
		s.mu.RLock()
		config := s.oauthConfig
		s.mu.RUnlock()
		
		if config == nil {
			return false, fmt.Errorf("OAuth configuration not set, cannot refresh token")
		}
		
		log.Println("Token expired, attempting to refresh")
		_, err := config.RefreshToken(token.RefreshToken)
		if err != nil {
			return false, fmt.Errorf("failed to refresh token: %w", err)
		}
		
		return true, nil
	}
	
	return false, nil
}

// MemoryTokenStore implements TokenStore with in-memory storage
type MemoryTokenStore struct {
	BaseTokenStore
	token *Token
}

// NewTokenStore creates a new in-memory token store
func NewTokenStore() TokenStore {
	return &MemoryTokenStore{}
}

// SaveToken stores a token in memory
func (s *MemoryTokenStore) SaveToken(token *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = token
	return nil
}

// GetToken retrieves a token from memory, refreshing if necessary
func (s *MemoryTokenStore) GetToken() (*Token, error) {
	s.mu.RLock()
	token := s.token
	s.mu.RUnlock()

	if token == nil {
		return nil, fmt.Errorf("no token available")
	}

	// Check if token needs refresh
	needsRefresh, _ := s.refreshTokenIfNeeded(token)
	if needsRefresh {
		// If refresh is needed, do it
		newToken, err := s.RefreshToken()
		if err != nil {
			return nil, err
		}
		return newToken, nil
	}

	return token, nil
}

// RefreshToken refreshes the stored token
func (s *MemoryTokenStore) RefreshToken() (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token == nil || s.token.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	if s.oauthConfig == nil {
		return nil, fmt.Errorf("OAuth configuration not set")
	}

	// Call the OAuth refresh endpoint
	newToken, err := s.oauthConfig.RefreshToken(s.token.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	// Save the new token
	s.token = newToken
	return newToken, nil
}

// FileTokenStore implements TokenStore using file storage
type FileTokenStore struct {
	BaseTokenStore
	filePath string
	token    *Token
}

// NewFileTokenStore creates a new file-based token store
func NewFileTokenStore(storageDir string) (TokenStore, error) {
	// Ensure the directory exists
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create token storage directory: %w", err)
	}

	filePath := filepath.Join(storageDir, "zoom_token.json")
	store := &FileTokenStore{
		filePath: filePath,
	}

	// Attempt to load existing token
	if err := store.loadToken(); err != nil {
		// It's okay if the file doesn't exist yet
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load token: %w", err)
		}
	}

	return store, nil
}

// SaveToken saves a token to disk
func (s *FileTokenStore) SaveToken(token *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.token = token

	// Marshal token to JSON
	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	// Write to file
	if err := os.WriteFile(s.filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write token to file: %w", err)
	}

	return nil
}

// GetToken retrieves a token, refreshing if necessary
func (s *FileTokenStore) GetToken() (*Token, error) {
	s.mu.RLock()
	token := s.token
	s.mu.RUnlock()

	if token == nil {
		return nil, fmt.Errorf("no token available")
	}

	// Check if token needs refresh
	needsRefresh, _ := s.refreshTokenIfNeeded(token)
	if needsRefresh {
		// If refresh is needed, do it
		newToken, err := s.RefreshToken()
		if err != nil {
			return nil, err
		}
		return newToken, nil
	}

	return token, nil
}

// RefreshToken refreshes the stored token
func (s *FileTokenStore) RefreshToken() (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token == nil || s.token.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	if s.oauthConfig == nil {
		return nil, fmt.Errorf("OAuth configuration not set")
	}

	// Call the OAuth refresh endpoint
	newToken, err := s.oauthConfig.RefreshToken(s.token.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	// Save the new token
	s.token = newToken
	
	// Persist to storage
	data, err := json.MarshalIndent(newToken, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal token: %w", err)
	}

	if err := os.WriteFile(s.filePath, data, 0600); err != nil {
		return nil, fmt.Errorf("failed to write refreshed token to file: %w", err)
	}

	return newToken, nil
}

// loadToken loads a token from disk
func (s *FileTokenStore) loadToken() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	var token Token
	if err := json.Unmarshal(data, &token); err != nil {
		return fmt.Errorf("failed to unmarshal token: %w", err)
	}

	s.token = &token
	return nil
}

func (c *OAuthConfig) AuthCodeURL() string {
	authURL := fmt.Sprintf(
		"https://zoom.us/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s",
		c.ClientID,
		c.RedirectURL,
	)
	log.Printf("Generated OAuth authorization URL: %s", authURL)
	return authURL
}

func (c *OAuthConfig) Exchange(code string) (*Token, error) {
	log.Printf("Exchanging authorization code for token")
	
	tokenURL := "https://zoom.us/oauth/token"
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", c.RedirectURL)
	
	log.Printf("Making token request to: %s", tokenURL)
	
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		log.Printf("ERROR: Failed to create token request: %v", err)
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	
	// Set basic auth and content type
	req.SetBasicAuth(c.ClientID, c.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	// Log the auth header partially (for security)
	maskedClientID := c.ClientID[:5] + "..." + c.ClientID[len(c.ClientID)-5:]
	log.Printf("Using Basic auth with Client ID: %s", maskedClientID)
	log.Printf("Request data: grant_type=authorization_code, code=<redacted>, redirect_uri=%s", c.RedirectURL)
	
	client := &http.Client{}
	log.Printf("Sending token request to Zoom...")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("ERROR: Failed to send token request: %v", err)
		return nil, fmt.Errorf("failed to send token request: %w", err)
	}
	defer resp.Body.Close()
	
	// Read full response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR: Failed to read token response: %v", err)
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}
	
	log.Printf("Token exchange response status: %d %s", resp.StatusCode, resp.Status)
	
	if resp.StatusCode != http.StatusOK {
		log.Printf("ERROR: Token exchange failed: %s", string(respBody))
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(respBody))
	}
	
	var tokenResp Token
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		log.Printf("ERROR: Failed to parse token response: %v", err)
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	
	// Set expiry time
	tokenResp.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	
	log.Printf("Successfully exchanged authorization code for token")
	log.Printf("Token expires at: %s", tokenResp.ExpiresAt.Format("2006-01-02 15:04:05"))
	
	return &tokenResp, nil
}

// RefreshToken refreshes an access token using a refresh token
func (c *OAuthConfig) RefreshToken(refreshToken string) (*Token, error) {
	log.Printf("Refreshing token using refresh token")
	
	tokenURL := "https://zoom.us/oauth/token"
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	
	log.Printf("Making refresh token request to: %s", tokenURL)
	
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		log.Printf("ERROR: Failed to create refresh token request: %v", err)
		return nil, fmt.Errorf("failed to create refresh token request: %w", err)
	}
	
	// Set basic auth and content type
	req.SetBasicAuth(c.ClientID, c.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	// Log the auth header partially (for security)
	maskedClientID := c.ClientID[:5] + "..." + c.ClientID[len(c.ClientID)-5:]
	log.Printf("Using Basic auth with Client ID: %s", maskedClientID)
	log.Printf("Request data: grant_type=refresh_token, refresh_token=<redacted>")
	
	client := &http.Client{}
	log.Printf("Sending refresh token request to Zoom...")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("ERROR: Failed to send refresh token request: %v", err)
		return nil, fmt.Errorf("failed to send refresh token request: %w", err)
	}
	defer resp.Body.Close()
	
	// Read full response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR: Failed to read refresh token response: %v", err)
		return nil, fmt.Errorf("failed to read refresh token response: %w", err)
	}
	
	log.Printf("Refresh token response status: %d %s", resp.StatusCode, resp.Status)
	
	if resp.StatusCode != http.StatusOK {
		log.Printf("ERROR: Token refresh failed: %s", string(respBody))
		return nil, fmt.Errorf("token refresh failed with status %d: %s", resp.StatusCode, string(respBody))
	}
	
	var tokenResp Token
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		log.Printf("ERROR: Failed to parse refresh token response: %v", err)
		return nil, fmt.Errorf("failed to parse refresh token response: %w", err)
	}
	
	// Set expiry time
	tokenResp.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	
	log.Printf("Successfully refreshed token")
	log.Printf("New token expires at: %s", tokenResp.ExpiresAt.Format("2006-01-02 15:04:05"))
	
	return &tokenResp, nil
} 