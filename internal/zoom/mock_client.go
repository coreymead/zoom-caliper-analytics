package zoom

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	
	"github.com/corey/zoom-caliper/internal/types"
)

// Variables for testing
var (
	zoomClientForTesting    *Client
	getUserDetailsForTesting func(client *Client, userID string, email string) UserWithLTI
)

// Error variables
var (
	ErrNoToken = fmt.Errorf("no token available")
)

// Initialize variables with mocks for testing
func init() {
	// Default implementation that will be replaced in tests
	getUserDetailsForTesting = GetUserDetails
}

// MockTokenStore is a token store implementation for testing
type MockTokenStore struct {
	tokens map[string]*Token
	oauthConfig *OAuthConfig
}

// NewMockTokenStore creates a new mock token store
func NewMockTokenStore() *MockTokenStore {
	return &MockTokenStore{
		tokens: make(map[string]*Token),
	}
}

// GetToken returns a token from the store
func (m *MockTokenStore) GetToken() (*Token, error) {
	token, ok := m.tokens["default"]
	if !ok {
		return nil, ErrNoToken
	}
	return token, nil
}

// SaveToken saves a token to the store
func (m *MockTokenStore) SaveToken(token *Token) error {
	m.tokens["default"] = token
	return nil
}

// RefreshToken refreshes the OAuth token
func (m *MockTokenStore) RefreshToken() (*Token, error) {
	token, err := m.GetToken()
	if err != nil {
		return nil, err
	}
	
	// Simulate token refresh by extending expiry
	token.ExpiresAt = time.Now().Add(time.Hour)
	m.tokens["default"] = token
	return token, nil
}

// SetOAuthConfig sets the OAuth configuration
func (m *MockTokenStore) SetOAuthConfig(config *OAuthConfig) {
	m.oauthConfig = config
}

// MockTransport is an http.RoundTripper that returns predefined responses
type MockTransport struct {
	Responses map[string]*http.Response
}

// RoundTrip implements http.RoundTripper
func (m *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.Method + " " + req.URL.String()
	resp, ok := m.Responses[key]
	if !ok {
		return &http.Response{
			StatusCode: 404,
			Body:       http.NoBody,
		}, nil
	}
	return resp, nil
}

// CreateMockToken creates a token for testing
func CreateMockToken() *Token {
	return &Token{
		AccessToken:  "mock-access-token",
		TokenType:    "bearer",
		RefreshToken: "mock-refresh-token",
		ExpiresIn:    3600,
		Scope:        "user:read meeting:read",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
}

// SendEvent is a mock implementation for testing
func (m *MockTokenStore) SendEvent(event *types.CaliperEvent) error {
	return nil
}

// CreateMockClient creates a client with a mock token store and HTTP client
func CreateMockClient(responses map[string]*http.Response) *Client {
	tokenStore := NewMockTokenStore()
	token := CreateMockToken()
	tokenStore.SaveToken(token)
	
	transport := &MockTransport{
		Responses: responses,
	}
	
	httpClient := &http.Client{
		Transport: transport,
	}
	
	return &Client{
		tokenStore: tokenStore,
		baseURL:    "https://api.zoom.us/v2",
		httpClient: httpClient,
	}
}

// CreateUserResponse creates a mock API response for a user
func CreateUserResponse(user User) *http.Response {
	data, _ := json.Marshal(user)
	return &http.Response{
		StatusCode: 200,
		Body:       NewMockBody(data),
	}
}

// NewMockBody creates a ReadCloser from a byte slice
func NewMockBody(data []byte) *MockReadCloser {
	return &MockReadCloser{
		data: data,
		pos:  0,
	}
}

// MockReadCloser implements io.ReadCloser
type MockReadCloser struct {
	data []byte
	pos  int
}

func (m *MockReadCloser) Read(p []byte) (n int, err error) {
	if m.pos >= len(m.data) {
		return 0, nil
	}
	n = copy(p, m.data[m.pos:])
	m.pos += n
	return n, nil
}

func (m *MockReadCloser) Close() error {
	return nil
} 