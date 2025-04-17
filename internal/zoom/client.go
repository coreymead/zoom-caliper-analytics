package zoom

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/corey/zoom-caliper/internal/types"
)

// User represents a Zoom user profile
type User struct {
	ID              string                 `json:"id"`
	Email           string                 `json:"email"`
	FirstName       string                 `json:"first_name"`
	LastName        string                 `json:"last_name"`
	Role            string                 `json:"role"`
	RoleName        string                 `json:"role_name"`
	Status          string                 `json:"status"`
	Type            int                    `json:"type"`
	AccountID       string                 `json:"account_id"`
	PMI             int                    `json:"pmi"`
	CustomAttributes []CustomAttribute     `json:"custom_attributes"`
}

// CustomAttribute represents a single custom attribute in the Zoom user profile
type CustomAttribute struct {
	Key   string `json:"key"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Client provides methods to interact with the Zoom API
type Client struct {
	tokenStore TokenStore
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new Zoom API client
func NewClient(tokenStore TokenStore) *Client {
	return &Client{
		tokenStore: tokenStore,
		baseURL:    "https://api.zoom.us/v2",
		httpClient: &http.Client{},
	}
}

// SendEvent sends an event to a Caliper endpoint
func (c *Client) SendEvent(event *types.CaliperEvent) error {
	// This is just a placeholder - the actual implementation would depend on how you want to send events
	log.Printf("Sending event to Caliper endpoint: %+v", event)
	return nil
}

// GetMe retrieves the current user's information
func (c *Client) GetMe() (*User, error) {
	return c.GetUser("me")
}

// GetUser retrieves a user by ID
func (c *Client) GetUser(userID string) (*User, error) {
	token, err := c.tokenStore.GetToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	// API endpoint to get user profile with custom attributes
	endpoint := fmt.Sprintf("/users/%s?custom_attributes=true", userID)
	url := c.baseURL + endpoint

	log.Printf("Making request to Zoom API: %s", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("ERROR: Failed to create request: %v", err)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("ERROR: Failed to send request: %v", err)
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read full response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR: Failed to read response: %v", err)
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	log.Printf("User info response status: %d %s", resp.StatusCode, resp.Status)
	
	// For debugging, log part of the response
	if len(respBody) > 200 {
		log.Printf("Response body preview: %s...", string(respBody[:200]))
	} else {
		log.Printf("Response body: %s", string(respBody))
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("ERROR: API request failed: %s", string(respBody))
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var user User
	if err := json.Unmarshal(respBody, &user); err != nil {
		log.Printf("ERROR: Failed to parse user info response: %v", err)
		return nil, fmt.Errorf("failed to parse user info response: %w", err)
	}

	log.Printf("Successfully retrieved user info for user ID: %s", user.ID)
	if len(user.CustomAttributes) > 0 {
		log.Printf("User has %d custom attributes:", len(user.CustomAttributes))
		for _, attr := range user.CustomAttributes {
			log.Printf("  - %s (%s): %s", attr.Name, attr.Key, attr.Value)
		}
	} else {
		log.Printf("User has no custom attributes")
	}
	
	return &user, nil
} 