package caliper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	
	"github.com/corey/zoom-caliper/internal/types"
)

// Client represents a Caliper client
type Client struct {
	Endpoint string
	ApiKey   string
}

// NewClient creates a new Caliper client
func NewClient(endpoint, apiKey string) *Client {
	return &Client{
		Endpoint: endpoint,
		ApiKey:   apiKey,
	}
}

// SendEvent sends a Caliper event
func (c *Client) SendEvent(event *types.CaliperEvent) error {
	// Log the event
	eventJSON, _ := json.MarshalIndent(event, "", "  ")
	log.Printf("Sending Caliper event: \n%s", string(eventJSON))
	
	// Skip actual HTTP request if endpoint is not configured (for testing)
	if c.Endpoint == "" {
		log.Printf("Skipping HTTP request - no endpoint configured")
		return nil
	}
	
	// Marshal event to JSON
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}
	
	// Prepare request
	req, err := http.NewRequest("POST", c.Endpoint, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if c.ApiKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))
	}
	
	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	// Check response
	if resp.StatusCode >= 400 {
		return fmt.Errorf("request failed with status: %s", resp.Status)
	}
	
	log.Printf("Caliper event sent successfully: %s", resp.Status)
	return nil
}

// TestClient is a no-op implementation for testing
type TestClient struct {
	Events []*types.CaliperEvent
}

// NewTestClient creates a new test client
func NewTestClient() *TestClient {
	return &TestClient{
		Events: []*types.CaliperEvent{},
	}
}

// SendEvent implements the CaliperClient interface for testing
func (c *TestClient) SendEvent(event *types.CaliperEvent) error {
	eventJSON, _ := json.MarshalIndent(event, "", "  ")
	log.Printf("TEST CLIENT: Caliper event received: \n%s", string(eventJSON))
	c.Events = append(c.Events, event)
	return nil
} 