package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
	}

	// Get webhook URL and secret
	webhookSecret := os.Getenv("ZOOM_WEBHOOK_SECRET")
	webhookURL := "http://localhost:8080/webhook/zoom"

	// Determine which event type to send
	eventType := "meeting.started"
	if len(os.Args) > 1 {
		eventType = os.Args[1]
	}

	var event map[string]interface{}

	switch eventType {
	case "meeting.ended":
		event = createMeetingEndedEvent()
	default:
		event = createMeetingStartedEvent()
	}

	// Send the event
	if err := sendEvent(webhookURL, webhookSecret, event); err != nil {
		log.Fatalf("Error sending event: %v", err)
	}

	log.Printf("Event %s sent successfully!", eventType)
}

func createMeetingStartedEvent() map[string]interface{} {
	return map[string]interface{}{
		"event":      "meeting.started",
		"event_ts":   time.Now().Unix(),
		"account_id": "abc123",
		"payload": map[string]interface{}{
			"id":         "12345",
			"topic":      "Test Meeting",
			"type":       2,
			"start_time": time.Now().Format(time.RFC3339),
			"duration":   60,
			"timezone":   "America/Los_Angeles",
			"host": map[string]interface{}{
				"id":    "host123",
				"email": "host@example.com",
			},
			"participants": []map[string]interface{}{
				{
					"id":    "user1",
					"email": "user1@example.com",
				},
			},
		},
	}
}

func createMeetingEndedEvent() map[string]interface{} {
	return map[string]interface{}{
		"event":      "meeting.ended",
		"event_ts":   time.Now().Unix(),
		"account_id": "abc123",
		"payload": map[string]interface{}{
			"id":         "12345",
			"topic":      "Test Meeting",
			"type":       2,
			"start_time": time.Now().Add(-time.Hour).Format(time.RFC3339),
			"duration":   60,
			"timezone":   "America/Los_Angeles",
			"host": map[string]interface{}{
				"id":    "host123",
				"email": "host@example.com",
			},
			"participants": []map[string]interface{}{
				{
					"id":    "user1",
					"email": "user1@example.com",
				},
			},
		},
	}
}

func sendEvent(url, secret string, event map[string]interface{}) error {
	// Convert event to JSON
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("error marshaling event: %v", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	
	// Generate timestamp
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("x-zm-request-timestamp", timestamp)
	
	// Generate signature
	message := timestamp + string(payload)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	signature := "v0=" + hex.EncodeToString(h.Sum(nil))
	req.Header.Set("x-zm-signature", signature)
	
	// Log the headers and payload
	log.Printf("URL: %s", url)
	log.Printf("Headers:")
	for k, v := range req.Header {
		log.Printf("  %s: %s", k, v)
	}
	log.Printf("Payload: %s", string(payload))
	
	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()
	
	// Read and log the response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response: %v", err)
	}
	log.Printf("Response status: %d", resp.StatusCode)
	log.Printf("Response body: %s", string(respBody))
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	return nil
} 