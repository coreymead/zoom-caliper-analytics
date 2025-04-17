package zoom

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/corey/zoom-caliper/internal/caliper"
	"github.com/corey/zoom-caliper/internal/types"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCaliper is a mock caliper client
type TestCaliper struct {
	Events []*caliper.Event
}

func (c *TestCaliper) SendEvent(event *caliper.Event) error {
	c.Events = append(c.Events, event)
	return nil
}

// MockTokenStore is a dummy token store for testing
type MockTokenStore struct {
	token *Token
}

func NewMockTokenStore() *MockTokenStore {
	return &MockTokenStore{
		token: &Token{
			AccessToken:  "mock-access-token",
			RefreshToken: "mock-refresh-token",
			ExpiresAt:    time.Now().Add(1 * time.Hour).Unix(),
		},
	}
}

func (m *MockTokenStore) SaveToken(token *Token) error {
	m.token = token
	return nil
}

func (m *MockTokenStore) GetToken() (*Token, error) {
	if m.token == nil {
		return nil, fmt.Errorf("no token available")
	}
	return m.token, nil
}

func (m *MockTokenStore) DeleteToken() error {
	m.token = nil
	return nil
}

func TestVerifyWebhookSignature(t *testing.T) {
	tests := []struct {
		name           string
		secret         string
		requestBody    string
		timestamp      string
		signature      string
		expectedResult bool
	}{
		{
			name:           "Valid signature",
			secret:         "webhookSecret",
			requestBody:    `{"event":"meeting.started"}`,
			timestamp:      "1619191919",
			signature:      generateSignature("webhookSecret", "1619191919", `{"event":"meeting.started"}`),
			expectedResult: true,
		},
		{
			name:           "Invalid signature",
			secret:         "webhookSecret",
			requestBody:    `{"event":"meeting.started"}`,
			timestamp:      "1619191919",
			signature:      "invalid_signature",
			expectedResult: false,
		},
		{
			name:           "Missing timestamp",
			secret:         "webhookSecret",
			requestBody:    `{"event":"meeting.started"}`,
			timestamp:      "",
			signature:      generateSignature("webhookSecret", "", `{"event":"meeting.started"}`),
			expectedResult: false,
		},
		{
			name:           "Empty body",
			secret:         "webhookSecret",
			requestBody:    "",
			timestamp:      "1619191919",
			signature:      generateSignature("webhookSecret", "1619191919", ""),
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/webhook/zoom", bytes.NewBufferString(tt.requestBody))
			if tt.timestamp != "" {
				req.Header.Set("X-Zm-Request-Timestamp", tt.timestamp)
			}
			req.Header.Set("X-Zm-Signature", tt.signature)

			result := VerifyWebhookSignature(req, tt.secret)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestHandleWebhook(t *testing.T) {
	// Set up test data
	testEvent := types.ZoomEvent{
		Event: "meeting.started",
		Payload: map[string]interface{}{
			"account_id": "test-account",
			"object": map[string]interface{}{
				"id":         "123456789",
				"uuid":       "abcd1234",
				"host_id":    "host-123",
				"topic":      "Test Meeting",
				"type":       2,
				"start_time": time.Now().Format(time.RFC3339),
				"timezone":   "UTC",
				"host": map[string]interface{}{
					"id":    "host-123",
					"email": "host@example.com",
				},
			},
		},
	}

	// Set up Gin context with test request
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	
	// Create test request with JSON body
	eventJSON, _ := json.Marshal(testEvent)
	req, _ := http.NewRequest("POST", "/webhook", bytes.NewBuffer(eventJSON))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req
	
	// Create test dependencies
	tokenStore := NewMockTokenStore()
	client := NewClient(tokenStore)
	
	// Mock the GetUser method with a custom handler
	originalHTTPClient := client.httpClient
	client.httpClient = &http.Client{
		Transport: &mockTransport{
			responses: map[string]mockResponse{
				"/users/host-123": {
					status: http.StatusOK,
					body: `{
						"id": "host-123",
						"email": "host@example.com",
						"first_name": "Test",
						"last_name": "Host",
						"custom_attributes": [
							{
								"key": "attr-123",
								"name": "lti_id",
								"value": "lti-456"
							}
						]
					}`,
				},
			},
		},
	}
	defer func() { client.httpClient = originalHTTPClient }()
	
	// Create test Caliper client
	caliperClient := &TestCaliper{}
	
	// Set up server.Config
	// Call HandleWebhook
	HandleWebhook(c, client, tokenStore)
	
	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
	}
	
	// Parse response body
	var response map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	
	// Verify response data
	if status, ok := response["status"]; !ok || status != "ok" {
		t.Errorf("Expected status 'ok', got '%s'", status)
	}
}

// Mock HTTP transport for testing
type mockTransport struct {
	responses map[string]mockResponse
}

type mockResponse struct {
	status int
	body   string
}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Get the mock response for this path
	resp, ok := t.responses[req.URL.Path]
	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       http.NoBody,
		}, nil
	}
	
	// Return the mock response
	return &http.Response{
		StatusCode: resp.status,
		Body:       io.NopCloser(bytes.NewBufferString(resp.body)),
		Header:     make(http.Header),
	}, nil
}

func TestHandleWebhookEvent(t *testing.T) {
	tests := []struct {
		name            string
		eventJSON       string
		expectedEvent   string
		expectedPayload map[string]interface{}
	}{
		{
			name:          "Meeting Started Event",
			eventJSON:     `{"event":"meeting.started","payload":{"account_id":"abc123","object":{"id":"123456789","topic":"Test Meeting","start_time":"2023-01-01T12:00:00Z","duration":60,"timezone":"UTC"}}}`,
			expectedEvent: "meeting.started",
			expectedPayload: map[string]interface{}{
				"account_id": "abc123",
				"object": map[string]interface{}{
					"id":         "123456789",
					"topic":      "Test Meeting",
					"start_time": "2023-01-01T12:00:00Z",
					"duration":   float64(60),
					"timezone":   "UTC",
				},
			},
		},
		{
			name:          "Meeting Ended Event",
			eventJSON:     `{"event":"meeting.ended","payload":{"account_id":"abc123","object":{"id":"123456789","topic":"Test Meeting","end_time":"2023-01-01T13:00:00Z","duration":60,"timezone":"UTC"}}}`,
			expectedEvent: "meeting.ended",
			expectedPayload: map[string]interface{}{
				"account_id": "abc123",
				"object": map[string]interface{}{
					"id":       "123456789",
					"topic":    "Test Meeting",
					"end_time": "2023-01-01T13:00:00Z",
					"duration": float64(60),
					"timezone": "UTC",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := ParseWebhookEvent([]byte(tt.eventJSON))
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedEvent, event.Event)
			
			// Check that the payload matches the expected structure
			assert.Equal(t, tt.expectedPayload["account_id"], event.Payload["account_id"])
			
			objectExp := tt.expectedPayload["object"].(map[string]interface{})
			objectActual, ok := event.Payload["object"].(map[string]interface{})
			assert.True(t, ok)
			
			for k, v := range objectExp {
				assert.Equal(t, v, objectActual[k])
			}
		})
	}
}

func TestWebhookHandlerWithSignature(t *testing.T) {
	// Set up test data
	webhookSecret := "testSecret123"
	testEvent := types.ZoomEvent{
		Event: "meeting.started",
		Payload: map[string]interface{}{
			"account_id": "test-account",
			"object": map[string]interface{}{
				"id":         "123456789",
				"uuid":       "abcd1234",
				"host_id":    "host-123",
				"topic":      "Test Meeting",
				"type":       2,
				"start_time": time.Now().Format(time.RFC3339),
				"timezone":   "UTC",
				"host": map[string]interface{}{
					"id":    "host-123",
					"email": "host@example.com",
				},
			},
		},
	}

	// Set up Gin context with test request
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	
	// Create test request with JSON body
	eventJSON, _ := json.Marshal(testEvent)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	
	// Generate valid signature
	message := fmt.Sprintf("v0:%s:%s", timestamp, string(eventJSON))
	h := hmac.New(sha256.New, []byte(webhookSecret))
	h.Write([]byte(message))
	signature := fmt.Sprintf("v0=%s", hex.EncodeToString(h.Sum(nil)))
	
	req, _ := http.NewRequest("POST", "/webhook", bytes.NewBuffer(eventJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Zm-Signature", signature)
	req.Header.Set("X-Zm-Request-Timestamp", timestamp)
	c.Request = req
	
	// Create mock dependencies
	tokenStore := NewMockTokenStore()
	client := NewClient(tokenStore)
	
	// Mock the GetUser method with a custom handler
	originalHTTPClient := client.httpClient
	client.httpClient = &http.Client{
		Transport: &mockTransport{
			responses: map[string]mockResponse{
				"/users/host-123": {
					status: http.StatusOK,
					body: `{
						"id": "host-123",
						"email": "host@example.com",
						"first_name": "Test",
						"last_name": "Host",
						"custom_attributes": [
							{
								"key": "attr-123",
								"name": "lti_id",
								"value": "lti-456"
							}
						]
					}`,
				},
			},
		},
	}
	defer func() { client.httpClient = originalHTTPClient }()
	
	// Create test Caliper client
	caliperClient := &TestCaliper{}
	
	// First test the raw body processing flow
	body, _ := io.ReadAll(c.Request.Body)
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
	
	// Verify signature manually
	err := ValidateSignature(signature, timestamp, body, webhookSecret)
	assert.NoError(t, err, "Signature validation should pass")
	
	// Reset the body for handler
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
	
	// Call HandleWebhook
	HandleWebhook(c, client, tokenStore)
	
	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)
	
	// Parse response body
	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	
	// Verify response data
	assert.Equal(t, "ok", response["status"])
}

func TestWebhookHandlerWithInvalidSignature(t *testing.T) {
	// Set up test data with invalid signature
	webhookSecret := "testSecret123"
	testEvent := types.ZoomEvent{
		Event: "meeting.started",
		Payload: map[string]interface{}{
			"account_id": "test-account",
			"object": map[string]interface{}{
				"id":         "123456789",
				"topic":      "Test Meeting",
				"start_time": time.Now().Format(time.RFC3339),
			},
		},
	}

	// Generate JSON payload
	eventJSON, _ := json.Marshal(testEvent)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	
	// Tamper with the signature - use different secret
	message := fmt.Sprintf("v0:%s:%s", timestamp, string(eventJSON))
	h := hmac.New(sha256.New, []byte("wrongSecret"))
	h.Write([]byte(message))
	invalidSignature := fmt.Sprintf("v0=%s", hex.EncodeToString(h.Sum(nil)))
	
	// Verify signature fails
	err := ValidateSignature(invalidSignature, timestamp, eventJSON, webhookSecret)
	assert.Error(t, err, "Signature validation should fail with wrong secret")
	
	// Test with missing timestamp
	err = ValidateSignature(invalidSignature, "", eventJSON, webhookSecret)
	assert.Error(t, err, "Signature validation should fail with missing timestamp")
	
	// Test with missing signature
	err = ValidateSignature("", timestamp, eventJSON, webhookSecret)
	assert.Error(t, err, "Signature validation should fail with missing signature")
}

// Helper function to generate a valid signature for testing
func generateSignature(secret, timestamp, body string) string {
	message := timestamp + body
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	return "v0=" + base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func TestValidateZoomWebhookSignature(t *testing.T) {
	secretKey := "test-webhook-secret"
	timestamp := "1234567890"
	requestBody := `{"event":"meeting.started"}`
	
	// Compute expected signature
	h := hmac.New(sha256.New, []byte(secretKey))
	v := timestamp + "." + requestBody
	h.Write([]byte(v))
	expectedSignature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	
	// Create test request
	req := httptest.NewRequest("POST", "/webhook", bytes.NewBuffer([]byte(requestBody)))
	req.Header.Set("X-Zm-Request-Timestamp", timestamp)
	req.Header.Set("X-Zm-Signature", "v0=" + expectedSignature)
	
	// Test valid signature
	err := ValidateZoomWebhookSignature(secretKey, req)
	assert.NoError(t, err)
	
	// Test invalid signature
	req.Header.Set("X-Zm-Signature", "v0=invalidSignature")
	err = ValidateZoomWebhookSignature(secretKey, req)
	assert.Error(t, err)
	
	// Test missing timestamp
	req = httptest.NewRequest("POST", "/webhook", bytes.NewBuffer([]byte(requestBody)))
	req.Header.Set("X-Zm-Signature", "v0=" + expectedSignature)
	err = ValidateZoomWebhookSignature(secretKey, req)
	assert.Error(t, err)
	
	// Test missing signature
	req = httptest.NewRequest("POST", "/webhook", bytes.NewBuffer([]byte(requestBody)))
	req.Header.Set("X-Zm-Request-Timestamp", timestamp)
	err = ValidateZoomWebhookSignature(secretKey, req)
	assert.Error(t, err)
	
	// Test invalid signature format
	req = httptest.NewRequest("POST", "/webhook", bytes.NewBuffer([]byte(requestBody)))
	req.Header.Set("X-Zm-Request-Timestamp", timestamp)
	req.Header.Set("X-Zm-Signature", "invalidFormat")
	err = ValidateZoomWebhookSignature(secretKey, req)
	assert.Error(t, err)
}

func TestParseZoomEvent(t *testing.T) {
	// Test meeting.started event
	startedJSON := `{
		"event": "meeting.started",
		"payload": {
			"account_id": "account123",
			"object": {
				"id": "meeting123",
				"topic": "LTI-ABC123: Test Meeting",
				"host_id": "host123",
				"duration": 60,
				"start_time": "2023-01-01T12:00:00Z",
				"timezone": "UTC",
				"participant": {
					"user_id": "user123",
					"user_name": "Test User",
					"email": "test@example.com"
				}
			}
		}
	}`
	
	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(startedJSON))
	req.Header.Set("Content-Type", "application/json")
	
	event, err := ParseZoomEvent(req)
	require.NoError(t, err)
	assert.Equal(t, "meeting.started", event.Event)
	assert.Equal(t, "account123", event.Payload.AccountID)
	assert.Equal(t, "meeting123", event.Payload.Object.ID)
	assert.Equal(t, "LTI-ABC123: Test Meeting", event.Payload.Object.Topic)
	
	// Test participant.joined event
	joinedJSON := `{
		"event": "meeting.participant_joined",
		"payload": {
			"account_id": "account123",
			"object": {
				"id": "meeting123",
				"uuid": "uuid123",
				"host_id": "host123",
				"topic": "LTI-ABC123: Test Meeting",
				"participant": {
					"user_id": "user123",
					"user_name": "Test User",
					"email": "test@example.com",
					"join_time": "2023-01-01T12:05:00Z"
				}
			}
		}
	}`
	
	req = httptest.NewRequest("POST", "/webhook", strings.NewReader(joinedJSON))
	req.Header.Set("Content-Type", "application/json")
	
	event, err = ParseZoomEvent(req)
	require.NoError(t, err)
	assert.Equal(t, "meeting.participant_joined", event.Event)
	assert.Equal(t, "account123", event.Payload.AccountID)
	assert.Equal(t, "meeting123", event.Payload.Object.ID)
	assert.Equal(t, "Test User", event.Payload.Object.Participant.UserName)
	assert.Equal(t, "2023-01-01T12:05:00Z", event.Payload.Object.Participant.JoinTime)
	
	// Test invalid JSON
	invalidJSON := `{invalid json}`
	req = httptest.NewRequest("POST", "/webhook", strings.NewReader(invalidJSON))
	req.Header.Set("Content-Type", "application/json")
	
	_, err = ParseZoomEvent(req)
	assert.Error(t, err)
	
	// Test empty body
	req = httptest.NewRequest("POST", "/webhook", nil)
	req.Header.Set("Content-Type", "application/json")
	
	_, err = ParseZoomEvent(req)
	assert.Error(t, err)
}

// Mock EventHandler for testing
type MockEventHandler struct {
	Events []ZoomEvent
	Errors []error
}

func (m *MockEventHandler) HandleEvent(event ZoomEvent) error {
	m.Events = append(m.Events, event)
	if len(m.Errors) > 0 {
		err := m.Errors[0]
		m.Errors = m.Errors[1:]
		return err
	}
	return nil
}

func TestWebhookHandler(t *testing.T) {
	secretKey := "test-webhook-secret"
	eventJSON := `{"event":"meeting.started","payload":{"account_id":"account123","object":{"id":"meeting123"}}}`
	
	// Compute signature
	timestamp := time.Now().Unix()
	timestampStr := string(timestamp)
	h := hmac.New(sha256.New, []byte(secretKey))
	v := timestampStr + "." + eventJSON
	h.Write([]byte(v))
	signature := "v0=" + base64.StdEncoding.EncodeToString(h.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/webhook/zoom", bytes.NewBufferString(body))
	req.Header.Set("X-Zm-Request-Timestamp", timestampStr)
	req.Header.Set("X-Zm-Signature", signature)

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Handle the request
	http.HandlerFunc(handler.HandleWebhook).ServeHTTP(rr, req)

	// Check the response status code
	assert.Equal(t, http.StatusOK, rr.Code)

	// Check that the event was captured and processed
	assert.NotNil(t, capturedEvent)
	assert.Equal(t, "meeting.started", capturedEvent.Event)
	assert.Equal(t, "abc123", capturedEvent.Payload["account_id"])

	// Test with invalid signature
	req = httptest.NewRequest(http.MethodPost, "/webhook/zoom", bytes.NewBufferString(body))
	req.Header.Set("X-Zm-Request-Timestamp", timestampStr)
	req.Header.Set("X-Zm-Signature", "invalid_signature")
	rr = httptest.NewRecorder()
	http.HandlerFunc(handler.HandleWebhook).ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestExtractEventData(t *testing.T) {
	// Test meeting started event
	startedEvent := ZoomEvent{
		Event: "meeting.started",
		Payload: ZoomEventPayload{
			AccountID: "account123",
			Object: ZoomEventObject{
				ID:       "meeting123",
				Topic:    "LTI-ABC123: Test Meeting",
				HostID:   "host123",
				Duration: 60,
				StartTime: "2023-01-01T12:00:00Z",
				Timezone: "UTC",
				Participant: ZoomParticipant{
					UserID:   "user123",
					UserName: "Test Host",
					Email:    "host@example.com",
				},
			},
		},
	}
	
	meetingID, userID, userName, email, err := ExtractEventData(startedEvent)
	assert.NoError(t, err)
	assert.Equal(t, "meeting123", meetingID)
	assert.Equal(t, "user123", userID)
	assert.Equal(t, "Test Host", userName)
	assert.Equal(t, "host@example.com", email)
	
	// Test participant joined event
	joinedEvent := ZoomEvent{
		Event: "meeting.participant_joined",
		Payload: ZoomEventPayload{
			AccountID: "account123",
			Object: ZoomEventObject{
				ID:     "meeting123",
				UUID:   "uuid123",
				HostID: "host123",
				Topic:  "LTI-ABC123: Test Meeting",
				Participant: ZoomParticipant{
					UserID:   "participant123",
					UserName: "Test Participant",
					Email:    "participant@example.com",
					JoinTime: "2023-01-01T12:05:00Z",
				},
			},
		},
	}
	
	meetingID, userID, userName, email, err = ExtractEventData(joinedEvent)
	assert.NoError(t, err)
	assert.Equal(t, "meeting123", meetingID)
	assert.Equal(t, "participant123", userID)
	assert.Equal(t, "Test Participant", userName)
	assert.Equal(t, "participant@example.com", email)
	
	// Test recording completed event
	recordingEvent := ZoomEvent{
		Event: "recording.completed",
		Payload: ZoomEventPayload{
			AccountID: "account123",
			Object: ZoomEventObject{
				ID:       "recording123",
				MeetingID: "meeting123",
				HostID:    "host123",
				Topic:     "LTI-ABC123: Test Meeting",
			},
		},
	}
	
	meetingID, userID, userName, email, err = ExtractEventData(recordingEvent)
	assert.NoError(t, err)
	assert.Equal(t, "meeting123", meetingID)
	assert.Equal(t, "host123", userID)
	assert.Equal(t, "", userName) // No username in recording event
	assert.Equal(t, "", email)    // No email in recording event
}

func TestValidateWebhookSignature(t *testing.T) {
	secret := "test-webhook-secret"

	// Create test payload
	payload := []byte(`{"event":"meeting.started"}`)

	// Create valid signature
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(payload)
	validSignature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	timestamp := time.Now().Unix()

	// Test valid signature
	valid, err := ValidateWebhookSignature(validSignature, timestamp, payload, secret)
	assert.NoError(t, err)
	assert.True(t, valid, "Signature should be valid")

	// Test invalid signature
	invalidSignature := "invalid-signature"
	valid, err = ValidateWebhookSignature(invalidSignature, timestamp, payload, secret)
	assert.NoError(t, err)
	assert.False(t, valid, "Signature should be invalid")

	// Test expired timestamp
	expiredTimestamp := time.Now().Add(-6 * time.Minute).Unix()
	valid, err = ValidateWebhookSignature(validSignature, expiredTimestamp, payload, secret)
	assert.NoError(t, err)
	assert.False(t, valid, "Signature should be invalid due to expired timestamp")
}

func TestParseWebhookRequest(t *testing.T) {
	// Create test event
	event := WebhookEvent{
		Event:     "meeting.started",
		Timestamp: time.Now().Unix(),
		Payload: WebhookEventPayload{
			AccountID: "abc123",
			Object: WebhookEventObject{
				ID:       "123456789",
				UUID:     "abcdef123456",
				HostID:   "host123",
				Topic:    "Test Meeting [LTI_ID:course-123]",
				Type:     2,
				StartTime: time.Now().Format(time.RFC3339),
				Duration:  60,
				Timezone: "America/Los_Angeles",
			},
		},
	}

	// Create request body
	body, err := json.Marshal(event)
	require.NoError(t, err)

	// Create request
	req := httptest.NewRequest("POST", "/webhook/zoom", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Test parsing
	parsedEvent, requestBody, err := ParseWebhookRequest(req)
	require.NoError(t, err)
	assert.Equal(t, event.Event, parsedEvent.Event)
	assert.Equal(t, event.Payload.AccountID, parsedEvent.Payload.AccountID)
	assert.Equal(t, event.Payload.Object.ID, parsedEvent.Payload.Object.ID)
	assert.Equal(t, body, requestBody)

	// Test with invalid JSON
	invalidReq := httptest.NewRequest("POST", "/webhook/zoom", bytes.NewReader([]byte("invalid json")))
	invalidReq.Header.Set("Content-Type", "application/json")
	_, _, err = ParseWebhookRequest(invalidReq)
	assert.Error(t, err)
}

func TestHandleWebhook(t *testing.T) {
	secret := "test-webhook-secret"
	handlerCalled := false
	var capturedEvent WebhookEvent

	// Create handler
	handler := func(event WebhookEvent) error {
		handlerCalled = true
		capturedEvent = event
		return nil
	}

	// Create test event
	event := WebhookEvent{
		Event:     "meeting.started",
		Timestamp: time.Now().Unix(),
		Payload: WebhookEventPayload{
			AccountID: "abc123",
			Object: WebhookEventObject{
				ID:       "123456789",
				UUID:     "abcdef123456",
				HostID:   "host123",
				Topic:    "Test Meeting [LTI_ID:course-123]",
				Type:     2,
				StartTime: time.Now().Format(time.RFC3339),
				Duration:  60,
				Timezone: "America/Los_Angeles",
			},
		},
	}

	// Create request body
	body, err := json.Marshal(event)
	require.NoError(t, err)

	// Create valid signature
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(body)
	validSignature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	timestamp := time.Now().Unix()

	// Create valid request
	req := httptest.NewRequest("POST", "/webhook/zoom", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Zoom-Signature", validSignature)
	req.Header.Set("X-Zoom-Request-Timestamp", string(timestamp))

	// Create response recorder
	w := httptest.NewRecorder()

	// Handle request
	WebhookHandler(secret, handler)(w, req)

	// Check response
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, handlerCalled, "Handler should have been called")
	assert.Equal(t, event.Event, capturedEvent.Event)
	assert.Equal(t, event.Payload.AccountID, capturedEvent.Payload.AccountID)
	assert.Equal(t, event.Payload.Object.ID, capturedEvent.Payload.Object.ID)

	// Test validation failure
	handlerCalled = false
	invalidReq := httptest.NewRequest("POST", "/webhook/zoom", bytes.NewReader(body))
	invalidReq.Header.Set("Content-Type", "application/json")
	invalidReq.Header.Set("X-Zoom-Signature", "invalid-signature")
	invalidReq.Header.Set("X-Zoom-Request-Timestamp", string(timestamp))

	w = httptest.NewRecorder()
	WebhookHandler(secret, handler)(w, invalidReq)
	
	resp = w.Result()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.False(t, handlerCalled, "Handler should not have been called")

	// Test with missing headers
	missingHeaderReq := httptest.NewRequest("POST", "/webhook/zoom", bytes.NewReader(body))
	missingHeaderReq.Header.Set("Content-Type", "application/json")
	
	w = httptest.NewRecorder()
	WebhookHandler(secret, handler)(w, missingHeaderReq)
	
	resp = w.Result()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestEventsStructures(t *testing.T) {
	// Test parsing different webhook events
	testCases := []struct {
		name        string
		eventJson   string
		eventType   string
		checkFields func(*testing.T, WebhookEvent)
	}{
		{
			name: "Meeting Started",
			eventJson: `{
				"event": "meeting.started",
				"timestamp": 1639094400,
				"payload": {
					"account_id": "account123",
					"object": {
						"id": "123456789",
						"uuid": "abcdef123456",
						"host_id": "host123",
						"topic": "Test Meeting [LTI_ID:course-123]",
						"type": 2,
						"start_time": "2023-06-15T10:00:00Z",
						"duration": 60,
						"timezone": "America/Los_Angeles"
					}
				}
			}`,
			eventType: "meeting.started",
			checkFields: func(t *testing.T, event WebhookEvent) {
				assert.Equal(t, "account123", event.Payload.AccountID)
				assert.Equal(t, "123456789", event.Payload.Object.ID)
				assert.Equal(t, "Test Meeting [LTI_ID:course-123]", event.Payload.Object.Topic)
				assert.Equal(t, 2, event.Payload.Object.Type)
				assert.Equal(t, "2023-06-15T10:00:00Z", event.Payload.Object.StartTime)
				assert.Equal(t, 60, event.Payload.Object.Duration)
			},
		},
		{
			name: "Meeting Ended",
			eventJson: `{
				"event": "meeting.ended",
				"timestamp": 1639094460,
				"payload": {
					"account_id": "account123",
					"object": {
						"id": "123456789",
						"uuid": "abcdef123456",
						"host_id": "host123",
						"topic": "Test Meeting [LTI_ID:course-123]",
						"type": 2,
						"start_time": "2023-06-15T10:00:00Z",
						"duration": 60,
						"timezone": "America/Los_Angeles"
					}
				}
			}`,
			eventType: "meeting.ended",
			checkFields: func(t *testing.T, event WebhookEvent) {
				assert.Equal(t, "account123", event.Payload.AccountID)
				assert.Equal(t, "123456789", event.Payload.Object.ID)
			},
		},
		{
			name: "Participant Joined",
			eventJson: `{
				"event": "meeting.participant_joined",
				"timestamp": 1639094410,
				"payload": {
					"account_id": "account123",
					"object": {
						"id": "123456789",
						"uuid": "abcdef123456",
						"host_id": "host123",
						"topic": "Test Meeting [LTI_ID:course-123]",
						"type": 2,
						"participant": {
							"user_id": "user123",
							"user_name": "Test User",
							"email": "test@example.com",
							"join_time": "2023-06-15T10:01:00Z"
						}
					}
				}
			}`,
			eventType: "meeting.participant_joined",
			checkFields: func(t *testing.T, event WebhookEvent) {
				assert.Equal(t, "account123", event.Payload.AccountID)
				assert.Equal(t, "123456789", event.Payload.Object.ID)
				assert.Equal(t, "user123", event.Payload.Object.Participant.UserID)
				assert.Equal(t, "Test User", event.Payload.Object.Participant.UserName)
				assert.Equal(t, "test@example.com", event.Payload.Object.Participant.Email)
				assert.Equal(t, "2023-06-15T10:01:00Z", event.Payload.Object.Participant.JoinTime)
			},
		},
		{
			name: "Participant Left",
			eventJson: `{
				"event": "meeting.participant_left",
				"timestamp": 1639094450,
				"payload": {
					"account_id": "account123",
					"object": {
						"id": "123456789",
						"uuid": "abcdef123456",
						"host_id": "host123",
						"topic": "Test Meeting [LTI_ID:course-123]",
						"type": 2,
						"participant": {
							"user_id": "user123",
							"user_name": "Test User",
							"email": "test@example.com",
							"join_time": "2023-06-15T10:01:00Z",
							"leave_time": "2023-06-15T10:05:00Z"
						}
					}
				}
			}`,
			eventType: "meeting.participant_left",
			checkFields: func(t *testing.T, event WebhookEvent) {
				assert.Equal(t, "account123", event.Payload.AccountID)
				assert.Equal(t, "123456789", event.Payload.Object.ID)
				assert.Equal(t, "user123", event.Payload.Object.Participant.UserID)
				assert.Equal(t, "Test User", event.Payload.Object.Participant.UserName)
				assert.Equal(t, "test@example.com", event.Payload.Object.Participant.Email)
				assert.Equal(t, "2023-06-15T10:01:00Z", event.Payload.Object.Participant.JoinTime)
				assert.Equal(t, "2023-06-15T10:05:00Z", event.Payload.Object.Participant.LeaveTime)
			},
		}
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var event WebhookEvent
			err := json.Unmarshal([]byte(tc.eventJson), &event)
			require.NoError(t, err)
			assert.Equal(t, tc.eventType, event.Event)
			tc.checkFields(t, event)
		})
	}
}

func TestValidateWebhook(t *testing.T) {
	secret := "test-webhook-secret"
	payload := `{"event":"meeting.started","payload":{"object":{"id":"123456789"}}}`
	timestamp := "1624481713000"

	// Calculate the expected signature
	h := hmac.New(sha256.New, []byte(secret))
	v2Hash := "v0:" + timestamp + ":" + payload
	h.Write([]byte(v2Hash))
	expectedSignature := "v0=" + hex.EncodeToString(h.Sum(nil))

	tests := []struct {
		name       string
		headers    map[string]string
		body       string
		secret     string
		wantErr    bool
		errMessage string
	}{
		{
			name: "valid signature",
			headers: map[string]string{
				"X-Zm-Request-Timestamp": timestamp,
				"X-Zm-Signature":         expectedSignature,
			},
			body:    payload,
			secret:  secret,
			wantErr: false,
		},
		{
			name: "missing timestamp header",
			headers: map[string]string{
				"X-Zm-Signature": expectedSignature,
			},
			body:       payload,
			secret:     secret,
			wantErr:    true,
			errMessage: "missing timestamp header",
		},
		{
			name: "missing signature header",
			headers: map[string]string{
				"X-Zm-Request-Timestamp": timestamp,
			},
			body:       payload,
			secret:     secret,
			wantErr:    true,
			errMessage: "missing signature header",
		},
		{
			name: "invalid signature format",
			headers: map[string]string{
				"X-Zm-Request-Timestamp": timestamp,
				"X-Zm-Signature":         "invalid-signature",
			},
			body:       payload,
			secret:     secret,
			wantErr:    true,
			errMessage: "invalid signature format",
		},
		{
			name: "invalid signature value",
			headers: map[string]string{
				"X-Zm-Request-Timestamp": timestamp,
				"X-Zm-Signature":         "v0=invalid-signature",
			},
			body:       payload,
			secret:     secret,
			wantErr:    true,
			errMessage: "signature mismatch",
		},
		{
			name: "expired timestamp",
			headers: map[string]string{
				"X-Zm-Request-Timestamp": "1000000000000", // Very old timestamp
				"X-Zm-Signature":         expectedSignature,
			},
			body:       payload,
			secret:     secret,
			wantErr:    true,
			errMessage: "webhook expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewBufferString(tt.body))
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			err := ValidateWebhook(req, tt.secret)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMessage != "" {
					assert.Contains(t, err.Error(), tt.errMessage)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseEvent(t *testing.T) {
	tests := []struct {
		name        string
		payload     string
		expectEvent string
		expectErr   bool
	}{
		{
			name: "valid meeting.started event",
			payload: `{
				"event": "meeting.started",
				"payload": {
					"account_id": "account123",
					"object": {
						"id": "123456789",
						"uuid": "abc123",
						"host_id": "host123",
						"topic": "Test Meeting [LTI-123]",
						"type": 2,
						"start_time": "2023-01-01T12:00:00Z",
						"timezone": "UTC"
					}
				},
				"event_ts": 1624481713000
			}`,
			expectEvent: "meeting.started",
			expectErr:   false,
		},
		{
			name: "valid meeting.ended event",
			payload: `{
				"event": "meeting.ended",
				"payload": {
					"account_id": "account123",
					"object": {
						"id": "123456789",
						"uuid": "abc123",
						"host_id": "host123",
						"topic": "Test Meeting [LTI-123]",
						"type": 2,
						"start_time": "2023-01-01T12:00:00Z",
						"duration": 60,
						"timezone": "UTC"
					}
				},
				"event_ts": 1624481713000
			}`,
			expectEvent: "meeting.ended",
			expectErr:   false,
		},
		{
			name: "valid participant_joined event",
			payload: `{
				"event": "meeting.participant_joined",
				"payload": {
					"account_id": "account123",
					"object": {
						"id": "123456789",
						"uuid": "abc123",
						"host_id": "host123",
						"topic": "Test Meeting [LTI-123]",
						"type": 2,
						"participant": {
							"user_id": "user123",
							"user_name": "John Doe",
							"email": "john@example.com",
							"join_time": "2023-01-01T12:05:00Z"
						}
					}
				},
				"event_ts": 1624481713000
			}`,
			expectEvent: "meeting.participant_joined",
			expectErr:   false,
		},
		{
			name:        "invalid JSON",
			payload:     `{invalid json}`,
			expectEvent: "",
			expectErr:   true,
		},
		{
			name:        "empty payload",
			payload:     `{}`,
			expectEvent: "",
			expectErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := ParseEvent([]byte(tt.payload))
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectEvent, event.Event)
				assert.NotNil(t, event.Payload)
				assert.NotNil(t, event.Payload.Object)
			}
		})
	}
}

func TestWebhookHandler(t *testing.T) {
	secret := "test-webhook-secret"
	
	// Create a sample event payload
	payload := `{
		"event": "meeting.started",
		"payload": {
			"account_id": "account123",
			"object": {
				"id": "123456789",
				"uuid": "abc123",
				"host_id": "host123",
				"topic": "Test Meeting [LTI-123]",
				"type": 2,
				"start_time": "2023-01-01T12:00:00Z",
				"timezone": "UTC"
			}
		},
		"event_ts": 1624481713000
	}`
	
	// Generate a valid signature
	timestamp := time.Now().UnixMilli()
	timestampStr := string(timestamp)
	h := hmac.New(sha256.New, []byte(secret))
	v2Hash := "v0:" + timestampStr + ":" + payload
	h.Write([]byte(v2Hash))
	signature := "v0=" + hex.EncodeToString(h.Sum(nil))
	
	// Track if handler was called
	handlerCalled := false
	var receivedEvent *Event
	
	handler := func(event *Event) error {
		handlerCalled = true
		receivedEvent = event
		return nil
	}
	
	// Create webhook handler
	webhookHandler := NewWebhookHandler(secret, handler)
	
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(webhookHandler.HandleWebhook))
	defer server.Close()
	
	// Send request to the test server
	req, err := http.NewRequest(http.MethodPost, server.URL, bytes.NewBufferString(payload))
	require.NoError(t, err)
	req.Header.Set("X-Zm-Request-Timestamp", timestampStr)
	req.Header.Set("X-Zm-Signature", signature)
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Check response
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, handlerCalled)
	assert.NotNil(t, receivedEvent)
	assert.Equal(t, "meeting.started", receivedEvent.Event)
	assert.Equal(t, "123456789", receivedEvent.Payload.Object.ID)
}

func TestWebhookHandlerWithInvalidSignature(t *testing.T) {
	secret := "test-webhook-secret"
	
	// Create a sample event payload
	payload := `{
		"event": "meeting.started",
		"payload": {
			"account_id": "account123",
			"object": {
				"id": "123456789",
				"uuid": "abc123",
				"host_id": "host123",
				"topic": "Test Meeting [LTI-123]",
				"type": 2,
				"start_time": "2023-01-01T12:00:00Z",
				"timezone": "UTC"
			}
		},
		"event_ts": 1624481713000
	}`
	
	// Track if handler was called
	handlerCalled := false
	
	handler := func(event *Event) error {
		handlerCalled = true
		return nil
	}
	
	// Create webhook handler
	webhookHandler := NewWebhookHandler(secret, handler)
	
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(webhookHandler.HandleWebhook))
	defer server.Close()
	
	// Send request with invalid signature
	req, err := http.NewRequest(http.MethodPost, server.URL, bytes.NewBufferString(payload))
	require.NoError(t, err)
	req.Header.Set("X-Zm-Request-Timestamp", string(time.Now().UnixMilli()))
	req.Header.Set("X-Zm-Signature", "v0=invalid-signature")
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Check response - should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.False(t, handlerCalled)
}

func TestExtractLtiID(t *testing.T) {
	tests := []struct {
		name     string
		topic    string
		expected string
		hasError bool
	}{
		{
			name:     "valid LTI ID",
			topic:    "Test Meeting [LTI-123]",
			expected: "123",
			hasError: false,
		},
		{
			name:     "valid LTI ID with longer number",
			topic:    "Test Meeting [LTI-123456789]",
			expected: "123456789",
			hasError: false,
		},
		{
			name:     "valid LTI ID with text before and after",
			topic:    "Before [LTI-123] After",
			expected: "123",
			hasError: false,
		},
		{
			name:     "no LTI ID",
			topic:    "Test Meeting",
			expected: "",
			hasError: true,
		},
		{
			name:     "empty topic",
			topic:    "",
			expected: "",
			hasError: true,
		},
		{
			name:     "LTI prefix but no ID",
			topic:    "Test Meeting [LTI-]",
			expected: "",
			hasError: true,
		},
		{
			name:     "LTI ID with special characters",
			topic:    "Test Meeting [LTI-123-456]",
			expected: "123-456",
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := ExtractLtiID(tt.topic)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, id)
			}
		})
	}
}

func TestValidateSignature(t *testing.T) {
	tests := []struct {
		name           string
		secret         string
		bodyContent    string
		timestamp      string
		signature      string
		expectedError  bool
	}{
		{
			name:           "Valid signature",
			secret:         "webhookSecret",
			bodyContent:    `{"event":"meeting.started"}`,
			timestamp:      "1619191919",
			signature:      "v0=" + generateHmacSha256("webhookSecret", "v0:1619191919:{\"event\":\"meeting.started\"}"),
			expectedError:  false,
		},
		{
			name:           "Invalid signature",
			secret:         "webhookSecret",
			bodyContent:    `{"event":"meeting.started"}`,
			timestamp:      "1619191919",
			signature:      "v0=invalid_signature",
			expectedError:  true,
		},
		{
			name:           "Missing timestamp",
			secret:         "webhookSecret",
			bodyContent:    `{"event":"meeting.started"}`,
			timestamp:      "",
			signature:      "v0=" + generateHmacSha256("webhookSecret", "v0::{\"event\":\"meeting.started\"}"),
			expectedError:  true,
		},
		{
			name:           "Missing signature",
			secret:         "webhookSecret",
			bodyContent:    `{"event":"meeting.started"}`,
			timestamp:      "1619191919",
			signature:      "",
			expectedError:  true,
		},
		{
			name:           "Invalid signature format",
			secret:         "webhookSecret",
			bodyContent:    `{"event":"meeting.started"}`,
			timestamp:      "1619191919",
			signature:      "invalid=format",
			expectedError:  true,
		},
		{
			name:           "Empty body",
			secret:         "webhookSecret",
			bodyContent:    "",
			timestamp:      "1619191919",
			signature:      "v0=" + generateHmacSha256("webhookSecret", "v0:1619191919:"),
			expectedError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSignature(tt.signature, tt.timestamp, []byte(tt.bodyContent), tt.secret)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// generateHmacSha256 creates an HMAC SHA256 hash for testing
func generateHmacSha256(secret, message string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
} 