package zoom

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetUserDetails(t *testing.T) {
	// Test cases
	testCases := []struct {
		name           string
		userID         string
		email          string
		mockResponse   string
		mockStatusCode int
		expectedLTIID  string
		expectedName   string
	}{
		{
			name:   "User with LTI ID",
			userID: "user-123",
			email:  "user@example.com",
			mockResponse: `{
				"id": "user-123",
				"email": "user@example.com",
				"first_name": "Test",
				"last_name": "User",
				"custom_attributes": [
					{
						"key": "attr-key-123",
						"name": "lti_id",
						"value": "lti-user-456"
					},
					{
						"key": "attr-key-789",
						"name": "other_attr",
						"value": "some-value"
					}
				]
			}`,
			mockStatusCode: http.StatusOK,
			expectedLTIID:  "lti-user-456",
			expectedName:   "Test User",
		},
		{
			name:   "User without LTI ID",
			userID: "user-456",
			email:  "another@example.com",
			mockResponse: `{
				"id": "user-456",
				"email": "another@example.com",
				"first_name": "Another",
				"last_name": "Person",
				"custom_attributes": [
					{
						"key": "attr-key-789",
						"name": "other_attr",
						"value": "some-value"
					}
				]
			}`,
			mockStatusCode: http.StatusOK,
			expectedLTIID:  "",
			expectedName:   "Another Person",
		},
		{
			name:           "API error",
			userID:         "user-789",
			email:          "bad@example.com",
			mockResponse:   `{"error": "Not found"}`,
			mockStatusCode: http.StatusNotFound,
			expectedLTIID:  "",
			expectedName:   "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock HTTP server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Set response status and body
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.mockStatusCode)
				w.Write([]byte(tc.mockResponse))
			}))
			defer server.Close()

			// Create client with mock server
			tokenStore := NewMockTokenStore()
			client := NewClient(tokenStore)
			client.baseURL = server.URL

			// Call GetUserDetails
			userDetails := GetUserDetails(client, tc.userID, tc.email)

			// Verify results
			if userDetails.ID != tc.userID {
				t.Errorf("Expected user ID %s, got %s", tc.userID, userDetails.ID)
			}

			if userDetails.Email != tc.email {
				t.Errorf("Expected email %s, got %s", tc.email, userDetails.Email)
			}

			// If API error, we should fall back to minimal info
			if tc.mockStatusCode != http.StatusOK {
				if userDetails.FullName != "" {
					t.Errorf("Expected empty full name, got %s", userDetails.FullName)
				}
				return
			}

			// Check for LTI ID
			if userDetails.LTIID != tc.expectedLTIID {
				t.Errorf("Expected LTI ID %s, got %s", tc.expectedLTIID, userDetails.LTIID)
			}

			// Check name
			if userDetails.FullName != tc.expectedName {
				t.Errorf("Expected name %s, got %s", tc.expectedName, userDetails.FullName)
			}
		})
	}
}

func TestGetUserName(t *testing.T) {
	// Test cases
	testCases := []struct {
		name           string
		userID         string
		email          string
		mockResponse   string
		mockStatusCode int
		expectedName   string
	}{
		{
			name:   "User with name",
			userID: "user-123",
			email:  "user@example.com",
			mockResponse: `{
				"id": "user-123",
				"email": "user@example.com",
				"first_name": "Test",
				"last_name": "User"
			}`,
			mockStatusCode: http.StatusOK,
			expectedName:   "Test User",
		},
		{
			name:   "User with empty last name",
			userID: "user-456",
			email:  "another@example.com",
			mockResponse: `{
				"id": "user-456",
				"email": "another@example.com",
				"first_name": "Another",
				"last_name": ""
			}`,
			mockStatusCode: http.StatusOK,
			expectedName:   "Another ",
		},
		{
			name:           "API error",
			userID:         "user-789",
			email:          "bad@example.com",
			mockResponse:   `{"error": "Not found"}`,
			mockStatusCode: http.StatusNotFound,
			expectedName:   "bad@example.com", // Fall back to email
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock HTTP server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Set response status and body
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.mockStatusCode)
				w.Write([]byte(tc.mockResponse))
			}))
			defer server.Close()

			// Create client with mock server
			tokenStore := NewMockTokenStore()
			client := NewClient(tokenStore)
			client.baseURL = server.URL
			
			// Replace client creation in GetUserName
			originalNewClient := NewClient
			defer func() { NewClient = originalNewClient }()
			NewClient = func(ts TokenStore) *Client {
				return client
			}

			// Call GetUserName
			userName := GetUserName(tokenStore, tc.userID, tc.email)

			// Verify result
			if userName != tc.expectedName {
				t.Errorf("Expected name %s, got %s", tc.expectedName, userName)
			}
		})
	}
} 