package zoom

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ValidateSignatureForTest verifies the Zoom webhook signature without reading the request body again
func ValidateSignatureForTest(signature, timestamp string, body []byte, secret string) error {
	if signature == "" {
		return fmt.Errorf("missing Zoom signature header")
	}
	
	if timestamp == "" {
		return fmt.Errorf("missing Zoom timestamp header")
	}
	
	if !strings.HasPrefix(signature, "v0=") {
		return fmt.Errorf("invalid signature format")
	}
	
	signature = strings.TrimPrefix(signature, "v0=")
	
	// According to Zoom docs, the message is concatenation of the endpoint URL,
	// the timestamp header value, and the request body
	// https://marketplace.zoom.us/docs/api-reference/webhook-reference/#verify-webhook-events
	message := fmt.Sprintf("v0:%s:%s", timestamp, string(body))
	
	// Create HMAC SHA256 hash
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	expectedSignature := hex.EncodeToString(h.Sum(nil))
	
	isValid := hmac.Equal([]byte(signature), []byte(expectedSignature))
	if !isValid {
		return fmt.Errorf("invalid signature")
	}
	
	return nil
}

func TestSignatureValidation(t *testing.T) {
	// Create a webhook secret
	webhookSecret := "test-webhook-secret"
	
	// Create a test payload
	payload := []byte(`{"event":"meeting.started","payload":{"id":"123456789"}}`)
	
	// Create a timestamp
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	
	// Generate valid signature
	message := fmt.Sprintf("v0:%s:%s", timestamp, string(payload))
	h := hmac.New(sha256.New, []byte(webhookSecret))
	h.Write([]byte(message))
	validSignature := fmt.Sprintf("v0=%s", hex.EncodeToString(h.Sum(nil)))
	
	// Test valid signature
	err := ValidateSignatureForTest(validSignature, timestamp, payload, webhookSecret)
	if err != nil {
		t.Errorf("Valid signature should be verified, got error: %v", err)
	}
	
	// Test invalid signature
	invalidSignature := fmt.Sprintf("v0=%s", "invalid-signature")
	err = ValidateSignatureForTest(invalidSignature, timestamp, payload, webhookSecret)
	if err == nil {
		t.Errorf("Invalid signature should fail verification")
	}
	
	// Test missing signature
	err = ValidateSignatureForTest("", timestamp, payload, webhookSecret)
	if err == nil {
		t.Errorf("Missing signature should fail verification")
	}
	
	// Test missing timestamp
	err = ValidateSignatureForTest(validSignature, "", payload, webhookSecret)
	if err == nil {
		t.Errorf("Missing timestamp should fail verification")
	}
	
	// Test invalid signature format
	err = ValidateSignatureForTest("invalid-format", timestamp, payload, webhookSecret)
	if err == nil {
		t.Errorf("Invalid signature format should fail verification")
	}
} 