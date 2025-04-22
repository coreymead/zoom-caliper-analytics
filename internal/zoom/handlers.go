package zoom

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/corey/zoom-caliper/internal/types"
	"github.com/gin-gonic/gin"
	"bytes"
)

// Event represents a Zoom webhook event
type Event struct {
	Event   string                 `json:"event"`
	Payload map[string]interface{} `json:"payload"`
	EventTs int64                  `json:"event_ts"`
}

// MeetingStartedEvent represents a Zoom meeting.started event
type MeetingStartedEvent struct {
	AccountID string `json:"account_id"`
	HostID    string `json:"host_id"`
	MeetingID string `json:"id"`
	Topic     string `json:"topic"`
	Type      int    `json:"type"`
	StartTime string `json:"start_time"`
	Timezone  string `json:"timezone"`
}

// MeetingEndedEvent represents a Zoom meeting.ended event
type MeetingEndedEvent struct {
	AccountID    string `json:"account_id"`
	HostID       string `json:"host_id"`
	MeetingID    string `json:"id"`
	Topic        string `json:"topic"`
	Type         int    `json:"type"`
	StartTime    string `json:"start_time"`
	Timezone     string `json:"timezone"`
	Duration     int    `json:"duration"`
	Participants int    `json:"participants"`
}

// GetUserDetails gets full user information including LTI ID if available
type UserWithLTI struct {
	ID        string
	Email     string
	FirstName string
	LastName  string
	FullName  string
	LTIID     string
}

// ValidateSignature verifies the Zoom webhook signature without reading the request body again
func ValidateSignature(signature, timestamp string, body []byte, secret string) error {
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

// VerifyWebhookSignature verifies the Zoom webhook signature
// This is kept for backward compatibility
func VerifyWebhookSignature(r *http.Request, secret string) error {
	signature := r.Header.Get("x-zm-signature")
	timestamp := r.Header.Get("x-zm-request-timestamp")
	
	// Get the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("error reading request body: %v", err)
	}
	
	// Restore the body for future reads
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	
	return ValidateSignature(signature, timestamp, body, secret)
}

// ParseWebhookEvent parses the Zoom webhook event
func ParseWebhookEvent(c *gin.Context) (*Event, error) {
	var event Event
	if err := c.ShouldBindJSON(&event); err != nil {
		log.Printf("Error binding JSON: %v", err)
		return nil, err
	}

	// Validate required fields
	if event.Event == "" {
		log.Printf("Missing event type in payload")
		return nil, errors.New("event type is required")
	}

	log.Printf("Parsed event type: %s, timestamp: %d", event.Event, event.EventTs)
	return &event, nil
}

// HandleMeetingStarted handles the meeting started event
func HandleMeetingStarted(event *Event) (*MeetingStartedEvent, error) {
	log.Printf("Processing meeting started event")
	var meetingEvent MeetingStartedEvent
	payload, err := json.Marshal(event.Payload)
	if err != nil {
		log.Printf("Error marshaling payload: %v", err)
		return nil, err
	}

	if err := json.Unmarshal(payload, &meetingEvent); err != nil {
		log.Printf("Error unmarshaling meeting event: %v", err)
		return nil, err
	}

	log.Printf("Meeting started: ID=%s, Topic=%s, Host=%s", 
		meetingEvent.MeetingID, meetingEvent.Topic, meetingEvent.HostID)
	return &meetingEvent, nil
}

// HandleMeetingEnded handles the meeting ended event
func HandleMeetingEnded(event *Event) (*MeetingEndedEvent, error) {
	log.Printf("Processing meeting ended event")
	var meetingEvent MeetingEndedEvent
	payload, err := json.Marshal(event.Payload)
	if err != nil {
		log.Printf("Error marshaling payload: %v", err)
		return nil, err
	}

	if err := json.Unmarshal(payload, &meetingEvent); err != nil {
		log.Printf("Error unmarshaling meeting event: %v", err)
		return nil, err
	}

	log.Printf("Meeting ended: ID=%s, Topic=%s, Host=%s, Participants=%d", 
		meetingEvent.MeetingID, meetingEvent.Topic, meetingEvent.HostID, meetingEvent.Participants)
	return &meetingEvent, nil
}

func HandleWebhook(c *gin.Context, client *Client, tokenStore TokenStore, eventStore types.EventStore) {
	var event types.ZoomEvent
	
	// Get the raw body to log
	rawBody, _ := c.GetRawData()
	log.Printf("Raw webhook payload: %s", string(rawBody))
	
	// Restore the body for binding
	c.Request.Body = io.NopCloser(bytes.NewBuffer(rawBody))
	
	if err := c.BindJSON(&event); err != nil {
		log.Printf("ERROR: Failed to parse webhook payload: %v", err)
		c.JSON(400, gin.H{"error": "Invalid request body"})
		return
	}
	
	log.Printf("Parsed Zoom event type: %s", event.Event)
	log.Printf("Full event payload: %+v", event.Payload)

	// Create event mapper
	mapper := NewEventMapper("https://zoom.us")
	
	// Map Zoom event to Caliper event
	var caliperEvent *types.CaliperEvent
	var err error

	switch event.Event {
	case "meeting.started":
		var meetingEvent types.MeetingEvent
		payloadBytes, err := json.Marshal(event.Payload)
		if err != nil {
			log.Printf("ERROR: Failed to marshal payload: %v", err)
			c.JSON(400, gin.H{"error": "Invalid meeting event payload"})
			return
		}
		
		log.Printf("Meeting payload JSON: %s", string(payloadBytes))
		
		if err := json.Unmarshal(payloadBytes, &meetingEvent); err != nil {
			log.Printf("ERROR: Failed to unmarshal to MeetingEvent: %v", err)
			c.JSON(400, gin.H{"error": "Invalid meeting event payload"})
			return
		}
		
		// Log the parsed meeting event for debugging
		meetingJSON, _ := json.MarshalIndent(meetingEvent, "", "  ")
		log.Printf("Parsed MeetingEvent structure: \n%s", string(meetingJSON))
		
		log.Printf("Meeting details - ID: %s, Topic: %s", 
			meetingEvent.Object.ID, meetingEvent.Object.Topic)
		log.Printf("Host details - ID: %s, HostID: %s, Email: %s", 
			meetingEvent.Object.Host.ID, meetingEvent.Object.HostID, meetingEvent.Object.Host.Email)
		
		caliperEvent, err = mapper.MapMeetingStartedToCaliper(meetingEvent)
		
	case "meeting.ended":
		var meetingEvent types.MeetingEvent
		payloadBytes, err := json.Marshal(event.Payload)
		if err != nil {
			log.Printf("ERROR: Failed to marshal payload: %v", err)
			c.JSON(400, gin.H{"error": "Invalid meeting event payload"})
			return
		}
		
		log.Printf("Meeting payload JSON: %s", string(payloadBytes))
		
		if err := json.Unmarshal(payloadBytes, &meetingEvent); err != nil {
			log.Printf("ERROR: Failed to unmarshal to MeetingEvent: %v", err)
			c.JSON(400, gin.H{"error": "Invalid meeting event payload"})
			return
		}
		
		// Log the parsed meeting event for debugging
		meetingJSON, _ := json.MarshalIndent(meetingEvent, "", "  ")
		log.Printf("Parsed MeetingEvent structure: \n%s", string(meetingJSON))
		
		log.Printf("Meeting details - ID: %s, Topic: %s", 
			meetingEvent.Object.ID, meetingEvent.Object.Topic)
		log.Printf("Host details - ID: %s, HostID: %s, Email: %s", 
			meetingEvent.Object.Host.ID, meetingEvent.Object.HostID, meetingEvent.Object.Host.Email)
		
		caliperEvent, err = mapper.MapMeetingEndedToCaliper(meetingEvent)
		
	case "meeting.participant_joined":
		var meetingEvent types.MeetingEvent
		payloadBytes, err := json.Marshal(event.Payload)
		if err != nil {
			log.Printf("ERROR: Failed to marshal payload: %v", err)
			c.JSON(400, gin.H{"error": "Invalid participant joined event payload"})
			return
		}
		
		log.Printf("Participant joined payload JSON: %s", string(payloadBytes))
		
		if err := json.Unmarshal(payloadBytes, &meetingEvent); err != nil {
			log.Printf("ERROR: Failed to unmarshal to MeetingEvent: %v", err)
			log.Printf("Using lower level access to handle participant joined event")
			
			// Try to manually extract the participant data
			object, ok := event.Payload["object"].(map[string]interface{})
			if !ok {
				log.Printf("ERROR: Could not extract object from payload")
				c.JSON(400, gin.H{"error": "Invalid participant joined event payload: missing object"})
				return
			}
			
			meetingID := fmt.Sprintf("%v", object["id"])
			meetingTopic := fmt.Sprintf("%v", object["topic"])
			
			participant, ok := object["participant"].(map[string]interface{})
			if !ok {
				log.Printf("ERROR: Could not extract participant from object")
				c.JSON(400, gin.H{"error": "Invalid participant joined event payload: missing participant"})
				return
			}
			
			// Create a manual Caliper event
			userName := fmt.Sprintf("%v", participant["user_name"])
			userID := fmt.Sprintf("%v", participant["participant_user_id"])
			if userID == "<nil>" || userID == "" {
				userID = fmt.Sprintf("%v", participant["user_id"])
			}
			
			if userID == "<nil>" || userID == "" {
				userID = fmt.Sprintf("%v", participant["id"])
			}
			
			caliperEvent = &types.CaliperEvent{
				Context:   "http://purl.imsglobal.org/ctx/caliper/v1p1",
				ID:        fmt.Sprintf("urn:uuid:%s", NewUUID()),
				Type:      "SessionEvent",
				Action:    "LoggedIn",
				EventTime: time.Now().UTC().Format(time.RFC3339),
				Actor: map[string]interface{}{
					"id":   fmt.Sprintf("https://zoom.us/users/%s", userID),
					"type": "Person", 
					"name": userName,
				},
				Object: map[string]interface{}{
					"id":   fmt.Sprintf("https://zoom.us/meeting/%s", meetingID),
					"type": "Session",
					"name": meetingTopic,
				},
				Source: map[string]interface{}{
					"id": "https://zoom.us",
				},
			}
			
			// Add email if available
			email, ok := participant["email"].(string)
			if ok && email != "" {
				caliperEvent.Actor["email"] = email
			}
			
			err = nil
			return
		}
		
		// Log the parsed participant event for debugging
		meetingJSON, _ := json.MarshalIndent(meetingEvent, "", "  ")
		log.Printf("Parsed Participant Joined structure: \n%s", string(meetingJSON))
		
		log.Printf("Meeting details - ID: %s, Topic: %s", 
			meetingEvent.Object.ID, meetingEvent.Object.Topic)
			
		if meetingEvent.Object.Participant != nil {
			log.Printf("Participant details - ID: %s, Name: %s, Email: %s", 
				meetingEvent.Object.Participant.UserID, 
				meetingEvent.Object.Participant.UserName, 
				meetingEvent.Object.Participant.Email)
		}
		
		caliperEvent, err = mapper.MapParticipantJoinedToCaliper(meetingEvent)
		
	case "meeting.participant_left":
		var meetingEvent types.MeetingEvent
		payloadBytes, err := json.Marshal(event.Payload)
		if err != nil {
			log.Printf("ERROR: Failed to marshal payload: %v", err)
			c.JSON(400, gin.H{"error": "Invalid participant left event payload"})
			return
		}
		
		log.Printf("Participant left payload JSON: %s", string(payloadBytes))
		
		if err := json.Unmarshal(payloadBytes, &meetingEvent); err != nil {
			log.Printf("ERROR: Failed to unmarshal to MeetingEvent: %v", err)
			log.Printf("Using lower level access to handle participant left event")
			
			// Try to manually extract the participant data
			object, ok := event.Payload["object"].(map[string]interface{})
			if !ok {
				log.Printf("ERROR: Could not extract object from payload")
				c.JSON(400, gin.H{"error": "Invalid participant left event payload: missing object"})
				return
			}
			
			meetingID := fmt.Sprintf("%v", object["id"])
			meetingTopic := fmt.Sprintf("%v", object["topic"])
			
			participant, ok := object["participant"].(map[string]interface{})
			if !ok {
				log.Printf("ERROR: Could not extract participant from object")
				c.JSON(400, gin.H{"error": "Invalid participant left event payload: missing participant"})
				return
			}
			
			// Create a manual Caliper event
			userName := fmt.Sprintf("%v", participant["user_name"])
			userID := fmt.Sprintf("%v", participant["participant_user_id"])
			if userID == "<nil>" || userID == "" {
				userID = fmt.Sprintf("%v", participant["user_id"])
			}
			
			if userID == "<nil>" || userID == "" {
				userID = fmt.Sprintf("%v", participant["id"])
			}
			
			caliperEvent = &types.CaliperEvent{
				Context:   "http://purl.imsglobal.org/ctx/caliper/v1p1",
				ID:        fmt.Sprintf("urn:uuid:%s", NewUUID()),
				Type:      "SessionEvent",
				Action:    "LoggedOut",
				EventTime: time.Now().UTC().Format(time.RFC3339),
				Actor: map[string]interface{}{
					"id":   fmt.Sprintf("https://zoom.us/users/%s", userID),
					"type": "Person", 
					"name": userName,
				},
				Object: map[string]interface{}{
					"id":   fmt.Sprintf("https://zoom.us/meeting/%s", meetingID),
					"type": "Session",
					"name": meetingTopic,
				},
				Source: map[string]interface{}{
					"id": "https://zoom.us",
				},
			}
			
			// Add email if available
			email, ok := participant["email"].(string)
			if ok && email != "" {
				caliperEvent.Actor["email"] = email
			}
			
			err = nil
			return
		}
		
		// Log the parsed participant event for debugging
		meetingJSON, _ := json.MarshalIndent(meetingEvent, "", "  ")
		log.Printf("Parsed Participant Left structure: \n%s", string(meetingJSON))
		
		log.Printf("Meeting details - ID: %s, Topic: %s", 
			meetingEvent.Object.ID, meetingEvent.Object.Topic)
			
		if meetingEvent.Object.Participant != nil {
			log.Printf("Participant details - ID: %s, Name: %s, Email: %s", 
				meetingEvent.Object.Participant.UserID, 
				meetingEvent.Object.Participant.UserName, 
				meetingEvent.Object.Participant.Email)
		}
		
		caliperEvent, err = mapper.MapParticipantLeftToCaliper(meetingEvent)
		
	default:
		c.JSON(400, gin.H{"error": fmt.Sprintf("Unsupported event type: %s", event.Event)})
		return
	}

	if err != nil {
		log.Printf("ERROR: Failed to map event: %v", err)
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Store the event in the event store
	if err := eventStore.StoreEvent(caliperEvent); err != nil {
		log.Printf("ERROR: Failed to store event: %v", err)
		// Continue processing even if storage fails
	}

	// Log the final Caliper event before sending
	eventJSON, _ := json.MarshalIndent(caliperEvent, "", "  ")
	log.Printf("Final Caliper event: \n%s", string(eventJSON))

	// Send event to client
	if err := client.SendEvent(caliperEvent); err != nil {
		log.Printf("ERROR: Failed to send event: %v", err)
		c.JSON(500, gin.H{"error": "Failed to send event"})
		return
	}

	c.JSON(200, gin.H{"status": "ok"})
}

// NewUUID generates a new UUID string without external dependencies
func NewUUID() string {
	// This is a simplified version
	now := time.Now().UnixNano()
	return fmt.Sprintf("%x-%x-%x-%x-%x", 
		now&0xffffffff, 
		(now>>32)&0xffff, 
		(now>>48)&0xffff, 
		time.Now().UnixNano()&0xffff, 
		time.Now().Unix())
}

// GetUserDetails gets all available user information including LTI ID
func GetUserDetails(client *Client, userID string, email string) UserWithLTI {
	log.Printf("Getting detailed user information for user ID: %s", userID)
	
	result := UserWithLTI{
		ID:    userID,
		Email: email,
	}
	
	// Try to get user details from Zoom API
	user, err := client.GetUser(userID)
	if err != nil {
		log.Printf("WARNING: Failed to get user details, using minimal info: %v", err)
		return result
	}
	
	result.FirstName = user.FirstName
	result.LastName = user.LastName
	result.FullName = fmt.Sprintf("%s %s", user.FirstName, user.LastName)
	
	// Extract LTI ID from custom attributes if available
	for _, attr := range user.CustomAttributes {
		if attr.Name == "lti_id" {
			log.Printf("Found LTI ID for user %s: %s", userID, attr.Value)
			result.LTIID = attr.Value
			break
		}
	}
	
	if result.LTIID == "" {
		log.Printf("No LTI ID found for user %s", userID)
	}
	
	return result
}

// GetUserName attempts to get a user's full name, falling back to email if needed
func GetUserName(tokenStore TokenStore, userID string, email string) string {
	log.Printf("Getting user name for user ID: %s", userID)
	
	client := NewClient(tokenStore)
	user, err := client.GetUser(userID)
	if err != nil {
		log.Printf("WARNING: Failed to get user details, using email as fallback: %v", err)
		return email
	}
	
	if user.FirstName != "" || user.LastName != "" {
		fullName := fmt.Sprintf("%s %s", user.FirstName, user.LastName)
		log.Printf("Using full name for user %s: %s", userID, fullName)
		return fullName
	}
	
	log.Printf("User name not found in API response, using email as fallback for user %s", userID)
	return email
} 