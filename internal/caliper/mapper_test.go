package caliper

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/corey/git/zoom-caliper/internal/zoom"
)

func TestMapZoomToCaliper(t *testing.T) {
	// Setup test data
	meetingID := "123456789"
	userID := "user123"
	userName := "John Doe"
	email := "john@example.com"
	ltiID := "LTI123"
	
	// Test mapping meeting.started event
	caliperEvents, err := MapZoomToCaliper("meeting.started", meetingID, userID, userName, email, ltiID)
	require.NoError(t, err)
	require.Len(t, caliperEvents, 1)
	
	event := caliperEvents[0]
	assert.Equal(t, "SessionEvent", event.Type)
	assert.Equal(t, "Started", event.Action)
	assert.NotEmpty(t, event.EventTime)
	assert.Equal(t, event.ID, "urn:uuid:"+uuid.MustParse(event.ID[9:]).String())
	
	assert.Equal(t, "Person", event.Actor.Type)
	assert.Equal(t, userID, event.Actor.ID)
	assert.Equal(t, userName, event.Actor.Name)
	
	assert.Equal(t, "Session", event.Object.Type)
	assert.Equal(t, meetingID, event.Object.ID)
	assert.Equal(t, ltiID, event.Object.LtiID)
	
	// Test mapping meeting.ended event
	caliperEvents, err = MapZoomToCaliper("meeting.ended", meetingID, userID, userName, email, ltiID)
	require.NoError(t, err)
	require.Len(t, caliperEvents, 1)
	
	event = caliperEvents[0]
	assert.Equal(t, "SessionEvent", event.Type)
	assert.Equal(t, "Ended", event.Action)
	
	// Test mapping meeting.participant_joined event
	caliperEvents, err = MapZoomToCaliper("meeting.participant_joined", meetingID, userID, userName, email, ltiID)
	require.NoError(t, err)
	require.Len(t, caliperEvents, 1)
	
	event = caliperEvents[0]
	assert.Equal(t, "SessionEvent", event.Type)
	assert.Equal(t, "LoggedIn", event.Action)
	
	// Test mapping meeting.participant_left event
	caliperEvents, err = MapZoomToCaliper("meeting.participant_left", meetingID, userID, userName, email, ltiID)
	require.NoError(t, err)
	require.Len(t, caliperEvents, 1)
	
	event = caliperEvents[0]
	assert.Equal(t, "SessionEvent", event.Type)
	assert.Equal(t, "LoggedOut", event.Action)
	
	// Test mapping unsupported event
	caliperEvents, err = MapZoomToCaliper("unsupported.event", meetingID, userID, userName, email, ltiID)
	assert.Error(t, err)
	assert.Empty(t, caliperEvents)
}

func TestExtractLTIID(t *testing.T) {
	// Test valid topic with LTI prefix
	topic := "LTI-ABC123: Test Meeting"
	ltiID, ok := ExtractLTIID(topic)
	assert.True(t, ok)
	assert.Equal(t, "ABC123", ltiID)
	
	// Test valid topic with LTI-ID prefix
	topic = "LTI-ID-DEF456: Another Meeting"
	ltiID, ok = ExtractLTIID(topic)
	assert.True(t, ok)
	assert.Equal(t, "DEF456", ltiID)
	
	// Test valid topic with LTI_ID prefix
	topic = "LTI_ID_GHI789: Third Meeting"
	ltiID, ok = ExtractLTIID(topic)
	assert.True(t, ok)
	assert.Equal(t, "GHI789", ltiID)
	
	// Test topic without LTI prefix
	topic = "Regular Meeting Without LTI"
	ltiID, ok = ExtractLTIID(topic)
	assert.False(t, ok)
	assert.Empty(t, ltiID)
	
	// Test empty topic
	ltiID, ok = ExtractLTIID("")
	assert.False(t, ok)
	assert.Empty(t, ltiID)
}

func TestCreateCaliperEvent(t *testing.T) {
	// Setup test data
	meetingID := "123456789"
	userID := "user123"
	userName := "John Doe"
	ltiID := "LTI123"
	eventType := "SessionEvent"
	action := "Started"
	
	// Create event
	event := CreateCaliperEvent(eventType, action, meetingID, userID, userName, ltiID)
	
	// Verify event fields
	assert.Equal(t, eventType, event.Type)
	assert.Equal(t, action, event.Action)
	assert.Equal(t, "Person", event.Actor.Type)
	assert.Equal(t, userID, event.Actor.ID)
	assert.Equal(t, userName, event.Actor.Name)
	assert.Equal(t, "Session", event.Object.Type)
	assert.Equal(t, meetingID, event.Object.ID)
	assert.Equal(t, ltiID, event.Object.LtiID)
	
	// Verify event ID is a valid UUID
	assert.Equal(t, event.ID, "urn:uuid:"+uuid.MustParse(event.ID[9:]).String())
	
	// Verify event time is close to now
	eventTime, err := time.Parse(time.RFC3339, event.EventTime)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), eventTime, 2*time.Second)
}

// Mock Caliper client for testing
type MockClient struct {
	Events []Event
	Errors []error
}

func (m *MockClient) PublishEvent(event Event) error {
	m.Events = append(m.Events, event)
	if len(m.Errors) > 0 {
		err := m.Errors[0]
		m.Errors = m.Errors[1:]
		return err
	}
	return nil
}

func TestPublishCaliperEvents(t *testing.T) {
	// Setup mock client
	mockClient := &MockClient{}
	client = mockClient
	
	// Create test events
	event1 := CreateCaliperEvent("SessionEvent", "Started", "123", "user1", "User One", "LTI1")
	event2 := CreateCaliperEvent("SessionEvent", "Ended", "123", "user1", "User One", "LTI1")
	events := []Event{event1, event2}
	
	// Test successful publishing
	err := PublishCaliperEvents(events)
	assert.NoError(t, err)
	assert.Len(t, mockClient.Events, 2)
	assert.Equal(t, event1, mockClient.Events[0])
	assert.Equal(t, event2, mockClient.Events[1])
	
	// Test error handling
	mockClient.Events = nil
	mockClient.Errors = append(mockClient.Errors, assert.AnError)
	err = PublishCaliperEvents(events)
	assert.Error(t, err)
}

func TestMapMeetingStarted(t *testing.T) {
	// Create a test Zoom event
	zoomEvent := zoom.WebhookEvent{
		Event:     "meeting.started",
		Timestamp: time.Now().Unix(),
		Payload: zoom.WebhookEventPayload{
			AccountID: "abc123",
			Object: zoom.WebhookEventObject{
				ID:        "123456789",
				UUID:      "abcdef123456",
				HostID:    "host123",
				Topic:     "Test Meeting [LTI_ID:course-123]",
				Type:      2,
				StartTime: time.Now().Format(time.RFC3339),
				Duration:  60,
				Timezone:  "America/Los_Angeles",
			},
		},
	}

	// Map to Caliper event
	caliperEvent, err := MapZoomToCaliperEvent(zoomEvent)
	require.NoError(t, err)
	
	// Verify event type and properties
	assert.Equal(t, "SessionEvent", caliperEvent.Type)
	assert.Equal(t, "Started", caliperEvent.Action)
	assert.Equal(t, "course-123", caliperEvent.Context.ID)
	assert.Equal(t, "123456789", caliperEvent.Object.ID)
	assert.Equal(t, "VideoConference", caliperEvent.Object.Type)
	assert.Equal(t, "Meeting", caliperEvent.Object.Name)
	assert.Equal(t, "host123", caliperEvent.Actor.ID)
}

func TestMapMeetingEnded(t *testing.T) {
	// Create a test Zoom event
	zoomEvent := zoom.WebhookEvent{
		Event:     "meeting.ended",
		Timestamp: time.Now().Unix(),
		Payload: zoom.WebhookEventPayload{
			AccountID: "abc123",
			Object: zoom.WebhookEventObject{
				ID:        "123456789",
				UUID:      "abcdef123456",
				HostID:    "host123",
				Topic:     "Test Meeting [LTI_ID:course-123]",
				Type:      2,
				StartTime: time.Now().Format(time.RFC3339),
				Duration:  60,
				Timezone:  "America/Los_Angeles",
			},
		},
	}

	// Map to Caliper event
	caliperEvent, err := MapZoomToCaliperEvent(zoomEvent)
	require.NoError(t, err)
	
	// Verify event type and properties
	assert.Equal(t, "SessionEvent", caliperEvent.Type)
	assert.Equal(t, "Ended", caliperEvent.Action)
	assert.Equal(t, "course-123", caliperEvent.Context.ID)
	assert.Equal(t, "123456789", caliperEvent.Object.ID)
	assert.Equal(t, "VideoConference", caliperEvent.Object.Type)
	assert.Equal(t, "Meeting", caliperEvent.Object.Name)
	assert.Equal(t, "host123", caliperEvent.Actor.ID)
}

func TestMapParticipantJoined(t *testing.T) {
	// Create a test Zoom event
	zoomEvent := zoom.WebhookEvent{
		Event:     "meeting.participant_joined",
		Timestamp: time.Now().Unix(),
		Payload: zoom.WebhookEventPayload{
			AccountID: "abc123",
			Object: zoom.WebhookEventObject{
				ID:        "123456789",
				UUID:      "abcdef123456",
				HostID:    "host123",
				Topic:     "Test Meeting [LTI_ID:course-123]",
				Type:      2,
				StartTime: time.Now().Format(time.RFC3339),
				Duration:  60,
				Timezone:  "America/Los_Angeles",
				Participant: zoom.WebhookEventParticipant{
					UserID:   "user123",
					UserName: "Test User",
					Email:    "test@example.com",
					JoinTime: time.Now().Format(time.RFC3339),
				},
			},
		},
	}

	// Map to Caliper event
	caliperEvent, err := MapZoomToCaliperEvent(zoomEvent)
	require.NoError(t, err)
	
	// Verify event type and properties
	assert.Equal(t, "SessionEvent", caliperEvent.Type)
	assert.Equal(t, "LoggedIn", caliperEvent.Action)
	assert.Equal(t, "course-123", caliperEvent.Context.ID)
	assert.Equal(t, "123456789", caliperEvent.Object.ID)
	assert.Equal(t, "VideoConference", caliperEvent.Object.Type)
	assert.Equal(t, "Meeting", caliperEvent.Object.Name)
	assert.Equal(t, "user123", caliperEvent.Actor.ID)
	assert.Equal(t, "Test User", caliperEvent.Actor.Name)
}

func TestMapParticipantLeft(t *testing.T) {
	// Create a test Zoom event
	zoomEvent := zoom.WebhookEvent{
		Event:     "meeting.participant_left",
		Timestamp: time.Now().Unix(),
		Payload: zoom.WebhookEventPayload{
			AccountID: "abc123",
			Object: zoom.WebhookEventObject{
				ID:        "123456789",
				UUID:      "abcdef123456",
				HostID:    "host123",
				Topic:     "Test Meeting [LTI_ID:course-123]",
				Type:      2,
				StartTime: time.Now().Format(time.RFC3339),
				Duration:  60,
				Timezone:  "America/Los_Angeles",
				Participant: zoom.WebhookEventParticipant{
					UserID:    "user123",
					UserName:  "Test User",
					Email:     "test@example.com",
					JoinTime:  time.Now().Format(time.RFC3339),
					LeaveTime: time.Now().Format(time.RFC3339),
				},
			},
		},
	}

	// Map to Caliper event
	caliperEvent, err := MapZoomToCaliperEvent(zoomEvent)
	require.NoError(t, err)
	
	// Verify event type and properties
	assert.Equal(t, "SessionEvent", caliperEvent.Type)
	assert.Equal(t, "LoggedOut", caliperEvent.Action)
	assert.Equal(t, "course-123", caliperEvent.Context.ID)
	assert.Equal(t, "123456789", caliperEvent.Object.ID)
	assert.Equal(t, "VideoConference", caliperEvent.Object.Type)
	assert.Equal(t, "Meeting", caliperEvent.Object.Name)
	assert.Equal(t, "user123", caliperEvent.Actor.ID)
	assert.Equal(t, "Test User", caliperEvent.Actor.Name)
}

func TestExtractLtiID(t *testing.T) {
	testCases := []struct {
		name     string
		topic    string
		expected string
		hasError bool
	}{
		{
			name:     "Valid LTI ID",
			topic:    "Test Meeting [LTI_ID:course-123]",
			expected: "course-123",
			hasError: false,
		},
		{
			name:     "No LTI ID",
			topic:    "Test Meeting",
			expected: "",
			hasError: true,
		},
		{
			name:     "Empty LTI ID",
			topic:    "Test Meeting [LTI_ID:]",
			expected: "",
			hasError: true,
		},
		{
			name:     "LTI ID with special chars",
			topic:    "Test Meeting [LTI_ID:course/123@example.com]",
			expected: "course/123@example.com",
			hasError: false,
		},
		{
			name:     "Multiple LTI IDs - takes first",
			topic:    "Test Meeting [LTI_ID:course-123] [LTI_ID:course-456]",
			expected: "course-123",
			hasError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := extractLtiID(tc.topic)
			if tc.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, id)
			}
		})
	}
}

func TestUnsupportedEventType(t *testing.T) {
	// Create a test Zoom event with unsupported type
	zoomEvent := zoom.WebhookEvent{
		Event:     "meeting.unsupported_event",
		Timestamp: time.Now().Unix(),
		Payload: zoom.WebhookEventPayload{
			AccountID: "abc123",
			Object: zoom.WebhookEventObject{
				ID:        "123456789",
				UUID:      "abcdef123456",
				HostID:    "host123",
				Topic:     "Test Meeting [LTI_ID:course-123]",
				Type:      2,
				StartTime: time.Now().Format(time.RFC3339),
				Duration:  60,
				Timezone:  "America/Los_Angeles",
			},
		},
	}

	// Map to Caliper event
	_, err := MapZoomToCaliperEvent(zoomEvent)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported event type")
}

func TestMissingLtiID(t *testing.T) {
	// Create a test Zoom event with no LTI ID
	zoomEvent := zoom.WebhookEvent{
		Event:     "meeting.started",
		Timestamp: time.Now().Unix(),
		Payload: zoom.WebhookEventPayload{
			AccountID: "abc123",
			Object: zoom.WebhookEventObject{
				ID:        "123456789",
				UUID:      "abcdef123456",
				HostID:    "host123",
				Topic:     "Test Meeting", // No LTI ID
				Type:      2,
				StartTime: time.Now().Format(time.RFC3339),
				Duration:  60,
				Timezone:  "America/Los_Angeles",
			},
		},
	}

	// Map to Caliper event
	_, err := MapZoomToCaliperEvent(zoomEvent)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to extract LTI ID")
} 