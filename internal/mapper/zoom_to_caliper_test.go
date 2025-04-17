package mapper

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/corey/zoom-caliper/internal/zoom"
	"github.com/stretchr/testify/assert"
)

func TestMapZoomMeetingStartedEvent(t *testing.T) {
	// Create a sample Zoom meeting.started webhook event
	zoomEvent := &zoom.WebhookEvent{
		Event: "meeting.started",
		Payload: map[string]interface{}{
			"account_id": "abc123",
			"object": map[string]interface{}{
				"id":         "987654321",
				"uuid":       "abcdef123456",
				"host_id":    "host123",
				"topic":      "Math 101",
				"type":       2,
				"start_time": "2023-05-15T10:00:00Z",
				"timezone":   "America/New_York",
				"duration":   60,
				"join_url":   "https://zoom.us/j/987654321",
			},
		},
	}

	// Map the Zoom event to a Caliper event
	caliperEvent, err := MapZoomToCaliperEvent(zoomEvent)
	
	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, caliperEvent)
	
	// Check event type and action
	assert.Equal(t, "SessionEvent", caliperEvent.Type)
	assert.Equal(t, "Started", caliperEvent.Action)
	
	// Check session details
	assert.Equal(t, "Session", caliperEvent.Object.Type)
	assert.Equal(t, "https://zoom.us/meeting/987654321", caliperEvent.Object.ID)
	assert.Equal(t, "Math 101", caliperEvent.Object.Name)
	
	// Check actor details
	assert.Equal(t, "Person", caliperEvent.Actor.Type)
	assert.Equal(t, "https://zoom.us/user/host123", caliperEvent.Actor.ID)
}

func TestMapZoomMeetingEndedEvent(t *testing.T) {
	// Create a sample Zoom meeting.ended webhook event
	zoomEvent := &zoom.WebhookEvent{
		Event: "meeting.ended",
		Payload: map[string]interface{}{
			"account_id": "abc123",
			"object": map[string]interface{}{
				"id":       "987654321",
				"uuid":     "abcdef123456",
				"host_id":  "host123",
				"topic":    "Math 101",
				"type":     2,
				"end_time": "2023-05-15T11:00:00Z",
				"timezone": "America/New_York",
				"duration": 60,
			},
		},
	}

	// Map the Zoom event to a Caliper event
	caliperEvent, err := MapZoomToCaliperEvent(zoomEvent)
	
	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, caliperEvent)
	
	// Check event type and action
	assert.Equal(t, "SessionEvent", caliperEvent.Type)
	assert.Equal(t, "Ended", caliperEvent.Action)
	
	// Check session details
	assert.Equal(t, "Session", caliperEvent.Object.Type)
	assert.Equal(t, "https://zoom.us/meeting/987654321", caliperEvent.Object.ID)
	assert.Equal(t, "Math 101", caliperEvent.Object.Name)
	
	// Check actor details
	assert.Equal(t, "Person", caliperEvent.Actor.Type)
	assert.Equal(t, "https://zoom.us/user/host123", caliperEvent.Actor.ID)
	
	// Check that end time is properly set
	endTime, err := time.Parse(time.RFC3339, caliperEvent.EndedAtTime)
	assert.NoError(t, err)
	expectedEndTime, _ := time.Parse(time.RFC3339, "2023-05-15T11:00:00Z")
	assert.Equal(t, expectedEndTime, endTime)
}

func TestMapZoomParticipantJoinedEvent(t *testing.T) {
	// Create a sample Zoom participant.joined webhook event
	zoomEvent := &zoom.WebhookEvent{
		Event: "meeting.participant_joined",
		Payload: map[string]interface{}{
			"account_id": "abc123",
			"object": map[string]interface{}{
				"id":       "987654321",
				"uuid":     "abcdef123456",
				"host_id":  "host123",
				"topic":    "Math 101",
				"type":     2,
				"timezone": "America/New_York",
				"participant": map[string]interface{}{
					"id":       "part123",
					"user_id":  "user123",
					"name":     "John Doe",
					"user_email": "john@example.com",
					"join_time": "2023-05-15T10:05:00Z",
				},
			},
		},
	}

	// Map the Zoom event to a Caliper event
	caliperEvent, err := MapZoomToCaliperEvent(zoomEvent)
	
	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, caliperEvent)
	
	// Check event type and action
	assert.Equal(t, "SessionEvent", caliperEvent.Type)
	assert.Equal(t, "LoggedIn", caliperEvent.Action)
	
	// Check session details
	assert.Equal(t, "Session", caliperEvent.Object.Type)
	assert.Equal(t, "https://zoom.us/meeting/987654321", caliperEvent.Object.ID)
	assert.Equal(t, "Math 101", caliperEvent.Object.Name)
	
	// Check actor details
	assert.Equal(t, "Person", caliperEvent.Actor.Type)
	assert.Equal(t, "https://zoom.us/user/user123", caliperEvent.Actor.ID)
	assert.Equal(t, "John Doe", caliperEvent.Actor.Name)
}

func TestMapZoomParticipantLeftEvent(t *testing.T) {
	// Create a sample Zoom participant.left webhook event
	zoomEvent := &zoom.WebhookEvent{
		Event: "meeting.participant_left",
		Payload: map[string]interface{}{
			"account_id": "abc123",
			"object": map[string]interface{}{
				"id":       "987654321",
				"uuid":     "abcdef123456",
				"host_id":  "host123",
				"topic":    "Math 101",
				"type":     2,
				"timezone": "America/New_York",
				"participant": map[string]interface{}{
					"id":         "part123",
					"user_id":    "user123",
					"name":       "John Doe",
					"user_email": "john@example.com",
					"leave_time": "2023-05-15T10:55:00Z",
				},
			},
		},
	}

	// Map the Zoom event to a Caliper event
	caliperEvent, err := MapZoomToCaliperEvent(zoomEvent)
	
	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, caliperEvent)
	
	// Check event type and action
	assert.Equal(t, "SessionEvent", caliperEvent.Type)
	assert.Equal(t, "LoggedOut", caliperEvent.Action)
	
	// Check session details
	assert.Equal(t, "Session", caliperEvent.Object.Type)
	assert.Equal(t, "https://zoom.us/meeting/987654321", caliperEvent.Object.ID)
	assert.Equal(t, "Math 101", caliperEvent.Object.Name)
	
	// Check actor details
	assert.Equal(t, "Person", caliperEvent.Actor.Type)
	assert.Equal(t, "https://zoom.us/user/user123", caliperEvent.Actor.ID)
	assert.Equal(t, "John Doe", caliperEvent.Actor.Name)
}

func TestMapZoomRecordingCompletedEvent(t *testing.T) {
	// Create a sample Zoom recording.completed webhook event
	zoomEvent := &zoom.WebhookEvent{
		Event: "recording.completed",
		Payload: map[string]interface{}{
			"account_id": "abc123",
			"object": map[string]interface{}{
				"id":       "987654321",
				"uuid":     "abcdef123456",
				"host_id":  "host123",
				"topic":    "Math 101",
				"type":     2,
				"timezone": "America/New_York",
				"recording_files": []interface{}{
					map[string]interface{}{
						"id":            "rec123",
						"meeting_id":    "987654321",
						"recording_type": "shared_screen_with_speaker_view",
						"file_type":     "MP4",
						"file_size":     10000,
						"download_url":  "https://zoom.us/rec/123",
					},
				},
			},
		},
	}

	// Map the Zoom event to a Caliper event
	caliperEvent, err := MapZoomToCaliperEvent(zoomEvent)
	
	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, caliperEvent)
	
	// Check event type and action
	assert.Equal(t, "ResourceEvent", caliperEvent.Type)
	assert.Equal(t, "Created", caliperEvent.Action)
	
	// Check resource details
	assert.Equal(t, "MediaObject", caliperEvent.Object.Type)
	assert.Equal(t, "https://zoom.us/rec/123", caliperEvent.Object.ID)
	assert.Equal(t, "Math 101 Recording", caliperEvent.Object.Name)
	
	// Check actor details
	assert.Equal(t, "Person", caliperEvent.Actor.Type)
	assert.Equal(t, "https://zoom.us/user/host123", caliperEvent.Actor.ID)
}

func TestMapUnsupportedEvent(t *testing.T) {
	// Create an unsupported Zoom event
	zoomEvent := &zoom.WebhookEvent{
		Event: "unsupported.event",
		Payload: map[string]interface{}{
			"account_id": "abc123",
		},
	}

	// Map the Zoom event to a Caliper event
	caliperEvent, err := MapZoomToCaliperEvent(zoomEvent)
	
	// Assertions
	assert.Error(t, err)
	assert.Nil(t, caliperEvent)
	assert.Contains(t, err.Error(), "unsupported event type")
}

func TestExtractLTIID(t *testing.T) {
	tests := []struct {
		name        string
		meetingTopic string
		expected    string
		shouldFind  bool
	}{
		{
			name:        "LTI ID in topic",
			meetingTopic: "Math 101 [LTI:12345]",
			expected:    "12345",
			shouldFind:  true,
		},
		{
			name:        "LTI ID with different format",
			meetingTopic: "Math 101 [LTI: 67890]",
			expected:    "67890",
			shouldFind:  true,
		},
		{
			name:        "No LTI ID in topic",
			meetingTopic: "Math 101 Regular Meeting",
			expected:    "",
			shouldFind:  false,
		},
		{
			name:        "Empty topic",
			meetingTopic: "",
			expected:    "",
			shouldFind:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ltiID, found := ExtractLTIID(tt.meetingTopic)
			assert.Equal(t, tt.shouldFind, found)
			if tt.shouldFind {
				assert.Equal(t, tt.expected, ltiID)
			}
		})
	}
}

func TestBuildCaliperEvent(t *testing.T) {
	// Test building a Caliper event with minimal data
	eventData := &CaliperEventData{
		EventType:   "SessionEvent",
		Action:      "Started",
		ActorID:     "user123",
		ActorType:   "Person",
		ActorName:   "John Doe",
		ObjectID:    "meeting456",
		ObjectType:  "Session",
		ObjectName:  "Test Meeting",
		EventTime:   "2023-05-15T10:00:00Z",
		EdAppID:     "zoom",
		LTIContextID: "course789",
	}

	caliperEvent := BuildCaliperEvent(eventData)
	assert.NotNil(t, caliperEvent)
	assert.Equal(t, "SessionEvent", caliperEvent.Type)
	assert.Equal(t, "Started", caliperEvent.Action)
	assert.Equal(t, "Person", caliperEvent.Actor.Type)
	assert.Equal(t, "user123", caliperEvent.Actor.ID)
	assert.Equal(t, "John Doe", caliperEvent.Actor.Name)
	assert.Equal(t, "Session", caliperEvent.Object.Type)
	assert.Equal(t, "meeting456", caliperEvent.Object.ID)
	assert.Equal(t, "Test Meeting", caliperEvent.Object.Name)
	assert.Equal(t, "2023-05-15T10:00:00Z", caliperEvent.EventTime)
	assert.Equal(t, "zoom", caliperEvent.EdApp.ID)
	assert.Equal(t, "course789", caliperEvent.Group.ID)

	// Verify JSON serialization
	jsonData, err := json.Marshal(caliperEvent)
	assert.NoError(t, err)
	assert.Contains(t, string(jsonData), `"type":"SessionEvent"`)
	assert.Contains(t, string(jsonData), `"action":"Started"`)
} 