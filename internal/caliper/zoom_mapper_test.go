package caliper

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/corey/git/zoom-caliper/internal/zoom"
)

func TestMapMeetingStartedToCaliperEvent(t *testing.T) {
	// Create a sample Zoom meeting.started event
	startTime, _ := time.Parse(time.RFC3339, "2023-01-01T12:00:00Z")
	
	zoomEvent := &zoom.Event{
		Event: "meeting.started",
		Payload: &zoom.EventPayload{
			AccountID: "account123",
			Object: &zoom.EventObject{
				ID:        "123456789",
				UUID:      "abc123",
				HostID:    "host123",
				Topic:     "Test Meeting [LTI-123]",
				Type:      2,
				StartTime: startTime.Format(time.RFC3339),
				Timezone:  "UTC",
			},
		},
		EventTs: 1624481713000,
	}

	// Create the mapper
	sourceId := "https://example.com/zoom"
	mapper := NewZoomMapper(sourceId)

	// Test mapping
	caliperEvent, err := mapper.MapToCaliperEvent(zoomEvent, "123")

	// Assertions
	require.NoError(t, err)
	assert.NotNil(t, caliperEvent)
	
	// Assert specific fields of the Caliper event
	assert.Equal(t, "SessionEvent", caliperEvent.Type)
	assert.Equal(t, "Started", caliperEvent.Action)
	assert.Equal(t, "123456789", caliperEvent.Object.ID)
	assert.Equal(t, "Session", caliperEvent.Object.Type)
	assert.Equal(t, "Test Meeting [LTI-123]", caliperEvent.Object.Name)
	assert.Equal(t, "123", caliperEvent.Object.IsPartOf.ID)
	assert.Equal(t, "CourseSection", caliperEvent.Object.IsPartOf.Type)
	assert.Equal(t, sourceId, caliperEvent.Source.ID)
	assert.NotEmpty(t, caliperEvent.ID)
	assert.NotEmpty(t, caliperEvent.EventTime)
}

func TestMapMeetingEndedToCaliperEvent(t *testing.T) {
	// Create a sample Zoom meeting.ended event
	startTime, _ := time.Parse(time.RFC3339, "2023-01-01T12:00:00Z")
	
	zoomEvent := &zoom.Event{
		Event: "meeting.ended",
		Payload: &zoom.EventPayload{
			AccountID: "account123",
			Object: &zoom.EventObject{
				ID:        "123456789",
				UUID:      "abc123",
				HostID:    "host123",
				Topic:     "Test Meeting [LTI-123]",
				Type:      2,
				StartTime: startTime.Format(time.RFC3339),
				Duration:  60,
				Timezone:  "UTC",
			},
		},
		EventTs: 1624481713000,
	}

	// Create the mapper
	sourceId := "https://example.com/zoom"
	mapper := NewZoomMapper(sourceId)

	// Test mapping
	caliperEvent, err := mapper.MapToCaliperEvent(zoomEvent, "123")

	// Assertions
	require.NoError(t, err)
	assert.NotNil(t, caliperEvent)
	
	// Assert specific fields of the Caliper event
	assert.Equal(t, "SessionEvent", caliperEvent.Type)
	assert.Equal(t, "Ended", caliperEvent.Action)
	assert.Equal(t, "123456789", caliperEvent.Object.ID)
	assert.Equal(t, "Session", caliperEvent.Object.Type)
	assert.Equal(t, "Test Meeting [LTI-123]", caliperEvent.Object.Name)
	assert.Equal(t, "123", caliperEvent.Object.IsPartOf.ID)
	assert.Equal(t, "CourseSection", caliperEvent.Object.IsPartOf.Type)
	assert.Equal(t, sourceId, caliperEvent.Source.ID)
	assert.NotEmpty(t, caliperEvent.ID)
	assert.NotEmpty(t, caliperEvent.EventTime)
}

func TestMapParticipantJoinedToCaliperEvent(t *testing.T) {
	// Create a sample Zoom participant_joined event
	joinTime, _ := time.Parse(time.RFC3339, "2023-01-01T12:05:00Z")
	
	zoomEvent := &zoom.Event{
		Event: "meeting.participant_joined",
		Payload: &zoom.EventPayload{
			AccountID: "account123",
			Object: &zoom.EventObject{
				ID:     "123456789",
				UUID:   "abc123",
				HostID: "host123",
				Topic:  "Test Meeting [LTI-123]",
				Type:   2,
				Participant: &zoom.Participant{
					UserID:   "user123",
					UserName: "John Doe",
					Email:    "john@example.com",
					JoinTime: joinTime.Format(time.RFC3339),
				},
			},
		},
		EventTs: 1624481713000,
	}

	// Create the mapper
	sourceId := "https://example.com/zoom"
	mapper := NewZoomMapper(sourceId)

	// Test mapping
	caliperEvent, err := mapper.MapToCaliperEvent(zoomEvent, "123")

	// Assertions
	require.NoError(t, err)
	assert.NotNil(t, caliperEvent)
	
	// Assert specific fields of the Caliper event
	assert.Equal(t, "SessionEvent", caliperEvent.Type)
	assert.Equal(t, "LoggedIn", caliperEvent.Action)
	assert.Equal(t, "123456789", caliperEvent.Object.ID)
	assert.Equal(t, "Session", caliperEvent.Object.Type)
	assert.Equal(t, "Test Meeting [LTI-123]", caliperEvent.Object.Name)
	assert.Equal(t, "123", caliperEvent.Object.IsPartOf.ID)
	assert.Equal(t, "CourseSection", caliperEvent.Object.IsPartOf.Type)
	assert.Equal(t, sourceId, caliperEvent.Source.ID)
	
	// Check for actor (the participant)
	assert.NotNil(t, caliperEvent.Actor)
	assert.Equal(t, "user123", caliperEvent.Actor.ID)
	assert.Equal(t, "Person", caliperEvent.Actor.Type)
	assert.Equal(t, "John Doe", caliperEvent.Actor.Name)
	
	assert.NotEmpty(t, caliperEvent.ID)
	assert.NotEmpty(t, caliperEvent.EventTime)
}

func TestMapParticipantLeftToCaliperEvent(t *testing.T) {
	// Create a sample Zoom participant_left event
	leaveTime, _ := time.Parse(time.RFC3339, "2023-01-01T13:05:00Z")
	
	zoomEvent := &zoom.Event{
		Event: "meeting.participant_left",
		Payload: &zoom.EventPayload{
			AccountID: "account123",
			Object: &zoom.EventObject{
				ID:     "123456789",
				UUID:   "abc123",
				HostID: "host123",
				Topic:  "Test Meeting [LTI-123]",
				Type:   2,
				Participant: &zoom.Participant{
					UserID:    "user123",
					UserName:  "John Doe",
					Email:     "john@example.com",
					LeaveTime: leaveTime.Format(time.RFC3339),
				},
			},
		},
		EventTs: 1624485313000,
	}

	// Create the mapper
	sourceId := "https://example.com/zoom"
	mapper := NewZoomMapper(sourceId)

	// Test mapping
	caliperEvent, err := mapper.MapToCaliperEvent(zoomEvent, "123")

	// Assertions
	require.NoError(t, err)
	assert.NotNil(t, caliperEvent)
	
	// Assert specific fields of the Caliper event
	assert.Equal(t, "SessionEvent", caliperEvent.Type)
	assert.Equal(t, "LoggedOut", caliperEvent.Action)
	assert.Equal(t, "123456789", caliperEvent.Object.ID)
	assert.Equal(t, "Session", caliperEvent.Object.Type)
	assert.Equal(t, "Test Meeting [LTI-123]", caliperEvent.Object.Name)
	assert.Equal(t, "123", caliperEvent.Object.IsPartOf.ID)
	assert.Equal(t, "CourseSection", caliperEvent.Object.IsPartOf.Type)
	assert.Equal(t, sourceId, caliperEvent.Source.ID)
	
	// Check for actor (the participant)
	assert.NotNil(t, caliperEvent.Actor)
	assert.Equal(t, "user123", caliperEvent.Actor.ID)
	assert.Equal(t, "Person", caliperEvent.Actor.Type)
	assert.Equal(t, "John Doe", caliperEvent.Actor.Name)
	
	assert.NotEmpty(t, caliperEvent.ID)
	assert.NotEmpty(t, caliperEvent.EventTime)
}

func TestMapUnsupportedEventType(t *testing.T) {
	// Create a sample unsupported Zoom event
	zoomEvent := &zoom.Event{
		Event: "meeting.unsupported_event",
		Payload: &zoom.EventPayload{
			AccountID: "account123",
			Object: &zoom.EventObject{
				ID:    "123456789",
				UUID:  "abc123",
				Topic: "Test Meeting [LTI-123]",
			},
		},
		EventTs: 1624481713000,
	}

	// Create the mapper
	sourceId := "https://example.com/zoom"
	mapper := NewZoomMapper(sourceId)

	// Test mapping
	_, err := mapper.MapToCaliperEvent(zoomEvent, "123")

	// Should return an error for unsupported event type
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported event type")
}

func TestMapWithMissingData(t *testing.T) {
	testCases := []struct {
		name      string
		zoomEvent *zoom.Event
		errorMsg  string
	}{
		{
			name: "missing event type",
			zoomEvent: &zoom.Event{
				Event: "",
				Payload: &zoom.EventPayload{
					Object: &zoom.EventObject{
						ID:    "123456789",
						Topic: "Test Meeting [LTI-123]",
					},
				},
			},
			errorMsg: "empty event type",
		},
		{
			name: "missing payload",
			zoomEvent: &zoom.Event{
				Event:   "meeting.started",
				Payload: nil,
			},
			errorMsg: "missing event payload",
		},
		{
			name: "missing object",
			zoomEvent: &zoom.Event{
				Event:   "meeting.started",
				Payload: &zoom.EventPayload{},
			},
			errorMsg: "missing event object",
		},
		{
			name: "missing meeting ID",
			zoomEvent: &zoom.Event{
				Event: "meeting.started",
				Payload: &zoom.EventPayload{
					Object: &zoom.EventObject{
						ID:    "",
						Topic: "Test Meeting [LTI-123]",
					},
				},
			},
			errorMsg: "missing meeting ID",
		},
		{
			name: "missing topic",
			zoomEvent: &zoom.Event{
				Event: "meeting.started",
				Payload: &zoom.EventPayload{
					Object: &zoom.EventObject{
						ID:    "123456789",
						Topic: "",
					},
				},
			},
			errorMsg: "missing meeting topic",
		},
	}

	sourceId := "https://example.com/zoom"
	mapper := NewZoomMapper(sourceId)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mapper.MapToCaliperEvent(tc.zoomEvent, "123")
			
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errorMsg)
		})
	}
} 