package zoom

import (
	"fmt"
	"log"
	"time"
	
	"github.com/google/uuid"
	"github.com/corey/zoom-caliper/internal/types"
)

// EventMapper maps Zoom events to Caliper events
type EventMapper struct {
	sourceID string
}

// NewEventMapper creates a new mapper for Zoom to Caliper events
func NewEventMapper(sourceID string) *EventMapper {
	return &EventMapper{
		sourceID: sourceID,
	}
}

// MapToCaliperEvent maps a Zoom event to a Caliper event
func (m *EventMapper) MapToCaliperEvent(event types.MeetingEvent) (*types.CaliperEvent, error) {
	// Generate event ID
	eventID := fmt.Sprintf("urn:uuid:%s", uuid.New().String())
	
	// Common event data
	caliperEvent := &types.CaliperEvent{
		Context:   "http://purl.imsglobal.org/ctx/caliper/v1p1",
		ID:        eventID,
		Type:      "SessionEvent",
		EventTime: time.Now().UTC().Format(time.RFC3339),
		Object: map[string]interface{}{
			"id":   fmt.Sprintf("https://zoom.us/meeting/%s", event.Object.ID),
			"type": "Session",
			"name": event.Object.Topic,
		},
		Source: map[string]interface{}{
			"id": m.sourceID,
		},
	}
	
	return caliperEvent, nil
}

// MapMeetingStartedToCaliper maps a meeting.started event
func (m *EventMapper) MapMeetingStartedToCaliper(event types.MeetingEvent) (*types.CaliperEvent, error) {
	caliperEvent, err := m.MapToCaliperEvent(event)
	if err != nil {
		return nil, err
	}
	
	caliperEvent.Action = "Started"
	caliperEvent.Object["startedAtTime"] = event.Object.StartTime
	
	// Set host as actor
	hostID := event.Object.HostID
	if hostID == "" && event.Object.Host.ID != "" {
		hostID = event.Object.Host.ID
	}
	
	caliperEvent.Actor = map[string]interface{}{
		"id":   fmt.Sprintf("https://zoom.us/users/%s", hostID),
		"type": "Person",
		"name": fmt.Sprintf("Host ID: %s", hostID),
	}
	
	return caliperEvent, nil
}

// MapMeetingEndedToCaliper maps a meeting.ended event
func (m *EventMapper) MapMeetingEndedToCaliper(event types.MeetingEvent) (*types.CaliperEvent, error) {
	caliperEvent, err := m.MapToCaliperEvent(event)
	if err != nil {
		return nil, err
	}
	
	caliperEvent.Action = "Ended"
	caliperEvent.Object["endedAtTime"] = time.Now().UTC().Format(time.RFC3339)
	
	// Set host as actor
	hostID := event.Object.HostID
	if hostID == "" && event.Object.Host.ID != "" {
		hostID = event.Object.Host.ID
	}
	
	caliperEvent.Actor = map[string]interface{}{
		"id":   fmt.Sprintf("https://zoom.us/users/%s", hostID),
		"type": "Person",
		"name": fmt.Sprintf("Host ID: %s", hostID),
	}
	
	return caliperEvent, nil
}

// MapParticipantJoinedToCaliper maps a meeting.participant_joined event
func (m *EventMapper) MapParticipantJoinedToCaliper(event types.MeetingEvent) (*types.CaliperEvent, error) {
	// Check if there's participant data
	if event.Object.Participant == nil {
		return nil, fmt.Errorf("missing participant data in participant_joined event")
	}
	
	caliperEvent, err := m.MapToCaliperEvent(event)
	if err != nil {
		return nil, err
	}
	
	caliperEvent.Action = "LoggedIn"
	
	// Get participant details
	participant := event.Object.Participant
	
	// Build user ID - use the Zoom user ID if provided, or fall back to email or username
	userID := participant.ParticipantUserID
	if userID == "" {
		userID = participant.UserID
	}
	if userID == "" {
		userID = participant.ID
	}
	
	log.Printf("Setting participant ID to: %s", userID)
	
	caliperEvent.Actor = map[string]interface{}{
		"id":   fmt.Sprintf("https://zoom.us/users/%s", userID),
		"type": "Person",
		"name": participant.UserName,
	}
	
	// Add email if available
	if participant.Email != "" {
		caliperEvent.Actor["email"] = participant.Email
	}
	
	return caliperEvent, nil
}

// MapParticipantLeftToCaliper maps a meeting.participant_left event
func (m *EventMapper) MapParticipantLeftToCaliper(event types.MeetingEvent) (*types.CaliperEvent, error) {
	// Check if there's participant data
	if event.Object.Participant == nil {
		return nil, fmt.Errorf("missing participant data in participant_left event")
	}
	
	caliperEvent, err := m.MapToCaliperEvent(event)
	if err != nil {
		return nil, err
	}
	
	caliperEvent.Action = "LoggedOut"
	
	// Get participant details
	participant := event.Object.Participant
	
	// Build user ID - use the Zoom user ID if provided, or fall back to email or username
	userID := participant.ParticipantUserID
	if userID == "" {
		userID = participant.UserID
	}
	if userID == "" {
		userID = participant.ID
	}
	
	log.Printf("Setting participant ID to: %s", userID)
	
	caliperEvent.Actor = map[string]interface{}{
		"id":   fmt.Sprintf("https://zoom.us/users/%s", userID),
		"type": "Person",
		"name": participant.UserName,
	}
	
	// Add email if available
	if participant.Email != "" {
		caliperEvent.Actor["email"] = participant.Email
	}
	
	return caliperEvent, nil
} 