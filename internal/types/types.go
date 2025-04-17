package types

// ZoomEvent represents a generic Zoom webhook event
type ZoomEvent struct {
	Event      string                 `json:"event"`
	Payload    map[string]interface{} `json:"payload"`
	EventTS    int64                  `json:"event_ts"`
	AccountID  string                 `json:"account_id"`
}

// HostInfo represents information about a meeting host
type HostInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// ParticipantInfo represents information about a meeting participant
type ParticipantInfo struct {
	ID                string `json:"id"`
	UserID            string `json:"user_id"`
	ParticipantUserID string `json:"participant_user_id"`
	UserName          string `json:"user_name"`
	Email             string `json:"email"`
	JoinTime          string `json:"join_time,omitempty"`
	LeaveTime         string `json:"leave_time,omitempty"`
	LeaveReason       string `json:"leave_reason,omitempty"`
	ParticipantUUID   string `json:"participant_uuid,omitempty"`
	PrivateIP         string `json:"private_ip,omitempty"`
	PublicIP          string `json:"public_ip,omitempty"`
	RegistrantID      string `json:"registrant_id,omitempty"`
}

// MeetingObject represents the object field in a Zoom meeting event
type MeetingObject struct {
	ID          string           `json:"id"`
	UUID        string           `json:"uuid"`
	Topic       string           `json:"topic"`
	Type        int              `json:"type"`
	StartTime   string           `json:"start_time"`
	Duration    int              `json:"duration"`
	Timezone    string           `json:"timezone"`
	HostID      string           `json:"host_id"`
	Host        HostInfo         `json:"host,omitempty"`
	Participant *ParticipantInfo  `json:"participant,omitempty"`
	Participants []ParticipantInfo `json:"participants,omitempty"`
}

// MeetingEvent represents a Zoom meeting event
type MeetingEvent struct {
	AccountID string        `json:"account_id"`
	Object    MeetingObject `json:"object"`
} 