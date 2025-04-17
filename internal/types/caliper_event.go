package types

// CaliperEvent represents the structure of a Caliper event
type CaliperEvent struct {
	Context   string                 `json:"@context,omitempty"`
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Action    string                 `json:"action"`
	EventTime string                 `json:"eventTime"`
	Actor     map[string]interface{} `json:"actor,omitempty"`
	Object    map[string]interface{} `json:"object"`
	Source    map[string]interface{} `json:"source,omitempty"`
}

// CaliperClient defines the interface for sending Caliper events
type CaliperClient interface {
	SendEvent(event *CaliperEvent) error
} 