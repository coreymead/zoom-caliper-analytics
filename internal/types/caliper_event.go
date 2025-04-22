package types

// CaliperEnvelope represents the Caliper envelope structure
type CaliperEnvelope struct {
	SensorID    string         `json:"sensor"`
	SendTime    string         `json:"sendTime"`
	DataVersion string         `json:"dataVersion"`
	Data        []*CaliperEvent `json:"data"`
}

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
	// SendEvent sends a single event wrapped in a Caliper envelope
	SendEvent(event *CaliperEvent) error
	
	// SendEvents sends multiple events in a single Caliper envelope
	SendEvents(events []*CaliperEvent) error
}

// EventStore defines the interface for storing and retrieving Caliper events
type EventStore interface {
	// StoreEvent stores a new Caliper event
	StoreEvent(event *CaliperEvent) error
	
	// GetEvents retrieves all stored events
	GetEvents() []*CaliperEvent
	
	// ClearEvents removes all stored events
	ClearEvents() error
}

// MemoryEventStore implements EventStore with in-memory storage
type MemoryEventStore struct {
	events []*CaliperEvent
}

// NewMemoryEventStore creates a new in-memory event store
func NewMemoryEventStore() *MemoryEventStore {
	return &MemoryEventStore{
		events: make([]*CaliperEvent, 0),
	}
}

// StoreEvent adds a new event to the store
func (s *MemoryEventStore) StoreEvent(event *CaliperEvent) error {
	s.events = append(s.events, event)
	return nil
}

// GetEvents returns all stored events
func (s *MemoryEventStore) GetEvents() []*CaliperEvent {
	return s.events
}

// ClearEvents removes all stored events
func (s *MemoryEventStore) ClearEvents() error {
	s.events = make([]*CaliperEvent, 0)
	return nil
} 