# Zoom to Caliper Event Mapping

This document outlines how Zoom webhook events are mapped to Caliper events in the Zoom Caliper integration.

## Event Mappings

| Zoom Event | Caliper Event Type | Description |
|------------|-------------------|-------------|
| `meeting.started` | `SessionEvent` - `LoggedIn` | Triggered when a meeting starts |
| `meeting.ended` | `SessionEvent` - `LoggedOut` | Triggered when a meeting ends |
| `webinar.started` | `SessionEvent` - `LoggedIn` | Triggered when a webinar starts |
| `webinar.ended` | `SessionEvent` - `LoggedOut` | Triggered when a webinar ends |
| `participant.joined` | `NavigationEvent` - `Navigated` | Triggered when a participant joins a meeting |
| `participant.left` | `NavigationEvent` - `NavigatedFrom` | Triggered when a participant leaves a meeting |
| `recording.started` | `MediaEvent` - `Started` | Triggered when recording starts |
| `recording.stopped` | `MediaEvent` - `Ended` | Triggered when recording stops |
| `recording.completed` | `MediaEvent` - `Completed` | Triggered when recording is completed and available |

## Caliper Context

All Caliper events include the following context:
- `@context`: "http://purl.imsglobal.org/ctx/caliper/v1p1"
- `type`: The specific Caliper event type
- `id`: A unique identifier for the event
- `actor`: The Zoom user who initiated the event
- `action`: The Caliper action corresponding to the Zoom event
- `object`: The Zoom meeting or webinar
- `eventTime`: The timestamp of the event
- `edApp`: The Zoom application

## Sample Event Transformations

### Meeting Started → Caliper SessionEvent

**Zoom Event**:
```json
{
  "event": "meeting.started",
  "payload": {
    "account_id": "abc123",
    "object": {
      "id": "12345678",
      "uuid": "abcd1234-abcd-1234-abcd-1234abcd1234",
      "host_id": "xyz789",
      "topic": "My Zoom Meeting",
      "type": 2,
      "start_time": "2023-06-15T10:00:00Z",
      "timezone": "America/New_York"
    }
  }
}
```

**Caliper Event**:
```json
{
  "@context": "http://purl.imsglobal.org/ctx/caliper/v1p1",
  "type": "SessionEvent",
  "id": "urn:uuid:abcd1234-abcd-1234-abcd-1234abcd1234",
  "actor": {
    "id": "urn:zoom:user:xyz789",
    "type": "Person"
  },
  "action": "LoggedIn",
  "object": {
    "id": "urn:zoom:meeting:12345678",
    "type": "Session",
    "name": "My Zoom Meeting"
  },
  "eventTime": "2023-06-15T10:00:00Z",
  "edApp": {
    "id": "urn:zoom:app",
    "type": "SoftwareApplication",
    "name": "Zoom"
  }
}
```

### Participant Joined → Caliper NavigationEvent

**Zoom Event**:
```json
{
  "event": "participant.joined",
  "payload": {
    "account_id": "abc123",
    "object": {
      "id": "12345678",
      "uuid": "abcd1234-abcd-1234-abcd-1234abcd1234",
      "participant": {
        "user_id": "user123",
        "email": "user@example.com",
        "join_time": "2023-06-15T10:05:00Z"
      }
    }
  }
}
```

**Caliper Event**:
```json
{
  "@context": "http://purl.imsglobal.org/ctx/caliper/v1p1",
  "type": "NavigationEvent",
  "id": "urn:uuid:[generated-uuid]",
  "actor": {
    "id": "urn:zoom:user:user123",
    "type": "Person",
    "email": "user@example.com"
  },
  "action": "Navigated",
  "object": {
    "id": "urn:zoom:meeting:12345678",
    "type": "DigitalResource",
    "name": "Zoom Meeting"
  },
  "eventTime": "2023-06-15T10:05:00Z",
  "edApp": {
    "id": "urn:zoom:app",
    "type": "SoftwareApplication",
    "name": "Zoom"
  }
}
```

## Extending the Mapping

To add support for additional Zoom events:

1. Identify the appropriate Caliper event type and action
2. Update the event mapping in `internal/zoom/events.go`
3. Create a transformation function in `internal/zoom/transform.go`
4. Register the event handler in `internal/zoom/webhook.go`

Refer to the [Caliper Analytics Specification](https://www.imsglobal.org/caliper/v1p1/caliper-spec-v1p1) for details on available event types and actions. 