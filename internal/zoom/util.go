package zoom

import (
	"strings"
)

// ExtractLTIIDFromTopic extracts LTI ID from a meeting topic
func ExtractLTIIDFromTopic(topic string) string {
	if topic == "" {
		return ""
	}
	
	// Look for [LTI-123] format
	if strings.Contains(topic, "[LTI-") {
		start := strings.Index(topic, "[LTI-") + 5 // Skip "[LTI-"
		end := strings.Index(topic[start:], "]")
		if end > 0 {
			return topic[start : start+end]
		}
	}
	
	// Look for [LTI_ID:123] format
	if strings.Contains(topic, "[LTI_ID:") {
		start := strings.Index(topic, "[LTI_ID:") + 8 // Skip "[LTI_ID:"
		end := strings.Index(topic[start:], "]")
		if end > 0 {
			return topic[start : start+end]
		}
	}
	
	return ""
} 