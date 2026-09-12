package activity

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestFailureAdviceInTextAndJSON(t *testing.T) {
	for _, code := range []string{"request_too_large", "response_too_large", "sse_event_too_large", "policy_blocked", "upstream_idle_timeout", "upstream_timeout", "upstream_connection_failed", "unsupported_compression", "unsafe_request", "stream_interrupted", "client_cancelled"} {
		var b bytes.Buffer
		if err := writeEvent(&b, Event{Status: 502, Error: code}, true); err != nil {
			t.Fatal(err)
		}
		var event Event
		if err := json.Unmarshal(b.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		if event.Error != code || event.Explanation == "" || event.NextStep == "" {
			t.Fatal(code)
		}
		b.Reset()
		writeEvent(&b, event, false)
		if !strings.Contains(b.String(), event.NextStep) {
			t.Fatal("advice missing")
		}
	}
}
