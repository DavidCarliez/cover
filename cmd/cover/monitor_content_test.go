package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/DavidCarliez/cover/internal/activity"
)

func TestContentPairsKeepControlCharactersOnOneLine(t *testing.T) {
	event := activity.ContentEvent{
		Caught: []activity.ContentCapture{
			{Original: "line\nbreak", Replacement: "alias-123"},
			{Original: "tab\tand\rreturn", Replacement: "quoted\"value"},
		},
		Sent: json.RawMessage(`{"input":"must not appear in the text view"}`),
	}
	var out bytes.Buffer
	if err := writeContentEvent(&out, event, false); err != nil {
		t.Fatal(err)
	}
	want := "\"line\\nbreak\" -> \"alias-123\"\n\"tab\\tand\\rreturn\" -> \"quoted\\\"value\"\n"
	if out.String() != want {
		t.Fatalf("pair output = %q, want %q", out.String(), want)
	}
}

func TestContentJSONRetainsBlockedStateAndOutboundBody(t *testing.T) {
	event := activity.ContentEvent{
		Blocked: true,
		Caught: []activity.ContentCapture{{Original: "original", Replacement: "replacement"}},
		Sent: json.RawMessage(`{"input":"replacement"}`),
	}
	var out bytes.Buffer
	if err := writeContentEvent(&out, event, true); err != nil {
		t.Fatal(err)
	}
	var got activity.ContentEvent
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Blocked || len(got.Caught) != 1 || got.Caught[0] != event.Caught[0] || !bytes.Equal(got.Sent, event.Sent) {
		t.Fatalf("JSON event lost content: %+v", got)
	}
}

func TestLiveMonitorBaseURLUsesLoopback(t *testing.T) {
	tests := map[string]string{
		"127.0.0.1:8317": "http://127.0.0.1:8317",
		"[::1]:8317":     "http://[::1]:8317",
		"0.0.0.0:8317":   "http://127.0.0.1:8317",
		"[::]:8317":      "http://[::1]:8317",
	}
	for listen, want := range tests {
		got, err := liveMonitorBaseURL(listen)
		if err != nil || got != want {
			t.Fatalf("liveMonitorBaseURL(%q)=%q, %v; want %q", listen, got, err, want)
		}
	}
	if _, err := liveMonitorBaseURL("192.0.2.10:8317"); err == nil {
		t.Fatal("specific remote listener was accepted for sensitive monitoring")
	}
}
