package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DavidCarliez/cover/internal/activity"
)

func TestWriteContentEventShowsCaughtAndOutboundBody(t *testing.T) {
	event := activity.ContentEvent{
		Time: time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC), Transformed: 1,
		Caught: []activity.ContentCapture{{
			Rule: "customer", Category: "customer", Action: "pseudonymize",
			Original: "nike", Replacement: "alias-123",
		}},
		Sent: json.RawMessage(`{"input":"alias-123"}`),
	}
	var out bytes.Buffer
	if err := writeContentEvent(&out, event, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"nike"`, `"alias-123"`, "Sent to LLM", `"input": "alias-123"`} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output omitted %q:\n%s", want, out.String())
		}
	}
}

func TestWriteContentEventExplainsLocalBlock(t *testing.T) {
	event := activity.ContentEvent{Blocked: true, Transformed: 1}
	var out bytes.Buffer
	if err := writeContentEvent(&out, event, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "nothing (blocked locally)") {
		t.Fatalf("blocked output was ambiguous:\n%s", out.String())
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
