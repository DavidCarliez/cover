package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func TestHeartbeatAndInterleavedChannelsRestore(t *testing.T) {
	r, fake := aliasPseudonym(t, "interleaved")
	split := len(fake) / 2
	stream := responseDeltaEventWithItem("response.output_text.delta", "a", fake[:split], 1) +
		": heartbeat\n\n" + responseDeltaEventWithItem("response.output_text.delta", "b", fake[:split], 2) +
		responseDeltaEventWithItem("response.output_text.delta", "a", fake[split:], 3) +
		responseDeltaEventWithItem("response.output_text.delta", "b", fake[split:], 4) + "data: [DONE]\n\n"
	out := restoreSSEForTest(t, r, "interleaved", stream)
	joined := map[string]string{}
	last := 0
	for _, payload := range sseJSONPayloads(t, out) {
		id, _ := payload["item_id"].(string)
		delta, _ := payload["delta"].(string)
		joined[id] += delta
		// The helper decodes numeric fields as float64.
		if number, ok := payload["sequence_number"].(float64); ok {
			if int(number) <= last {
				t.Fatal("event order changed")
			}
			last = int(number)
		}
	}
	if joined["a"] != "CUSTOMER-ALPHA" || joined["b"] != "CUSTOMER-ALPHA" {
		t.Fatalf("got %v", joined)
	}
	if strings.Count(out, ": heartbeat") != 1 {
		t.Fatal("heartbeat lost")
	}
}

func TestHeartbeatFlushesWithoutReleasingPartialFake(t *testing.T) {
	r, fake := aliasPseudonym(t, "heartbeat")
	var out bytes.Buffer
	w := NewSSERestoringWriterForSession(&out, r, "heartbeat")
	first := sseDeltaEvent("response.output_text.delta", fake[:len(fake)/2], 1)
	if _, err := w.Write([]byte(first + ": keepalive\n\n")); err != nil {
		t.Fatal(err)
	}
	if out.String() != ": keepalive\n\n" {
		t.Fatalf("premature output: %q", out.String())
	}
	if _, err := w.Write([]byte(sseDeltaEvent("response.output_text.delta", fake[len(fake)/2:], 2) + "data: [DONE]\n\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if got := joinedTopLevelDeltas(t, out.String()); got != "CUSTOMER-ALPHA" {
		t.Fatal(got)
	}
}

func TestRestorationQueueIsBounded(t *testing.T) {
	r, fake := aliasPseudonym(t, "bounded")
	var out bytes.Buffer
	w := NewSSERestoringWriterForSessionWithLimit(&out, r, "bounded", 512)
	if _, err := w.Write([]byte(responseDeltaEventWithItem("response.output_text.delta", "waiting", fake[:2], 1))); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		_, err := w.Write([]byte(responseDeltaEventWithItem("response.output_text.delta", "other", "hello", i+2)))
		if errors.Is(err, ErrSSEEventTooLarge) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("unresolved channel allowed unbounded buffering")
}

func TestStreamedToolArgumentsRemainValidJSON(t *testing.T) {
	const original = "quote\" slash\\ newline\n"
	r := policyProxyRedactor(t, detectors.CustomPattern{Name: "secret", Pattern: `quote" slash\\ newline\n`, Action: "pseudonymize", Generator: "alias"})
	request, _ := json.Marshal(map[string]string{"input": original})
	result, err := r.Transform(request, "args", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	var transformed map[string]string
	json.Unmarshal(result.Body, &transformed)
	fake := transformed["input"]
	if fake == original {
		t.Fatal("fixture not transformed")
	}
	args := `{"path":"` + fake + `","other":"a\\b"}`
	for split := 1; split < len(args); split++ {
		stream := responseDeltaEventWithItem("response.function_call_arguments.delta", "call", args[:split], 1) +
			": heartbeat\n\n" + responseDeltaEventWithItem("response.function_call_arguments.delta", "call", args[split:], 2) + "data: [DONE]\n\n"
		out := restoreSSEForTest(t, r, "args", stream)
		var got map[string]string
		if err := json.Unmarshal([]byte(joinedTopLevelDeltas(t, out)), &got); err != nil {
			t.Fatalf("split %d: %v; %s", split, err, out)
		}
		if got["path"] != original || got["other"] != `a\b` {
			t.Fatalf("split %d: %v", split, got)
		}
	}
}

func TestStreamOverflowIsTransportFailure(t *testing.T) {
	for _, eventLimit := range []bool{true, false} {
		t.Run(map[bool]string{true: "event", false: "response"}[eventLimit], func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, "data: {}\n\n")
				w.(http.Flusher).Flush()
				io.WriteString(w, "data: {\"delta\":\""+strings.Repeat("a", 100)+"\"}\n\n")
			}))
			defer upstream.Close()
			opts := Options{MaxSSEEventBytes: 32}
			if !eventLimit {
				opts = Options{MaxResponseBytes: 32}
			}
			var logs bytes.Buffer
			p, _ := New(upstream.URL, policyProxyRedactor(t), log.New(&logs, "", 0), opts)
			handlerDone := make(chan struct{})
			front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(handlerDone)
				p.ServeHTTP(w, r)
			}))
			defer front.Close()
			resp, err := http.Post(front.URL, "application/json", strings.NewReader(`{}`))
			if err == nil {
				defer resp.Body.Close()
				_, err = io.ReadAll(resp.Body)
			}
			if err == nil {
				t.Fatal("truncated stream looked successful")
			}
			<-handlerDone
			if !strings.Contains(logs.String(), "error=stream_interrupted") || strings.Contains(logs.String(), "status=200") {
				t.Fatalf("logs: %s", logs.String())
			}
		})
	}
}

func TestResponseIdleTimeoutAndActiveStream(t *testing.T) {
	for _, mode := range []string{"buffered-stall", "stream-stall", "active", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			upstreamDone := make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(upstreamDone)
				if mode != "buffered-stall" {
					w.Header().Set("Content-Type", "text/event-stream")
				}
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				if mode == "active" {
					for i := 0; i < 8; i++ {
						io.WriteString(w, ": heartbeat\n\n")
						w.(http.Flusher).Flush()
						time.Sleep(20 * time.Millisecond)
					}
					io.WriteString(w, "data: [DONE]\n\n")
					return
				}
				<-r.Context().Done()
			}))
			defer upstream.Close()
			p, _ := New(upstream.URL, policyProxyRedactor(t), nil, Options{ResponseIdleTimeout: 100 * time.Millisecond})
			front := httptest.NewServer(p)
			defer front.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if mode == "cancel" {
				time.AfterFunc(25*time.Millisecond, cancel)
			}
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, front.URL, strings.NewReader(`{}`))
			started := time.Now()
			resp, err := http.DefaultClient.Do(req)
			var body []byte
			if err == nil {
				defer resp.Body.Close()
				body, err = io.ReadAll(resp.Body)
			}
			if mode == "active" {
				if err != nil || !strings.Contains(string(body), "[DONE]") {
					t.Fatalf("active stream failed: %v", err)
				}
			} else {
				if time.Since(started) > time.Second {
					t.Fatal("stalled until client deadline")
				}
				if mode == "buffered-stall" {
					if resp == nil || resp.StatusCode != 502 {
						t.Fatal("missing 502")
					}
				} else if err == nil {
					t.Fatal("missing stream/cancellation error")
				}
			}
			select {
			case <-upstreamDone:
			case <-time.After(time.Second):
				t.Fatal("upstream not released")
			}
		})
	}
}
