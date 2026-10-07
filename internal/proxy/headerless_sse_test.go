package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func TestProxyRestoresSSEWithoutContentType(t *testing.T) {
	const original = "CUSTOMER-ALPHA"
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		fake := body["input"]
		if fake == original || !strings.HasPrefix(fake, "alias-") {
			t.Errorf("upstream received unprotected value: %q", fake)
			return
		}
		// Suppress net/http's automatic text/plain sniffing, like the router.
		w.Header()["Content-Type"] = nil
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for i := range fake {
			fmt.Fprint(w, sseDeltaEvent("response.output_text.delta", fake[i:i+1], i))
			w.(http.Flusher).Flush()
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-req.Context().Done():
		}
	}))
	defer upstream.Close()
	defer close(release)

	r := policyProxyRedactor(t, detectors.CustomPattern{
		Name: "customer", Pattern: original, Action: "pseudonymize", Generator: "alias",
	})
	p, err := New(upstream.URL, r, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(p)
	defer front.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Post(front.URL+"/responses", "application/json", strings.NewReader(`{"input":"CUSTOMER-ALPHA"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if got := response.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("Content-Type = %q", got)
	}
	// Read through the terminal event while the upstream connection stays open.
	// This also proves that headerless SSE is streamed rather than buffered to EOF.
	var stream strings.Builder
	buf := make([]byte, 256)
	for !strings.Contains(stream.String(), "data: [DONE]\n\n") {
		n, err := response.Body.Read(buf)
		stream.Write(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := joinedTopLevelDeltas(t, stream.String()); got != original {
		t.Fatalf("streamed reply = %q, want %q", got, original)
	}
}

func TestProxyPreservesHeaderlessNonSSEResponse(t *testing.T) {
	for _, body := range []string{"", "ok", `{"text":"ordinary JSON"}`} {
		t.Run(body, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header()["Content-Type"] = nil
				fmt.Fprint(w, body)
			}))
			defer upstream.Close()
			p, err := New(upstream.URL, newTestRedactor(t), nil, Options{})
			if err != nil {
				t.Fatal(err)
			}
			front := httptest.NewServer(p)
			defer front.Close()
			response, err := http.Post(front.URL, "application/json", strings.NewReader(`{"input":"hello"}`))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			got, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != body || response.Header.Get("Content-Type") == "text/event-stream" {
				t.Fatalf("non-SSE response changed: type=%q body=%q", response.Header.Get("Content-Type"), got)
			}
		})
	}
}

func TestProxyRestoresSSEStartingWithByteOrderMark(t *testing.T) {
	const original = "CUSTOMER-ALPHA"
	for _, contentType := range []string{"text/event-stream", ""} {
		t.Run("type="+contentType, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var body map[string]string
				if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
					t.Error(err)
					return
				}
				if contentType == "" {
					w.Header()["Content-Type"] = nil
				} else {
					w.Header().Set("Content-Type", contentType)
				}
				// Split the mark across writes to exercise buffering.
				fmt.Fprint(w, "\xef\xbb")
				w.(http.Flusher).Flush()
				fmt.Fprint(w, "\xbf"+sseDeltaEvent("response.output_text.delta", body["input"], 0))
				fmt.Fprint(w, "data: [DONE]\n\n")
			}))
			defer upstream.Close()
			r := policyProxyRedactor(t, detectors.CustomPattern{
				Name: "customer", Pattern: original, Action: "pseudonymize", Generator: "alias",
			})
			p, err := New(upstream.URL, r, nil, Options{})
			if err != nil {
				t.Fatal(err)
			}
			front := httptest.NewServer(p)
			defer front.Close()
			response, err := http.Post(front.URL+"/responses", "application/json", strings.NewReader(`{"input":"CUSTOMER-ALPHA"}`))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			stream, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(string(stream), "\xef\xbb\xbf") {
				t.Fatalf("byte order mark was not kept: %q", stream)
			}
			if got := joinedTopLevelDeltas(t, strings.TrimPrefix(string(stream), "\xef\xbb\xbf")); got != original {
				t.Fatalf("first event was not restored: %q", stream)
			}
		})
	}
}
