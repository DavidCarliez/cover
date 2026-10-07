package activity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestContentTokenIsStableAndInstallationScoped(t *testing.T) {
	var keyA, keyB [32]byte
	keyA[0], keyB[0] = 1, 2
	if first, second := ContentToken(keyA), ContentToken(keyA); first != second {
		t.Fatal("content token is not stable")
	}
	if ContentToken(keyA) == ContentToken(keyB) {
		t.Fatal("different installation keys produced the same content token")
	}
}

func TestWatchContentAuthenticatesAndDecodes(t *testing.T) {
	const token = "private-monitor-token"
	want := ContentEvent{Transformed: 1, Sent: json.RawMessage(`{"input":"protected"}`)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != ContentEndpoint || r.Header.Get("Authorization") != "Bearer "+token {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	var got ContentEvent
	err := WatchContent(ctx, server.URL, token, nil, func(event ContentEvent) error {
		got = event
		cancel()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Transformed != want.Transformed || string(got.Sent) != string(want.Sent) {
		t.Fatalf("event=%+v, want %+v", got, want)
	}
}

func TestHubDisconnectsSlowMonitorWithoutBlocking(t *testing.T) {
	hub := NewHub(1)
	ch, cancel, err := hub.Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if _, _, err := hub.Subscribe(); !errors.Is(err, ErrTooManyContentMonitors) {
		t.Fatalf("second subscription error=%v", err)
	}
	// A burst within the buffer is delivered; one more disconnects the viewer.
	for range contentMonitorBuffer + 1 {
		hub.Publish(ContentEvent{Time: time.Now()})
	}
	for range contentMonitorBuffer {
		if _, ok := <-ch; !ok {
			t.Fatal("buffered event was lost")
		}
	}
	if _, ok := <-ch; ok {
		t.Fatal("slow monitor was not disconnected")
	}
}

func TestHubCloseEndsMonitors(t *testing.T) {
	hub := NewHub(1)
	ch, cancel, err := hub.Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	hub.Close()
	if _, ok := <-ch; ok {
		t.Fatal("monitor stream stayed open after Close")
	}
	if _, _, err := hub.Subscribe(); err == nil {
		t.Fatal("a closed hub accepted a new monitor")
	}
}
