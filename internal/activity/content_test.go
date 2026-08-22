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
	if ContentToken(keyA) != ContentToken(keyA) {
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
	hub.Publish(ContentEvent{Time: time.Now()})
	hub.Publish(ContentEvent{Time: time.Now()})
	if _, ok := <-ch; !ok {
		t.Fatal("buffered event was lost")
	}
	if _, ok := <-ch; ok {
		t.Fatal("slow monitor was not disconnected")
	}
}
