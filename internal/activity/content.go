package activity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const ContentEndpoint = "/__cover/live-content"

var ErrTooManyContentMonitors = errors.New("too many live content monitors")

type ContentCapture struct {
	Rule        string `json:"rule"`
	Category    string `json:"category"`
	Action      string `json:"action"`
	Original    string `json:"original"`
	Replacement string `json:"replacement"`
}

type ContentEvent struct {
	Time        time.Time        `json:"time"`
	Transformed int              `json:"transformed"`
	Blocked     bool             `json:"blocked"`
	Caught      []ContentCapture `json:"caught"`
	Sent        json.RawMessage  `json:"sent,omitempty"`
}

type Hub struct {
	mu          sync.Mutex
	nextID      uint64
	maxMonitors int
	subscribers map[uint64]chan ContentEvent
}

func NewHub(maxMonitors int) *Hub {
	if maxMonitors <= 0 {
		maxMonitors = 4
	}
	return &Hub{maxMonitors: maxMonitors, subscribers: map[uint64]chan ContentEvent{}}
}

func (h *Hub) HasSubscribers() bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subscribers) > 0
}

func (h *Hub) Subscribe() (<-chan ContentEvent, func(), error) {
	if h == nil {
		return nil, func() {}, fmt.Errorf("content monitor is unavailable")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subscribers) >= h.maxMonitors {
		return nil, func() {}, ErrTooManyContentMonitors
	}
	h.nextID++
	id := h.nextID
	ch := make(chan ContentEvent, 1)
	h.subscribers[id] = ch
	cancel := func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if existing, ok := h.subscribers[id]; ok {
			delete(h.subscribers, id)
			close(existing)
		}
	}
	return ch, cancel, nil
}

// Publish never blocks request forwarding. A monitor that cannot keep up is
// disconnected instead of silently missing sensitive events.
func (h *Hub) Publish(event ContentEvent) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, ch := range h.subscribers {
		select {
		case ch <- event:
		default:
			delete(h.subscribers, id)
			close(ch)
		}
	}
}

func ContentToken(key [32]byte) string {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("cover:live-content-monitor:v1"))
	return hex.EncodeToString(mac.Sum(nil))
}

func WatchContent(ctx context.Context, baseURL, token string, ready func(), handle func(ContentEvent) error) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+ContentEndpoint, nil)
	if err != nil {
		return fmt.Errorf("creating live content request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/x-ndjson")
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("connecting to Cover live content stream: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Cover refused the live content stream (HTTP %d)", response.StatusCode)
	}
	if ready != nil {
		ready()
	}
	decoder := json.NewDecoder(response.Body)
	for {
		var event ContentEvent
		if err := decoder.Decode(&event); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, io.EOF) {
				return fmt.Errorf("live content stream ended; the monitor may have fallen behind")
			}
			return fmt.Errorf("reading live content stream: %w", err)
		}
		if err := handle(event); err != nil {
			return err
		}
	}
}
