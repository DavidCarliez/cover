package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DavidCarliez/cover/internal/redact"
	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func newTestRedactor(t *testing.T) *redact.Redactor {
	return newTestRedactorWithCategories(t, []string{"aws_access_key"})
}

func newTestRedactorWithCategories(t *testing.T, categories []string) *redact.Redactor {
	t.Helper()
	d, err := detectors.NewRegexDetector(categories, nil)
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}
	return redact.New(redact.NewStore(), 0, redact.RedactorOptions{}, d)
}

// TestProxy_RedactsRequestAndRestoresResponse verifies that a secret in the
// request body is replaced with a placeholder before reaching the upstream,
// and that if the upstream echoes that placeholder back, the client receives
// the real secret again.
func TestProxy_RedactsRequestAndRestoresResponse(t *testing.T) {
	const secret = "AKIAIOSFODNN7EXAMPLE"

	var receivedBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)

		echo, _ := json.Marshal(receivedBody)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"echo":%s}`, echo)
	}))
	defer upstream.Close()

	redactor := newTestRedactor(t)
	p, err := New(upstream.URL, redactor, nil, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	front := httptest.NewServer(p)
	defer front.Close()

	reqBody := fmt.Sprintf(`{"text":"my key is %s"}`, secret)
	resp, err := http.Post(front.URL+"/v1/chat", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if strings.Contains(receivedBody, secret) {
		t.Errorf("upstream received unredacted secret: %s", receivedBody)
	}
	if !strings.Contains(receivedBody, "⟦RG:") {
		t.Errorf("upstream body missing placeholder token: %s", receivedBody)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if !strings.Contains(string(respBody), secret) {
		t.Errorf("client response missing restored secret: %s", respBody)
	}
	if strings.Contains(string(respBody), "⟦RG:") {
		t.Errorf("client response still contains placeholder: %s", respBody)
	}
}

// TestProxy_RestoresSSEStream verifies that a placeholder token streamed back
// from the upstream over text/event-stream, split across multiple flushed
// writes, is restored to the original secret in the client response.
func TestProxy_RestoresSSEStream(t *testing.T) {
	testProxyRestoresSSE(t, "AKIAIOSFODNN7EXAMPLE")
}

func TestProxy_RestoresSSEStream_QuotedSecret(t *testing.T) {
	testProxyRestoresSSE(t, `api_key = "anasbdn198h291ebkhjabsdbbasbd"`)
}

func testProxyRestoresSSE(t *testing.T, secret string) {
	t.Helper()
	placeholderRe := regexp.MustCompile(`⟦RG:[0-9a-f]{8}⟧`)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		placeholder := placeholderRe.FindString(string(body))
		if placeholder == "" {
			http.Error(w, "no placeholder in request", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("upstream ResponseWriter does not support flushing")
		}

		chunkPayload, _ := json.Marshal(map[string]string{"text": placeholder})
		chunk := fmt.Sprintf("data: %s\n\n", chunkPayload)
		mid := len(chunk) / 2
		fmt.Fprint(w, chunk[:mid])
		flusher.Flush()
		fmt.Fprint(w, chunk[mid:])
		flusher.Flush()
	}))
	defer upstream.Close()

	redactor := newTestRedactorWithCategories(t, []string{"aws_access_key", "generic_api_key_assignment"})
	p, err := New(upstream.URL, redactor, nil, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	front := httptest.NewServer(p)
	defer front.Close()

	reqBodyBytes, err := json.Marshal(map[string]string{"text": secret})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(front.URL+"/v1/chat", "application/json", bytes.NewReader(reqBodyBytes))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}

	wantPayload, _ := json.Marshal(map[string]string{"text": secret})
	want := fmt.Sprintf("data: %s\n\n", wantPayload)
	if string(respBody) != want {
		t.Errorf("got %q, want %q", respBody, want)
	}
}

func TestProxy_UpstreamConnectTimeout(t *testing.T) {
	// RFC 5737 TEST-NET-1; unrouted, so TCP connect should time out.
	redactor := newTestRedactor(t)
	p, err := New("http://192.0.2.1:9", redactor, nil, Options{
		ConnectTimeout:        100 * time.Millisecond,
		ResponseHeaderTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	front := httptest.NewServer(p)
	defer front.Close()

	start := time.Now()
	resp, err := http.Post(front.URL+"/v1/chat", "application/json", strings.NewReader(`{"text":"hello"}`))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if elapsed > 2*time.Second {
		t.Errorf("request took %v, expected connect timeout near 100ms", elapsed)
	}
}

func TestProxy_UpstreamResponseHeaderTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	redactor := newTestRedactor(t)
	p, err := New(upstream.URL, redactor, nil, Options{
		ConnectTimeout:        time.Second,
		ResponseHeaderTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	front := httptest.NewServer(p)
	defer front.Close()

	start := time.Now()
	resp, err := http.Post(front.URL+"/v1/chat", "application/json", strings.NewReader(`{"text":"hello"}`))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if elapsed > time.Second {
		t.Errorf("request took %v, expected header timeout near 50ms", elapsed)
	}
}

func TestProxy_ReturnsWhenContextCanceledMidFlight(t *testing.T) {
	upstreamStarted := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(upstreamStarted)
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	p, err := New(upstream.URL, newTestRedactor(t), nil, Options{
		ConnectTimeout:        time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/v1/chat", strings.NewReader(`{"text":"hello"}`))
	req = req.WithContext(ctx)

	serveDone := make(chan struct{})
	go func() {
		p.ServeHTTP(httptest.NewRecorder(), req)
		close(serveDone)
	}()

	select {
	case <-upstreamStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream handler did not start")
	}
	cancel()

	start := time.Now()
	select {
	case <-serveDone:
		if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
			t.Fatalf("ServeHTTP took %v after cancel, want well under 200ms", elapsed)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("ServeHTTP did not return after client context was canceled")
	}
}

func TestProxy_CanceledContextBeforeUpstream(t *testing.T) {
	upstreamCalled := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled <- struct{}{}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	p, err := New(upstream.URL, newTestRedactor(t), nil, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := httptest.NewRequest(http.MethodPost, "/v1/chat", strings.NewReader(`{"text":"hello"}`))
	req = req.WithContext(ctx)
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	if rw.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rw.Code)
	}
	select {
	case <-upstreamCalled:
		t.Error("upstream was called despite canceled client context")
	default:
	}
}
