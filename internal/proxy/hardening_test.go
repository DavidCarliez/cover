package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DavidCarliez/cover/internal/activity"
	"github.com/DavidCarliez/cover/internal/redact"
	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func policyProxyRedactor(t *testing.T, rules ...detectors.CustomPattern) *redact.Redactor {
	t.Helper()
	d, err := detectors.NewRegexDetector(nil, rules)
	if err != nil {
		t.Fatal(err)
	}
	return redact.New(redact.NewStore(), 0, redact.RedactorOptions{}, d)
}

func TestProxyFailsClosedOnMalformedJSON(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	p, err := New(upstream.URL, policyProxyRedactor(t), nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"input":`)))
	if rw.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d", rw.Code)
	}
	if calls.Load() != 0 {
		t.Fatal("malformed request reached upstream")
	}
}

func TestProxyFailsClosedOnCompressedBody(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	p, err := New(upstream.URL, policyProxyRedactor(t), nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader("compressed bytes"))
	req.Header.Set("Content-Encoding", "zstd")
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)
	if rw.Code != http.StatusUnprocessableEntity || calls.Load() != 0 {
		t.Fatalf("status=%d calls=%d", rw.Code, calls.Load())
	}
}

func TestProxyBlockActionNeverCallsUpstream(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	r := policyProxyRedactor(t, detectors.CustomPattern{Name: "api_key", Pattern: `APIKEY-[A-Z0-9]+`, Action: "block"})
	p, _ := New(upstream.URL, r, nil, Options{})
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"input":"APIKEY-SECRET123"}`)))
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatal("blocked request reached upstream")
	}
}

func TestProxyPseudonymizesAndRestoresToolArguments(t *testing.T) {
	const original = "10.20.30.40"
	var upstreamBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		upstreamBody, _ = io.ReadAll(req.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write(upstreamBody)
	}))
	defer upstream.Close()
	r := policyProxyRedactor(t, detectors.CustomPattern{Name: "ipv4", Detector: "builtin_ipv4", Action: "pseudonymize", Generator: "ipv4"})
	p, _ := New(upstream.URL, r, nil, Options{SessionHeader: "X-Cover-Session"})
	front := httptest.NewServer(p)
	defer front.Close()
	payload := `{"input":[{"type":"function_call","name":"run_command","arguments":"{\"target\":\"10.20.30.40\",\"password\":\"safe\"}"}]}`
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/v1/responses", strings.NewReader(payload))
	req.Header.Set("X-Cover-Session", "codex-turns")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	clientBody, _ := io.ReadAll(resp.Body)
	if bytes.Contains(upstreamBody, []byte(original)) {
		t.Fatalf("upstream received original: %s", upstreamBody)
	}
	if bytes.Contains(upstreamBody, []byte(`"system"`)) {
		t.Fatalf("proxy injected a protocol-specific system field: %s", upstreamBody)
	}
	if !bytes.Contains(clientBody, []byte(original)) {
		t.Fatalf("client did not receive restored target: %s", clientBody)
	}
	var got any
	if err := json.Unmarshal(clientBody, &got); err != nil {
		t.Fatalf("invalid restored JSON: %v", err)
	}
}

func TestSSEFunctionArgumentDeltaRestoresAcrossNetworkChunks(t *testing.T) {
	r := policyProxyRedactor(t, detectors.CustomPattern{Name: "ip", Pattern: `10\.20\.30\.40`, Action: "pseudonymize", Generator: "ipv4"})
	result, err := r.Transform([]byte(`{"arguments":"{\"target\":\"10.20.30.40\"}"}`), "stream", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	var transformed map[string]string
	json.Unmarshal(result.Body, &transformed)
	eventJSON, _ := json.Marshal(map[string]any{"type": "response.function_call_arguments.delta", "delta": transformed["arguments"]})
	event := append(append([]byte("data: "), eventJSON...), []byte("\n\n")...)
	for split := 0; split <= len(event); split++ {
		var out bytes.Buffer
		rw := NewSSERestoringWriterForSession(&out, r, "stream")
		if _, err := rw.Write(event[:split]); err != nil {
			t.Fatal(err)
		}
		if _, err := rw.Write(event[split:]); err != nil {
			t.Fatal(err)
		}
		if err := rw.Close(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "10.20.30.40") {
			t.Fatalf("split=%d response not restored: %q", split, out.String())
		}
	}
}

func TestProxyImageBlockPolicy(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	p, _ := New(upstream.URL, policyProxyRedactor(t), nil, Options{MediaImages: "block"})
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"input":[{"type":"input_image","image_url":"data:image/png;base64,AAAA"}]}`)))
	if rw.Code != http.StatusForbidden || calls.Load() != 0 {
		t.Fatalf("status=%d calls=%d", rw.Code, calls.Load())
	}
}

func TestProxyPreservesBase64ImageWhileProtectingText(t *testing.T) {
	encoded := strings.Repeat("+1234567", 32768)
	imageURL := "data:image/png;base64," + encoded
	var upstreamImage string
	var upstreamText string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		input := body["input"].([]any)
		upstreamImage = input[0].(map[string]any)["image_url"].(string)
		upstreamText = input[1].(map[string]any)["text"].(string)
		payload := strings.TrimPrefix(upstreamImage, "data:image/png;base64,")
		if _, err := base64.StdEncoding.DecodeString(payload); err != nil {
			http.Error(w, "invalid Base64", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	d, err := detectors.NewRegexDetector([]string{"phone_intl"}, []detectors.CustomPattern{{
		Name: "private_ip", Pattern: `10\.20\.30\.40`, Action: "pseudonymize", Generator: "ipv4",
	}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(upstream.URL, redact.New(redact.NewStore(), 0, redact.RedactorOptions{}, d), nil, Options{MediaImages: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"input": []any{
			map[string]any{"type": "input_image", "image_url": imageURL},
			map[string]any{"type": "input_text", "text": "connect to 10.20.30.40"},
		},
	})
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body)))
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	if upstreamImage != imageURL {
		t.Fatal("upstream received modified image data")
	}
	if strings.Contains(upstreamText, "10.20.30.40") {
		t.Fatal("upstream received unprotected private text")
	}
}

func TestDefaultLogsNeverContainBodiesOrMappings(t *testing.T) {
	const secret = "API_RESPONSE_SECRET"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Request-ID", "request-id-secret")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"API_RESPONSE_SECRET"}`))
	}))
	defer upstream.Close()
	var logs bytes.Buffer
	p, _ := New(upstream.URL, policyProxyRedactor(t), log.New(&logs, "", 0), Options{})
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"input":"hello"}`)))
	if strings.Contains(logs.String(), secret) || strings.Contains(logs.String(), "request-id-secret") || strings.Contains(logs.String(), `{"input"`) {
		t.Fatalf("log exposed a body: %q", logs.String())
	}
	if !strings.Contains(logs.String(), "status=400") {
		t.Fatalf("log omitted status: %q", logs.String())
	}
	for _, field := range []string{"sent_bytes=", "returned_bytes=", "duration_ms="} {
		if !strings.Contains(logs.String(), field) {
			t.Fatalf("log omitted safe activity metric %q: %q", field, logs.String())
		}
	}
}

func TestAuditLogOmitsRequestPathAndQuery(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	var logs bytes.Buffer
	p, _ := New(upstream.URL, policyProxyRedactor(t), log.New(&logs, "", 0), Options{})
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "/customer-secret/responses?token=query-secret", strings.NewReader(`{"input":"hello"}`)))
	if strings.Contains(logs.String(), "customer-secret") || strings.Contains(logs.String(), "query-secret") || strings.Contains(logs.String(), "path=") {
		t.Fatalf("audit log exposed request routing data: %q", logs.String())
	}
	if !strings.Contains(logs.String(), "status=200") {
		t.Fatalf("audit log lost safe status metadata: %q", logs.String())
	}
}

func TestInvalidUpstreamErrorOmitsConfiguredValue(t *testing.T) {
	const configured = "https://router.example/secret-route/%zz"
	_, err := New(configured, policyProxyRedactor(t), nil, Options{})
	if err == nil {
		t.Fatal("expected invalid upstream URL error")
	}
	if strings.Contains(err.Error(), "secret-route") || strings.Contains(err.Error(), "%zz") {
		t.Fatalf("error exposed configured upstream value: %q", err)
	}
}

func TestProxyRejectsOversizedRequestBeforeUpstream(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	p, _ := New(upstream.URL, policyProxyRedactor(t), nil, Options{MaxRequestBytes: 8})
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"input":"too large"}`)))
	if rw.Code != http.StatusRequestEntityTooLarge || calls.Load() != 0 {
		t.Fatalf("status=%d upstream calls=%d", rw.Code, calls.Load())
	}
}

func TestProxyAcceptsBodiesAtConfiguredLimits(t *testing.T) {
	const payload = `{"a":1}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer upstream.Close()
	p, _ := New(upstream.URL, policyProxyRedactor(t), nil, Options{
		MaxRequestBytes:  int64(len(payload)),
		MaxResponseBytes: int64(len(payload)),
	})
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(payload)))
	if rw.Code != http.StatusOK || rw.Body.String() != payload {
		t.Fatalf("status=%d body=%q", rw.Code, rw.Body.String())
	}
}

func TestCappedReaderRejectsStreamingOverflow(t *testing.T) {
	got, err := io.ReadAll(&cappedReader{r: strings.NewReader("123456"), remaining: 5})
	if !errors.Is(err, errBodyTooLarge) {
		t.Fatalf("error=%v, want errBodyTooLarge", err)
	}
	if string(got) != "12345" {
		t.Fatalf("body=%q, want capped prefix", got)
	}
}

func TestProxyRejectsOversizedNonStreamingResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":"too large"}`))
	}))
	defer upstream.Close()
	p, _ := New(upstream.URL, policyProxyRedactor(t), nil, Options{MaxResponseBytes: 8})
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"input":"ok"}`)))
	if rw.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%q", rw.Code, rw.Body.String())
	}
	if strings.Contains(rw.Body.String(), "too large") {
		t.Fatalf("oversized upstream body was forwarded: %q", rw.Body.String())
	}
}

func TestSSERestoringWriterRejectsOversizedEvent(t *testing.T) {
	var out bytes.Buffer
	r := policyProxyRedactor(t)
	rw := NewSSERestoringWriterForSessionWithLimit(&out, r, "s", 16)
	if _, err := rw.Write([]byte("data: 12345678901234567890\n\n")); !errors.Is(err, ErrSSEEventTooLarge) {
		t.Fatalf("error=%v, want ErrSSEEventTooLarge", err)
	}
	if out.Len() != 0 {
		t.Fatalf("oversized SSE event was forwarded: %q", out.String())
	}
	if err := rw.Close(); err != nil {
		t.Fatalf("close after rejected event: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("close forwarded rejected SSE event: %q", out.String())
	}
}

func TestLiveContentMonitorIsAuthenticatedLocalAndNeverLogged(t *testing.T) {
	const original = "customer@example.com"
	var upstreamBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		upstreamBody, _ = io.ReadAll(req.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	var key [32]byte
	key[0] = 7
	token := activity.ContentToken(key)
	hub := activity.NewHub(2)
	var logs bytes.Buffer
	r := policyProxyRedactor(t, detectors.CustomPattern{Name: "customer", Pattern: original, Action: "pseudonymize", Generator: "email"})
	p, err := New(upstream.URL, r, log.New(&logs, "", 0), Options{ContentHub: hub, ContentToken: token})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(p)
	defer front.Close()

	unauthorized, _ := http.NewRequest(http.MethodGet, front.URL+activity.ContentEndpoint, nil)
	unauthorizedResponse, err := http.DefaultClient.Do(unauthorized)
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthorizedResponse.Body.Close()
	if unauthorizedResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized status=%d", unauthorizedResponse.StatusCode)
	}

	monitorRequest, _ := http.NewRequest(http.MethodGet, front.URL+activity.ContentEndpoint, nil)
	monitorRequest.Header.Set("Authorization", "Bearer "+token)
	monitorResponse, err := http.DefaultClient.Do(monitorRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer monitorResponse.Body.Close()
	if monitorResponse.StatusCode != http.StatusOK {
		t.Fatalf("monitor status=%d", monitorResponse.StatusCode)
	}

	clientResponse, err := http.Post(front.URL+"/responses", "application/json", strings.NewReader(`{"input":"customer@example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = clientResponse.Body.Close()
	var event activity.ContentEvent
	if err := json.NewDecoder(monitorResponse.Body).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if len(event.Caught) != 1 || event.Caught[0].Original != original || event.Caught[0].Replacement == original {
		t.Fatalf("unexpected captures: %+v", event.Caught)
	}
	if bytes.Contains(event.Sent, []byte(original)) || !bytes.Equal(event.Sent, upstreamBody) {
		t.Fatalf("event body does not match protected upstream body: event=%s upstream=%s", event.Sent, upstreamBody)
	}
	if strings.Contains(logs.String(), original) || strings.Contains(logs.String(), event.Caught[0].Replacement) {
		t.Fatalf("audit log retained live content: %q", logs.String())
	}

	remoteRequest := httptest.NewRequest(http.MethodGet, activity.ContentEndpoint, nil)
	remoteRequest.RemoteAddr = "198.51.100.10:1234"
	remoteRequest.Header.Set("Authorization", "Bearer "+token)
	remoteResponse := httptest.NewRecorder()
	p.ServeHTTP(remoteResponse, remoteRequest)
	if remoteResponse.Code != http.StatusNotFound {
		t.Fatalf("remote monitor status=%d", remoteResponse.Code)
	}
}

func TestProxyRejectsRequestsThatLoopBackThroughItself(t *testing.T) {
	var front *httptest.Server
	var p *Proxy
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { p.ServeHTTP(w, r) })
	front = httptest.NewServer(handler)
	defer front.Close()
	var err error
	if p, err = New(front.URL, newTestRedactor(t), nil, Options{}); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(front.URL+"/v1/responses", "application/json", strings.NewReader(`{"input":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// The first hop forwards to itself; the second recognizes its identifier.
	if resp.StatusCode != http.StatusLoopDetected {
		t.Fatalf("status=%d, want %d", resp.StatusCode, http.StatusLoopDetected)
	}
}

func TestProxyStripsHopByHopHeadersAndKeepsChainedCovers(t *testing.T) {
	var got http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Connection", "X-Private-Hop")
		w.Header().Set("X-Private-Hop", "upstream")
		w.Write([]byte(`{}`))
	}))
	defer upstream.Close()
	p, err := New(upstream.URL, newTestRedactor(t), nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(p)
	defer front.Close()
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Connection", "X-Local-Only")
	req.Header.Set("X-Local-Only", "secret")
	req.Header.Set("Proxy-Authorization", "Basic abc")
	req.Header.Set("Authorization", "Bearer keep")
	req.Header.Set(hopHeader, "another-cover")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got.Get("X-Local-Only") != "" || got.Get("Proxy-Authorization") != "" {
		t.Fatalf("hop-by-hop headers were forwarded: %v", got)
	}
	if got.Get("Authorization") != "Bearer keep" {
		t.Fatalf("end-to-end header was dropped: %v", got)
	}
	if hops := got.Values(hopHeader); len(hops) != 2 || hops[0] != "another-cover" || hops[1] != p.hopID {
		t.Fatalf("hop identifiers=%v", hops)
	}
	if resp.Header.Get("X-Private-Hop") != "" {
		t.Fatalf("upstream hop-by-hop header reached the client")
	}
}

func TestEphemeralSessionsCannotBeNamedByClients(t *testing.T) {
	front := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a request carrying the ephemeral session prefix reached the server")
	}))
	defer front.Close()
	req, _ := http.NewRequest(http.MethodPost, front.URL, strings.NewReader(`{}`))
	req.Header.Set("X-Cover-Session", ephemeralSessionPrefix+"1")
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("an HTTP client sent a session header with the ephemeral prefix")
	}
}

func TestLooksLikeSSE(t *testing.T) {
	for prefix, want := range map[string]bool{
		"event: message\n":    true,
		"data: {}\n":          true,
		"id: 1\ndata: x\n":    true,
		"retry: 100\n":        true,
		": comment\n":         true,
		"\xef\xbb\xbfdata: x": true,
		"\n\ndata: x\n":       true,
		`{"choices":[]}`:      false,
		"identifier: nope":    false,
		"HTTP/1.1 200 OK\r\n": false,
	} {
		if got := looksLikeSSE([]byte(prefix)); got != want {
			t.Errorf("looksLikeSSE(%q)=%v, want %v", prefix, got, want)
		}
	}
}
