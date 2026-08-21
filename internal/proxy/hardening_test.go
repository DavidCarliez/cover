package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"llmguard/internal/redact"
	"llmguard/internal/redact/detectors"
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
	p, _ := New(upstream.URL, r, nil, Options{SessionHeader: "X-LLMGuard-Session"})
	front := httptest.NewServer(p)
	defer front.Close()
	payload := `{"input":[{"type":"function_call","name":"run_command","arguments":"{\"target\":\"10.20.30.40\",\"password\":\"safe\"}"}]}`
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/v1/responses", strings.NewReader(payload))
	req.Header.Set("X-LLMGuard-Session", "codex-turns")
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

func TestRestoringWriterPseudonymSplitAcrossWrites(t *testing.T) {
	r := policyProxyRedactor(t, detectors.CustomPattern{Name: "ip", Pattern: `10\.20\.30\.40`, Action: "pseudonymize", Generator: "ipv4"})
	result, err := r.Transform([]byte(`{"text":"10.20.30.40"}`), "stream", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]string
	json.Unmarshal(result.Body, &obj)
	fake := obj["text"]
	data := []byte("prefix " + fake + " suffix")
	for split := 0; split <= len(data); split++ {
		var out bytes.Buffer
		rw := NewRestoringWriterForSession(&out, r, "stream")
		if _, err := rw.Write(data[:split]); err != nil {
			t.Fatal(err)
		}
		if _, err := rw.Write(data[split:]); err != nil {
			t.Fatal(err)
		}
		if err := rw.Close(); err != nil {
			t.Fatal(err)
		}
		if out.String() != "prefix 10.20.30.40 suffix" {
			t.Fatalf("split=%d got=%q", split, out.String())
		}
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

func TestDefaultLogsNeverContainBodiesOrMappings(t *testing.T) {
	const secret = "API_RESPONSE_SECRET"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"API_RESPONSE_SECRET"}`))
	}))
	defer upstream.Close()
	var logs bytes.Buffer
	p, _ := New(upstream.URL, policyProxyRedactor(t), log.New(&logs, "", 0), Options{})
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"input":"hello"}`)))
	if strings.Contains(logs.String(), secret) || strings.Contains(logs.String(), `{"input"`) {
		t.Fatalf("log exposed a body: %q", logs.String())
	}
	if !strings.Contains(logs.String(), "status=400") {
		t.Fatalf("log omitted status: %q", logs.String())
	}
}
