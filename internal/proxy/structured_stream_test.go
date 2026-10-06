package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DavidCarliez/cover/internal/redact"
)

type chunkedProofTransport struct {
	base      http.RoundTripper
	encodings chan []string
}

func (t chunkedProofTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err == nil {
		t.encodings <- append([]string(nil), response.TransferEncoding...)
	}
	return response, err
}

func TestChunkedJSONProviderRestoresNumericAndNestedValues(t *testing.T) {
	r := redact.New(redact.NewStore(), 0, redact.RedactorOptions{FieldRules: []redact.FieldRule{{
		Name: "customer_number", Keys: []string{"customer_number"}, Action: "pseudonymize", Generator: "number",
	}}})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var fields map[string]json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&fields); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fake := string(fields["customer_number"])
		if fake == "937165" || !json.Valid([]byte(fake)) {
			t.Error("selected numeric field was not protected")
		}
		arguments := `{"customer_number":` + fake + `}`
		body, _ := json.Marshal(map[string]any{"customer_number": json.RawMessage(fake), "arguments": arguments})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for _, value := range body {
			_, _ = w.Write([]byte{value})
			w.(http.Flusher).Flush()
		}
	}))
	defer upstream.Close()
	p, err := New(upstream.URL, r, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	base := p.client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	encodings := make(chan []string, 1)
	p.client.Transport = chunkedProofTransport{base: base, encodings: encodings}
	front := httptest.NewServer(p)
	defer front.Close()
	response, err := http.Post(front.URL+"/chat/completions", "application/json", strings.NewReader(`{"customer_number":937165}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
	if got := <-encodings; len(got) != 1 || got[0] != "chunked" {
		t.Fatalf("provider did not use actual chunked transport: %v", got)
	}
	var restored struct {
		Number    json.Number `json:"customer_number"`
		Arguments string      `json:"arguments"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&restored); err != nil {
		t.Fatal(err)
	}
	if restored.Number.String() != "937165" || restored.Arguments != `{"customer_number":937165}` {
		t.Fatalf("numeric restoration failed across chunk boundaries: %s", body)
	}
}
