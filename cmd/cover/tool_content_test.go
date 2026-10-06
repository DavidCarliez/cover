package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/DavidCarliez/cover/internal/config"
	"github.com/DavidCarliez/cover/internal/proxy"
)

func TestConfiguredHTTPSelectorsProtectToolOutputEndToEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	policy := `rules:
  json:
    keys: [password]
    action: pseudonymize
    generator: alias
  authorization:
    headers: [Authorization]
    action: pseudonymize
    generator: alias
  session:
    cookies: [session]
    action: pseudonymize
    generator: alias
  ticket:
    query_params: [ticket]
    action: pseudonymize
    generator: alias
  form:
    form_fields: [credential]
    action: pseudonymize
    generator: alias
`
	if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Pseudonymization.KeyFile = filepath.Join(t.TempDir(), "pseudonym.key")
	r, cleanup, err := buildRedactor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	forwardedBodies := make(chan []byte, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		captured, _ := io.ReadAll(req.Body)
		forwardedBodies <- captured
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(captured)
	}))
	defer upstream.Close()
	p, err := proxy.New(upstream.URL, r, nil, proxy.Options{})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(p)
	defer front.Close()
	formBody := "credential=birch-private%2Bsuffix&public=ok"
	transcript := "POST /submit?ticket=cedar-private%26scope%3Done%2Ftwo%3Fx%3Dy&public=ok HTTP/1.1\r\n" +
		"Host: example.invalid\r\nAuthorization: Bearer maple-private\r\n" +
		"Cookie: session=willow-private; theme=dark\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " + strconv.Itoa(len(formBody)) + "\r\n\r\n" + formBody
	body, _ := json.Marshal(map[string]any{"input": []any{map[string]any{"type": "function_call_output", "call_id": "sample", "output": transcript}}})
	response, err := http.Post(front.URL+"/responses", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	got, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.StatusCode, got)
	}
	var forwarded []byte
	select {
	case forwarded = <-forwardedBodies:
	default:
		t.Fatal("the valid tool result did not reach upstream")
	}
	for _, original := range []string{"cedar-private", "maple-private", "willow-private", "birch-private"} {
		if bytes.Contains(forwarded, []byte(original)) {
			t.Fatalf("selected HTTP value leaked upstream: %s", original)
		}
		if !bytes.Contains(got, []byte(original)) {
			t.Fatalf("selected HTTP value was not restored: %s", original)
		}
	}
	if !strings.Contains(string(forwarded), "public=ok") || !strings.Contains(string(forwarded), "theme=dark") {
		t.Fatal("unselected HTTP fields were lost")
	}
	var restored struct {
		Input []struct {
			Output string `json:"output"`
		} `json:"input"`
	}
	if err := json.Unmarshal(got, &restored); err != nil {
		t.Fatal(err)
	}
	if len(restored.Input) != 1 || restored.Input[0].Output != transcript {
		t.Fatalf("restoration changed URL/form boundaries or HTTP framing: %s", got)
	}
	for name, content := range map[string]string{
		"malformed JSON": `{"` + "pass" + `word":"cedar-private"`,
		"truncated HTTP": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 99\r\n\r\n{}",
		"encoded HTTP":   "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n\r\ncompressed bytes",
	} {
		t.Run(name, func(t *testing.T) {
			requestBody, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "tool", "content": content}}})
			blocked, err := http.Post(front.URL+"/chat/completions", "application/json", bytes.NewReader(requestBody))
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Body.Close()
			errorBody, err := io.ReadAll(blocked.Body)
			if err != nil {
				t.Fatal(err)
			}
			select {
			case leaked := <-forwardedBodies:
				t.Fatalf("unsafe tool content reached upstream: %s", leaked)
			default:
			}
			if blocked.StatusCode != http.StatusUnprocessableEntity {
				t.Fatalf("unsafe tool content was not blocked: status=%d", blocked.StatusCode)
			}
			if bytes.Contains(errorBody, []byte("cedar-private")) {
				t.Fatal("blocked content leaked into the error response")
			}
		})
	}
}
