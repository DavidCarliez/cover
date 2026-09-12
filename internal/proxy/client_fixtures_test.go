package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

// Synthetic protocol fixtures, not recordings of private conversations.
// Harnesses can use different providers; names identify the tested profiles.
func TestClientConversationFixtures(t *testing.T) {
	for _, profile := range []string{"codex", "pi", "omp"} {
		t.Run(profile, func(t *testing.T) {
			for _, stream := range []bool{false, true} {
				t.Run(fmt.Sprint("stream=", stream), func(t *testing.T) {
					fixture, err := os.ReadFile("testdata/" + profile + ".json")
					if err != nil {
						t.Fatal(err)
					}
					var pngData bytes.Buffer
					if err := png.Encode(&pngData, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
						t.Fatal(err)
					}
					encodedImage := base64.StdEncoding.EncodeToString(pngData.Bytes())
					fixture = bytes.ReplaceAll(fixture, []byte("YWJj"), []byte(encodedImage))
					var request map[string]any
					json.Unmarshal(fixture, &request)
					key := "messages"
					if profile == "codex" {
						key = "input"
					}
					// Include enough history to exercise repeated mappings, not just one turn.
					history := request[key].([]any)
					for i := 0; i < 200; i++ {
						history = append(history, map[string]any{"role": "user", "content": "client-private@example.com"})
					}
					request[key] = history
					request["stream"] = stream
					fixture, _ = json.Marshal(request)
					received := make(chan []byte, 1)
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						body, _ := io.ReadAll(r.Body)
						received <- body
						fake := regexp.MustCompile(`⟦RG:[a-f0-9]+⟧`).FindString(string(body))
						args, _ := json.Marshal(map[string]string{"customer": fake})
						if !stream {
							w.Header().Set("Content-Type", "application/json")
							switch profile {
							case "codex":
								json.NewEncoder(w).Encode(map[string]any{"output": []any{map[string]any{"type": "function_call", "name": "list_files", "arguments": string(args)}}})
							case "pi":
								json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"tool_calls": []any{map[string]any{"function": map[string]string{"name": "list_files", "arguments": string(args)}}}}}}})
							case "omp":
								json.NewEncoder(w).Encode(map[string]any{"content": []any{map[string]any{"type": "tool_use", "name": "list_files", "input": map[string]string{"customer": fake}}}})
							}
							return
						}
						w.Header().Set("Content-Type", "text/event-stream")
						split := len(fake) / 2
						makeEvent := func(text string, n int) string {
							switch profile {
							case "codex":
								return sseDeltaEvent("response.output_text.delta", text, n)
							case "pi":
								data, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]string{"content": text}}}})
								return "data: " + string(data) + "\n\n"
							default:
								data, _ := json.Marshal(map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]string{"type": "text_delta", "text": text}})
								return "data: " + string(data) + "\n\n"
							}
						}
						io.WriteString(w, makeEvent(fake[:split], 1))
						w.(http.Flusher).Flush()
						io.WriteString(w, ": keepalive\n\n"+makeEvent(fake[split:], 2)+"data: [DONE]\n\n")
					}))
					defer upstream.Close()
					redactor := policyProxyRedactor(t, detectors.CustomPattern{Name: "customer", Pattern: `client-private@example\.com`, Action: "placeholder"})
					proxy, _ := New(upstream.URL, redactor, nil, Options{})
					front := httptest.NewServer(proxy)
					defer front.Close()
					endpoint := "/v1/chat/completions"
					if profile == "codex" {
						endpoint = "/responses"
					}
					if profile == "omp" {
						endpoint = "/v1/messages"
					}
					resp, err := http.Post(front.URL+endpoint, "application/json", bytes.NewReader(fixture))
					if err != nil {
						t.Fatal(err)
					}
					defer resp.Body.Close()
					result, err := io.ReadAll(resp.Body)
					if err != nil {
						t.Fatal(err)
					}
					outbound := <-received
					if bytes.Contains(outbound, []byte("client-private@example.com")) {
						t.Fatal("private text reached provider")
					}
					if !bytes.Contains(outbound, []byte(encodedImage)) {
						t.Fatal("image payload changed")
					}
					if profile == "codex" && !bytes.Contains(outbound, []byte("opaque-test-bytes")) {
						t.Fatal("reasoning payload changed")
					}
					if resp.StatusCode != 200 || !bytes.Contains(result, []byte("client-private@example.com")) {
						t.Fatalf("roundtrip failed: %d %s", resp.StatusCode, result)
					}
					if stream {
						sseJSONPayloads(t, string(result))
						if !strings.HasSuffix(string(result), "data: [DONE]\n\n") {
							t.Fatal("stream completion lost")
						}
					} else {
						if !json.Valid(result) {
							t.Fatal("response invalid")
						}
						var decoded any
						json.Unmarshal(result, &decoded)
						checkNestedArguments(t, decoded)
					}
				})
			}
		})
	}
}

func checkNestedArguments(t *testing.T, v any) {
	t.Helper()
	switch value := v.(type) {
	case map[string]any:
		for key, item := range value {
			if key == "arguments" {
				text, ok := item.(string)
				if !ok || !json.Valid([]byte(text)) {
					t.Fatal("invalid tool arguments")
				}
			}
			checkNestedArguments(t, item)
		}
	case []any:
		for _, item := range value {
			checkNestedArguments(t, item)
		}
	}
}
