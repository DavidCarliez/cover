package redact

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func TestRestoreResponse_JSONEscapesQuotes(t *testing.T) {
	d, err := detectors.NewRegexDetector([]string{"generic_api_key_assignment"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := New(NewStore(), 0, RedactorOptions{}, d)

	secret := `api_key = "anasbdn198h291ebkhjabsdbbasbd"`
	placeholder := r.store.PlaceholderFor(secret)

	body := []byte(`{"type":"content_block_delta","delta":{"type":"text_delta","text":"yes ` + placeholder + `"}}`)
	restored := r.RestoreResponse(body, "application/json")

	var v map[string]any
	if err := json.Unmarshal(restored, &v); err != nil {
		t.Fatalf("restored body is not valid JSON: %v\n%s", err, restored)
	}

	delta := v["delta"].(map[string]any)
	text := delta["text"].(string)
	if !strings.Contains(text, secret) {
		t.Fatalf("expected restored secret in text, got %q", text)
	}
}

func TestRestoreResponseDoesNotAlterEncryptedContent(t *testing.T) {
	r := newTestRedactor(t)
	secret := "customer@example.com"
	redacted, _ := r.Redact([]byte(secret))
	fake := string(redacted)
	body, err := json.Marshal(map[string]any{
		"output_text":       fake,
		"encrypted_content": fake,
	})
	if err != nil {
		t.Fatal(err)
	}
	restored := r.RestoreResponse(body, "application/json")
	var got map[string]any
	if err := json.Unmarshal(restored, &got); err != nil {
		t.Fatal(err)
	}
	if got["output_text"] != secret {
		t.Fatalf("normal response text was not restored: %q", got["output_text"])
	}
	if got["encrypted_content"] != fake {
		t.Fatalf("encrypted_content was altered: %q", got["encrypted_content"])
	}
}

func TestRestoreSSEEvent_JSONEscapesQuotes(t *testing.T) {
	d, err := detectors.NewRegexDetector([]string{"generic_api_key_assignment"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := New(NewStore(), 0, RedactorOptions{}, d)

	secret := `api_key = "anasbdn198h291ebkhjabsdbbasbd"`
	placeholder := r.store.PlaceholderFor(secret)

	event := []byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"" + placeholder + "\"}}\n\n")
	restored := r.RestoreSSEEvent(event)

	if !json.Valid(bytesTrimToDataJSON(restored)) {
		t.Fatalf("restored SSE data is not valid JSON: %s", restored)
	}
	var payload map[string]any
	if err := json.Unmarshal(bytesTrimToDataJSON(restored), &payload); err != nil {
		t.Fatal(err)
	}
	delta := payload["delta"].(map[string]any)
	if delta["text"] != secret {
		t.Fatalf("expected restored secret in text, got %q", delta["text"])
	}
}

func TestRestoreSSEEventPreservesCRLF(t *testing.T) {
	r := newTestRedactor(t)
	secret := "customer@example.com"
	redacted, _ := r.Redact([]byte(secret))
	fake := string(redacted)
	payload, err := json.Marshal(map[string]string{"text": fake})
	if err != nil {
		t.Fatal(err)
	}
	event := append([]byte("event: message\r\ndata: "), payload...)
	event = append(event, []byte("\r\n\r\n")...)

	restored := r.RestoreSSEEvent(event)
	if strings.Contains(strings.ReplaceAll(string(restored), "\r\n", ""), "\n") {
		t.Fatalf("introduced a bare LF: %q", restored)
	}
	if !strings.HasSuffix(string(restored), "\r\n\r\n") {
		t.Fatalf("lost CRLF event terminator: %q", restored)
	}
	var got map[string]string
	if err := json.Unmarshal(bytesTrimToDataJSON(restored), &got); err != nil {
		t.Fatal(err)
	}
	if got["text"] != secret {
		t.Fatalf("text=%q, want %q", got["text"], secret)
	}
}

func bytesTrimToDataJSON(event []byte) []byte {
	for _, line := range strings.Split(string(event), "\n") {
		if strings.HasPrefix(line, "data:") {
			return []byte(strings.TrimSpace(line[5:]))
		}
	}
	return nil
}
