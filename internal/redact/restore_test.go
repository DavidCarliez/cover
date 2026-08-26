package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func TestRestoreResponsePreservesUnchangedJSONBytes(t *testing.T) {
	r := New(NewStore(), 0, RedactorOptions{})
	body := []byte(" \n { \"large\" : 9007199254740993, \"text\" : \"unchanged\" } \n")
	if restored := r.RestoreResponse(body, "application/json"); !bytes.Equal(restored, body) {
		t.Fatalf("unchanged response was rewritten:\n got: %q\nwant: %q", restored, body)
	}

	// An existing session mapping must not cause unrelated responses to be
	// normalized or re-encoded.
	_ = r.store.PlaceholderFor("customer@example.com")
	if restored := r.RestoreResponse(body, "application/json"); !bytes.Equal(restored, body) {
		t.Fatalf("unrelated response was rewritten:\n got: %q\nwant: %q", restored, body)
	}
}

func TestRestoreResponsePreservesEncryptedOnlyJSONExactly(t *testing.T) {
	r := newTestRedactor(t)
	fake := r.store.PlaceholderFor("customer@example.com")
	body := []byte(fmt.Sprintf(" { \"encrypted_content\" : %q, \"sequence\" : 9007199254740993 } ", fake))
	if restored := r.RestoreResponse(body, "application/json"); !bytes.Equal(restored, body) {
		t.Fatalf("encrypted-only response was rewritten:\n got: %q\nwant: %q", restored, body)
	}
}

func TestRestoreResponsePreservesLargeJSONNumbersWhenRestoring(t *testing.T) {
	r := newTestRedactor(t)
	secret := "customer@example.com"
	redacted, _ := r.Redact([]byte(secret))
	body := []byte(fmt.Sprintf(`{"sequence_number":9007199254740993,"text":%q}`, redacted))

	restored := r.RestoreResponse(body, "application/json")
	if !bytes.Contains(restored, []byte(`"sequence_number":9007199254740993`)) {
		t.Fatalf("large integer changed during restoration: %s", restored)
	}
	var got map[string]any
	dec := json.NewDecoder(bytes.NewReader(restored))
	dec.UseNumber()
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["text"] != secret {
		t.Fatalf("text=%q, want %q", got["text"], secret)
	}
}

func TestRestoreResponseSupportsTopLevelJSONString(t *testing.T) {
	r := newTestRedactor(t)
	secret := `api_key = "anasbdn198h291ebkhjabsdbbasbd"`
	fake := r.store.PlaceholderFor(secret)
	body, err := json.Marshal(fake)
	if err != nil {
		t.Fatal(err)
	}
	restored := r.RestoreResponse(body, "application/json")
	var got string
	if err := json.Unmarshal(restored, &got); err != nil {
		t.Fatalf("restored scalar is invalid JSON: %v: %s", err, restored)
	}
	if got != secret {
		t.Fatalf("got %q, want %q", got, secret)
	}
}

func TestRestorationSnapshotInvalidatesWhenMappingIsAdded(t *testing.T) {
	r := New(NewStore(), 0, RedactorOptions{})
	first := r.store.PlaceholderFor("first-secret")
	if got := string(r.Restore([]byte(first))); got != "first-secret" {
		t.Fatalf("first restoration=%q", got)
	}

	second := r.store.PlaceholderFor("second-secret")
	if got := string(r.Restore([]byte(first + "/" + second))); got != "first-secret/second-secret" {
		t.Fatalf("snapshot was not invalidated: %q", got)
	}
}

func TestRestorationSnapshotSupportsConcurrentReadsAndInvalidation(t *testing.T) {
	r := New(NewStore(), 0, RedactorOptions{})
	first := r.store.PlaceholderFor("first-secret")
	_ = r.Restore([]byte(first)) // Build the first snapshot before concurrency.

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			r.store.PlaceholderFor(fmt.Sprintf("new-secret-%d", i))
		}
	}()
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				if got := string(r.Restore([]byte(first))); got != "first-secret" {
					t.Errorf("concurrent restoration=%q", got)
					return
				}
			}
		}()
	}
	wg.Wait()
}

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
