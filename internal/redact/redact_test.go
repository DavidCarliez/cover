package redact

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

// fakeContextDetector records whether the context it was called with carries
// a deadline, so tests can verify llmBudget propagation.
type fakeContextDetector struct {
	sawDeadline bool
}

func (d *fakeContextDetector) Name() string { return "fake_ctx" }

func (d *fakeContextDetector) Detect(text string) []detectors.Match {
	return d.DetectWithContext(context.Background(), text)
}

func (d *fakeContextDetector) DetectWithContext(ctx context.Context, text string) []detectors.Match {
	if _, ok := ctx.Deadline(); ok {
		d.sawDeadline = true
	}
	return nil
}

func newTestRedactor(t *testing.T) *Redactor {
	t.Helper()
	d, err := detectors.NewRegexDetector([]string{"aws_access_key", "email"}, nil)
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}
	return New(NewStore(), 0, RedactorOptions{}, d)
}

func TestRedact_JSONRoundTrip(t *testing.T) {
	r := newTestRedactor(t)

	// Keys are listed alphabetically since json.Marshal sorts map keys on
	// re-serialization; this keeps the raw-string round-trip comparison below valid.
	body := `{"messages":[{"content":"my key is AKIAIOSFODNN7EXAMPLE, email alice@example.com","role":"user"}]}`

	redacted, categories := r.Redact([]byte(body))

	if strings.Contains(string(redacted), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("redacted body still contains secret: %s", redacted)
	}
	if strings.Contains(string(redacted), "alice@example.com") {
		t.Errorf("redacted body still contains email: %s", redacted)
	}

	wantCats := map[string]bool{"aws_access_key": true, "email": true}
	for _, c := range categories {
		if !wantCats[c] {
			t.Errorf("unexpected category %q", c)
		}
		delete(wantCats, c)
	}
	if len(wantCats) != 0 {
		t.Errorf("missing expected categories: %v", wantCats)
	}

	// Redacted body should still be valid JSON.
	var v any
	if err := json.Unmarshal(redacted, &v); err != nil {
		t.Fatalf("redacted body is not valid JSON: %v", err)
	}

	restored := r.Restore(redacted)
	if string(restored) != body {
		t.Errorf("restore mismatch:\n got: %s\nwant: %s", restored, body)
	}
}

func TestRedact_NonJSONText(t *testing.T) {
	r := newTestRedactor(t)

	body := "my key is AKIAIOSFODNN7EXAMPLE"
	redacted, categories := r.Redact([]byte(body))

	if strings.Contains(string(redacted), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("redacted body still contains secret: %s", redacted)
	}
	if len(categories) != 1 || categories[0] != "aws_access_key" {
		t.Errorf("unexpected categories: %v", categories)
	}

	restored := r.Restore(redacted)
	if string(restored) != body {
		t.Errorf("restore mismatch:\n got: %s\nwant: %s", restored, body)
	}
}

func TestRedact_SameValueSamePlaceholder(t *testing.T) {
	r := newTestRedactor(t)

	body := `{"a":"AKIAIOSFODNN7EXAMPLE","b":"AKIAIOSFODNN7EXAMPLE"}`
	redacted, _ := r.Redact([]byte(body))

	var obj map[string]string
	if err := json.Unmarshal(redacted, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if obj["a"] != obj["b"] {
		t.Errorf("expected same placeholder for identical values, got %q and %q", obj["a"], obj["b"])
	}
}

func TestRedact_ContextDetectorReceivesBudgetDeadline(t *testing.T) {
	fake := &fakeContextDetector{}
	r := New(NewStore(), 4*time.Second, RedactorOptions{}, fake)

	r.Redact([]byte(`{"a":"hello"}`))

	if !fake.sawDeadline {
		t.Errorf("expected ContextDetector to receive a context with a deadline when llmBudget > 0")
	}
}

func TestRedact_ContextDetectorNoDeadlineWithoutBudget(t *testing.T) {
	fake := &fakeContextDetector{}
	r := New(NewStore(), 0, RedactorOptions{}, fake)

	r.Redact([]byte(`{"a":"hello"}`))

	if fake.sawDeadline {
		t.Errorf("expected no deadline on context when llmBudget == 0")
	}
}

func TestRedact_SkipsProtocolFields(t *testing.T) {
	r := newTestRedactor(t)

	secret := "AKIAIOSFODNN7EXAMPLE"
	body := `{
		"model": "claude-` + secret + `",
		"tools": [{"type": "custom", "custom": {"name": "` + secret + `_tool"}}],
		"messages": [{"role": "user", "content": "my key is ` + secret + `"}]
	}`

	redacted, categories := r.Redact([]byte(body))

	var obj map[string]any
	if err := json.Unmarshal(redacted, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got := obj["model"]; got != "claude-"+secret {
		t.Errorf("model field was modified: got %q", got)
	}

	tools := obj["tools"].([]any)
	custom := tools[0].(map[string]any)["custom"].(map[string]any)
	if got := custom["name"]; got != secret+"_tool" {
		t.Errorf("tools[].custom.name was modified: got %q", got)
	}

	msg := obj["messages"].([]any)[0].(map[string]any)
	if strings.Contains(msg["content"].(string), secret) {
		t.Errorf("message content was not redacted: got %q", msg["content"])
	}

	if len(categories) != 1 || categories[0] != "aws_access_key" {
		t.Errorf("expected exactly one aws_access_key category, got %v", categories)
	}
}

func TestRedact_NoMatches(t *testing.T) {
	r := newTestRedactor(t)

	body := `{"messages":[{"content":"hello world","role":"user"}]}`
	redacted, categories := r.Redact([]byte(body))

	if string(redacted) != body {
		t.Errorf("expected unchanged body, got %s", redacted)
	}
	if len(categories) != 0 {
		t.Errorf("expected no categories, got %v", categories)
	}
}
