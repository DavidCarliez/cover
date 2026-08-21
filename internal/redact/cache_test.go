package redact

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func TestDetectionCache_HitReturnsSameResult(t *testing.T) {
	d, err := detectors.NewRegexDetector([]string{"aws_access_key"}, nil)
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}
	cache := NewDetectionCache(100)
	r := New(NewStore(), 0, RedactorOptions{Cache: cache}, d)

	body := []byte(`{"messages":[{"role":"user","content":"key AKIAIOSFODNN7EXAMPLE"}]}`)
	first, cats1 := r.Redact(body)
	second, cats2 := r.Redact(body)

	if string(first) != string(second) {
		t.Fatalf("cache hit mismatch:\n first=%s\nsecond=%s", first, second)
	}
	if len(cats1) != len(cats2) {
		t.Fatalf("categories mismatch: %v vs %v", cats1, cats2)
	}
}

func TestRedact_UnchangedBodyByteIdentical(t *testing.T) {
	r := newTestRedactor(t)
	body := []byte(`{"messages":[{"content":"hello world","role":"user"}]}`)
	redacted, categories := r.Redact(body)
	if string(redacted) != string(body) {
		t.Errorf("expected unchanged body, got %s", redacted)
	}
	if len(categories) != 0 {
		t.Errorf("expected no categories, got %v", categories)
	}
}

func TestRedactForProxy_InjectsGuardNote(t *testing.T) {
	r := newTestRedactor(t)
	body := []byte(`{"messages":[{"role":"user","content":"key AKIAIOSFODNN7EXAMPLE"}]}`)
	redacted, categories := r.RedactForProxy(body)
	if len(categories) == 0 {
		t.Fatal("expected categories")
	}
	if !strings.Contains(string(redacted), "[Cover]") {
		t.Fatalf("expected guard note in body: %s", redacted)
	}
}

func TestRedact_SkipLLMIfRegexMatched(t *testing.T) {
	calls := 0
	llm := &countingLLM{calls: &calls}
	d, err := detectors.NewRegexDetector([]string{"aws_access_key"}, nil)
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}
	r := New(NewStore(), time.Second, RedactorOptions{SkipLLMIfRegexMatched: true}, d, llm)

	body := []byte(`{"messages":[{"role":"user","content":"key AKIAIOSFODNN7EXAMPLE and Project Bluefin"}]}`)
	r.Redact(body)
	if calls != 0 {
		t.Errorf("expected LLM skipped after regex match, got %d calls", calls)
	}
}

type countingLLM struct {
	calls *int
}

func (c *countingLLM) Name() string { return "counting" }

func (c *countingLLM) Detect(text string) []detectors.Match {
	return c.DetectWithContext(nil, text)
}

func (c *countingLLM) DetectWithContext(_ context.Context, text string) []detectors.Match {
	*c.calls++
	idx := strings.Index(text, "Project Bluefin")
	if idx < 0 {
		return nil
	}
	return []detectors.Match{{Category: "llm_sensitive", Value: "Project Bluefin", Start: idx, End: idx + len("Project Bluefin")}}
}
