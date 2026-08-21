package redact

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func TestIsTestDataContext(t *testing.T) {
	if isTestDataContext("my key is AKIAIOSFODNN7EXAMPLE, email alice@example.com") {
		t.Fatal("should not treat AWS EXAMPLE suffix or email domain as test disclaimer")
	}
	if !isTestDataContext("This is test data with key AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("expected explicit test data disclaimer")
	}
}

func TestRedact_TestDataContextExemptsSecrets(t *testing.T) {
	d, err := detectors.NewRegexDetector([]string{"aws_access_key", "ssn"}, nil)
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}
	r := New(NewStore(), 0, RedactorOptions{}, d)

	body := []byte(`{"messages":[{"role":"user","content":"This is test data. AWS key AKIAIOSFODNN7EXAMPLE and SSN 123-45-6789."}]}`)
	redacted, categories := r.Redact(body)
	out := string(redacted)

	if !strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("expected test-labeled AWS key to pass through unchanged")
	}
	if strings.Contains(out, "123-45-6789") {
		t.Fatal("expected SSN to be redacted even in test context")
	}
	if len(categories) != 1 || categories[0] != "ssn" {
		t.Fatalf("expected only ssn category, got %v", categories)
	}
}

func TestRedact_TestDataContextDoesNotExemptWithoutDisclaimer(t *testing.T) {
	d, err := detectors.NewRegexDetector([]string{"aws_access_key"}, nil)
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}
	r := New(NewStore(), 0, RedactorOptions{}, d)

	body := []byte(`{"messages":[{"role":"user","content":"AWS key AKIAIOSFODNN7EXAMPLE"}]}`)
	redacted, categories := r.Redact(body)
	if strings.Contains(string(redacted), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("expected AWS key to be redacted without test disclaimer")
	}
	if len(categories) != 1 {
		t.Fatalf("expected one category, got %v", categories)
	}
}

func TestRedact_TestDataContextExemptsLLMSensitive(t *testing.T) {
	llm := &stubLLM{value: "Project Bluefin"}
	d, err := detectors.NewRegexDetector([]string{"aws_access_key"}, nil)
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}
	r := New(NewStore(), time.Second, RedactorOptions{}, d, llm)

	body := []byte(`{"messages":[{"role":"user","content":"This is just an example. Project Bluefin and key AKIAIOSFODNN7EXAMPLE."}]}`)
	redacted, categories := r.Redact(body)
	out := string(redacted)
	if !strings.Contains(out, "Project Bluefin") {
		t.Fatal("expected LLM-labeled content to pass through in test context")
	}
	if !strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("expected test-labeled AWS key to pass through")
	}
	if len(categories) != 0 {
		t.Fatalf("expected no redactions, got categories %v", categories)
	}
}

type stubLLM struct {
	value string
}

func (s *stubLLM) Name() string { return "stub" }

func (s *stubLLM) Detect(text string) []detectors.Match {
	return s.DetectWithContext(nil, text)
}

func (s *stubLLM) DetectWithContext(_ context.Context, text string) []detectors.Match {
	if !strings.Contains(text, s.value) {
		return nil
	}
	i := strings.Index(text, s.value)
	return []detectors.Match{{
		Category: "llm_sensitive",
		Value:    s.value,
		Start:    i,
		End:      i + len(s.value),
	}}
}
