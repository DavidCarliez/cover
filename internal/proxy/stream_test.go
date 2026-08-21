package proxy

import (
	"bytes"
	"testing"

	"github.com/DavidCarliez/cover/internal/redact"
	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func TestRestoringWriter_SplitAcrossWrites(t *testing.T) {
	d, err := detectors.NewRegexDetector([]string{"aws_access_key"}, nil)
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}
	redactor := redact.New(redact.NewStore(), 0, redact.RedactorOptions{}, d)

	const secret = "AKIAIOSFODNN7EXAMPLE"
	redactedBytes, _ := redactor.Redact([]byte(secret))
	placeholder := string(redactedBytes)
	if placeholder == secret {
		t.Fatalf("expected secret to be replaced with a placeholder, got %q", placeholder)
	}

	data := []byte("prefix " + placeholder + " suffix")
	want := "prefix " + secret + " suffix"

	// Try every possible split point to make sure a placeholder split across
	// two Write calls is always restored correctly.
	for split := 0; split <= len(data); split++ {
		var buf bytes.Buffer
		rw := NewRestoringWriter(&buf, redactor)
		if _, err := rw.Write(data[:split]); err != nil {
			t.Fatalf("Write 1: %v", err)
		}
		if _, err := rw.Write(data[split:]); err != nil {
			t.Fatalf("Write 2: %v", err)
		}
		if err := rw.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if buf.String() != want {
			t.Errorf("split=%d: got %q, want %q", split, buf.String(), want)
		}
	}
}

func TestRestoringWriter_UnknownPlaceholderPassesThrough(t *testing.T) {
	d, err := detectors.NewRegexDetector([]string{"aws_access_key"}, nil)
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}
	redactor := redact.New(redact.NewStore(), 0, redact.RedactorOptions{}, d)

	input := "no secrets here ⟦RG:deadbeef⟧ end"
	var buf bytes.Buffer
	rw := NewRestoringWriter(&buf, redactor)
	if _, err := rw.Write([]byte(input)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := rw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if buf.String() != input {
		t.Errorf("got %q, want unchanged %q", buf.String(), input)
	}
}
