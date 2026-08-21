package redact

import (
	"testing"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func benchRedactor(b *testing.B) *Redactor {
	d, err := detectors.NewRegexDetector(detectors.BuiltinCategories(), nil)
	if err != nil {
		b.Fatalf("NewRegexDetector: %v", err)
	}
	return New(NewStore(), 0, RedactorOptions{
		Cache: NewDetectionCache(10000),
	}, d)
}

func BenchmarkRedact_SmallChat(b *testing.B) {
	r := benchRedactor(b)
	body := benchFixtures.SmallChat
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Redact(body)
	}
}

func BenchmarkRedact_Chat20Msg(b *testing.B) {
	r := benchRedactor(b)
	body := benchFixtures.Chat20Msg
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Redact(body)
	}
}

func BenchmarkRedact_LargeSystem(b *testing.B) {
	r := benchRedactor(b)
	body := benchFixtures.LargeSystem
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Redact(body)
	}
}

func BenchmarkRedact_NoMatch(b *testing.B) {
	r := benchRedactor(b)
	body := benchFixtures.NoMatch
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Redact(body)
	}
}

func BenchmarkRedact_WithSecrets(b *testing.B) {
	r := benchRedactor(b)
	body := benchFixtures.WithSecrets
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Redact(body)
	}
}

func BenchmarkRedact_Chat20Msg_Cached(b *testing.B) {
	r := benchRedactor(b)
	body := benchFixtures.Chat20Msg
	// Warm cache.
	r.Redact(body)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Redact(body)
	}
}
