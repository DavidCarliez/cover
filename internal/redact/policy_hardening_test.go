package redact

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func policyRedactor(t *testing.T, rules ...detectors.CustomPattern) *Redactor {
	t.Helper()
	d, err := detectors.NewRegexDetector(nil, rules)
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}
	return New(NewStore(), 0, RedactorOptions{}, d)
}

func transformText(t *testing.T, r *Redactor, session, text string) (string, TransformResult) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"text": text})
	result, err := r.Transform(body, session, false, "allow")
	if err != nil {
		t.Fatalf("Transform: %v", err)
	}
	var out map[string]string
	if err := json.Unmarshal(result.Body, &out); err != nil {
		t.Fatal(err)
	}
	return out["text"], result
}

func TestPseudonymGeneratorsAreReversible(t *testing.T) {
	tests := []struct{ name, generator, value, pattern string }{
		{"ipv4", "ipv4", "10.20.30.40", `\b(?:\d{1,3}\.){3}\d{1,3}\b`},
		{"ipv6", "ipv6", "2001:db8::1234", `[0-9A-Fa-f:]{2,39}`},
		{"hostname", "hostname", "server01", `server01`},
		{"domain", "domain", "server01.bank.internal", `[a-z0-9.-]+\.internal`},
		{"email", "email", "john.smith@bank.example", `[a-z.]+@[a-z.]+`},
		{"username", "username", "john.smith", `john\.smith`},
		{"password", "password", "secret-password-123", `secret-password-123`},
		{"uuid", "uuid", "550e8400-e29b-41d4-a716-446655440000", `[0-9a-f-]{36}`},
		{"url", "url", "https://10.20.30.40:8443/a?q=1", `https://[^\s]+`},
		{"alias", "alias", "SECRET_PROJECT", `SECRET_PROJECT`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := policyRedactor(t, detectors.CustomPattern{Name: tc.name, Pattern: tc.pattern, Action: "pseudonymize", Generator: tc.generator})
			fake, result := transformText(t, r, "s1", tc.value)
			if fake == tc.value {
				t.Fatalf("value was not changed")
			}
			if result.Transformed != 1 {
				t.Fatalf("Transformed=%d", result.Transformed)
			}
			restored := string(r.RestoreForSession([]byte(fake), "s1"))
			if restored != tc.value {
				t.Fatalf("restored=%q want=%q", restored, tc.value)
			}
			fake2, _ := transformText(t, r, "s1", tc.value)
			if fake2 != fake {
				t.Fatalf("mapping is not stable: %q != %q", fake2, fake)
			}
		})
	}
}

func TestFieldRulePseudonymizesPasswordValuesByJSONKey(t *testing.T) {
	r := New(NewStore(), 0, RedactorOptions{FieldRules: []FieldRule{{
		Name:      "password_fields",
		Keys:      []string{"password", "passwd", "pwd", "passphrase"},
		Category:  "password",
		Action:    "pseudonymize",
		Generator: "password",
		Priority:  220,
	}}})
	payload := []byte(`{"password":"admin","nested":{"PWD":"x","passphrase":"correct horse battery staple"},"username":"admin","password_hint":"admin"}`)
	result, err := r.Transform(payload, "password-session", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	if result.Transformed != 3 {
		t.Fatalf("Transformed=%d, want 3: %s", result.Transformed, result.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(result.Body, &got); err != nil {
		t.Fatal(err)
	}
	if got["password"] == "admin" || got["username"] != "admin" || got["password_hint"] != "admin" {
		t.Fatalf("unexpected top-level transformation: %#v", got)
	}
	nested := got["nested"].(map[string]any)
	if nested["PWD"] == "x" || nested["passphrase"] == "correct horse battery staple" {
		t.Fatalf("nested password fields were not transformed: %#v", nested)
	}
	restored := r.RestoreResponseForSession(result.Body, "application/json", "password-session")
	var want, roundTrip any
	if err := json.Unmarshal(payload, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(restored, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(roundTrip) != fmt.Sprint(want) {
		t.Fatalf("restore mismatch\nwant=%v\ngot=%v", want, roundTrip)
	}
}

func TestFieldRulePriorityAndCaseSensitivity(t *testing.T) {
	r := New(NewStore(), 0, RedactorOptions{FieldRules: []FieldRule{
		{Name: "lower", Keys: []string{"password"}, Action: "block", Priority: 10, CaseSensitive: true},
		{Name: "fallback", Keys: []string{"password"}, Action: "pseudonymize", Generator: "password", Priority: 1},
	}})
	result, err := r.Transform([]byte(`{"password":"one","PASSWORD":"two"}`), "s", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Blocked || result.Transformed != 2 {
		t.Fatalf("unexpected field-rule result: %+v %s", result, result.Body)
	}
}

func TestNamedCaptureAndActions(t *testing.T) {
	rules := []detectors.CustomPattern{
		{Name: "password", Pattern: `password=(?P<value>[^\s]+)`, Category: "credential", Action: "pseudonymize", Generator: "password", Priority: 10},
		{Name: "mask", Pattern: `ACCT-[0-9]+`, Action: "mask"},
		{Name: "redact", Pattern: `CUSTOMER-[A-Z]+`, Action: "redact"},
		{Name: "allow", Pattern: `PUBLIC-[A-Z]+`, Action: "allow", Priority: 100},
		{Name: "block", Pattern: `APIKEY-[A-Z0-9]+`, Action: "block"},
	}
	r := policyRedactor(t, rules...)
	got, result := transformText(t, r, "s", "password=Secret123 ACCT-123456 CUSTOMER-ALPHA PUBLIC-DEMO APIKEY-XYZ")
	if !strings.HasPrefix(got, "password=") || strings.Contains(got, "Secret123") {
		t.Errorf("named capture failed: %q", got)
	}
	if !strings.Contains(got, "AC**") || !strings.Contains(got, "[REDACTED]") {
		t.Errorf("mask/redact failed: %q", got)
	}
	if !strings.Contains(got, "PUBLIC-DEMO") {
		t.Errorf("allow changed value: %q", got)
	}
	if !strings.Contains(got, "[BLOCKED]") || !result.Blocked {
		t.Errorf("block failed: %q %+v", got, result)
	}
	if strings.Contains(string(r.RestoreForSession([]byte(got), "s")), "CUSTOMER-ALPHA") {
		t.Error("redacted value was retained for restoration")
	}
}

func TestAllowPrioritySuppressesBlock(t *testing.T) {
	r := policyRedactor(t,
		detectors.CustomPattern{Name: "block", Pattern: `SAFE-[A-Z]+`, Action: "block", Priority: 1},
		detectors.CustomPattern{Name: "allow", Pattern: `SAFE-DEMO`, Action: "allow", Priority: 100},
	)
	got, result := transformText(t, r, "s", "SAFE-DEMO")
	if got != "SAFE-DEMO" || result.Blocked {
		t.Fatalf("higher priority allow did not win: %q %+v", got, result)
	}
}

func TestCollisionAndDuplicateHandling(t *testing.T) {
	const original = "10.20.30.40"
	fake0, err := generateReplacement("ipv4", original, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := policyRedactor(t, detectors.CustomPattern{Name: "ip", Pattern: `\b(?:\d{1,3}\.){3}\d{1,3}\b`, Action: "pseudonymize", Generator: "ipv4"})
	body, _ := json.Marshal(map[string]any{"targets": []string{original, original, fake0}})
	result, err := r.Transform(body, "s", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string][]string
	if err := json.Unmarshal(result.Body, &out); err != nil {
		t.Fatal(err)
	}
	if out["targets"][0] != out["targets"][1] {
		t.Error("duplicate originals received different fakes")
	}
	if out["targets"][0] == fake0 {
		t.Error("generated fake collided with a genuine input value")
	}
	if out["targets"][2] == fake0 {
		t.Error("third value should itself be pseudonymized")
	}
}

type failingDetector struct{ panic bool }

func (d failingDetector) Name() string                    { return "failing" }
func (d failingDetector) Detect(string) []detectors.Match { return nil }
func (d failingDetector) DetectE(string) ([]detectors.Match, error) {
	return nil, errors.New("secret value")
}

type panicDetector struct{}

func (panicDetector) Name() string                    { return "panic" }
func (panicDetector) Detect(string) []detectors.Match { panic("secret value") }

type invalidSpanDetector struct{}

func (invalidSpanDetector) Name() string { return "invalid" }
func (invalidSpanDetector) Detect(string) []detectors.Match {
	return []detectors.Match{{Value: "secret", Start: -1, End: 6}}
}

func TestFailClosedErrors(t *testing.T) {
	r := New(NewStore(), 0, RedactorOptions{}, failingDetector{})
	if _, err := r.Transform([]byte(`{"text":"x"}`), "s", false, "allow"); !errors.Is(err, ErrUnsafeRequest) {
		t.Fatalf("detector error=%v", err)
	}
	r = New(NewStore(), 0, RedactorOptions{}, panicDetector{})
	if _, err := r.Transform([]byte(`{"text":"x"}`), "s", false, "allow"); !errors.Is(err, ErrUnsafeRequest) {
		t.Fatalf("detector panic error=%v", err)
	}
	r = New(NewStore(), 0, RedactorOptions{}, invalidSpanDetector{})
	if _, err := r.Transform([]byte(`{"text":"secret"}`), "s", false, "allow"); !errors.Is(err, ErrUnsafeRequest) {
		t.Fatalf("invalid span error=%v", err)
	}
	if _, err := r.Transform([]byte(`{"text":`), "s", false, "allow"); !errors.Is(err, ErrMalformedJSON) {
		t.Fatalf("malformed error=%v", err)
	}
	r = policyRedactor(t, detectors.CustomPattern{Name: "bad_url", Pattern: `not-a-url`, Action: "pseudonymize", Generator: "url"})
	if _, err := r.Transform([]byte(`{"text":"not-a-url"}`), "s", false, "allow"); !errors.Is(err, ErrUnsafeRequest) {
		t.Fatalf("generator error=%v", err)
	}
}

func TestTestDataLabelCannotBypassPolicy(t *testing.T) {
	r := policyRedactor(t, detectors.CustomPattern{Name: "key", Pattern: `APIKEY-[A-Z0-9]+`, Action: "block"})
	_, result := transformText(t, r, "s", "synthetic data APIKEY-SECRET123")
	if !result.Blocked {
		t.Fatal("test-data wording bypassed a block rule")
	}
}

func TestProtocolPayloadsAndNestedToolArguments(t *testing.T) {
	const secret = "SECRET_PROJECT"
	r := policyRedactor(t, detectors.CustomPattern{Name: "project", Pattern: secret, Action: "pseudonymize", Generator: "alias"})
	payloads := []string{
		`{"model":"SECRET_PROJECT","instructions":"SECRET_PROJECT","input":[{"role":"user","content":"SECRET_PROJECT"}],"arguments":"{\"target\":\"SECRET_PROJECT\"}","output":"SECRET_PROJECT","metadata":{"customer":"SECRET_PROJECT"}}`,
		`{"messages":[{"role":"system","content":"SECRET_PROJECT"},{"role":"assistant","tool_calls":[{"id":"SECRET_PROJECT","function":{"name":"SECRET_PROJECT","arguments":"{\"x\":\"SECRET_PROJECT\"}"}}]},{"role":"tool","content":"SECRET_PROJECT"}]}`,
		`{"system":"SECRET_PROJECT","messages":[{"role":"user","content":[{"type":"tool_use","name":"SECRET_PROJECT","input":{"host":"SECRET_PROJECT"}},{"type":"tool_result","content":"SECRET_PROJECT"}]}]}`,
	}
	for i, payload := range payloads {
		result, err := r.Transform([]byte(payload), fmt.Sprintf("s%d", i), false, "allow")
		if err != nil {
			t.Fatalf("payload %d: %v", i, err)
		}
		var got any
		if err := json.Unmarshal(result.Body, &got); err != nil {
			t.Fatal(err)
		}
		// Structural identifiers remain untouched, so at least model/name/id may contain the marker.
		if result.Transformed < 3 {
			t.Errorf("payload %d transformed only %d text fields: %s", i, result.Transformed, result.Body)
		}
		restored := r.RestoreResponseForSession(result.Body, "application/json", fmt.Sprintf("s%d", i))
		var want, round any
		json.Unmarshal([]byte(payload), &want)
		json.Unmarshal(restored, &round)
		if fmt.Sprint(want) != fmt.Sprint(round) {
			t.Errorf("payload %d restore mismatch\nwant=%v\ngot=%v", i, want, round)
		}
	}
}

func TestSessionsAreIsolatedAndConcurrent(t *testing.T) {
	r := policyRedactor(t, detectors.CustomPattern{Name: "project", Pattern: `PROJECT-[A-Z]+`, Action: "pseudonymize", Generator: "alias"})
	fakeA, _ := transformText(t, r, "A", "PROJECT-ALPHA")
	if got := string(r.RestoreForSession([]byte(fakeA), "B")); got != fakeA {
		t.Fatalf("session B restored session A mapping: %q", got)
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); transformText(t, r, fmt.Sprintf("session-%d", i), "PROJECT-ALPHA") }(i)
	}
	wg.Wait()
}

func TestMappingCleanupAndBounds(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewStoreWithOptions(StoreOptions{MaxSessions: 2, MaxEntriesPerSession: 1, SessionTTL: time.Minute, Now: func() time.Time { return now }})
	if _, err := s.PlaceholderForSession("a", "one", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PlaceholderForSession("a", "two", nil); err == nil {
		t.Fatal("expected per-session capacity error")
	}
	if _, err := s.PlaceholderForSession("b", "one", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PlaceholderForSession("c", "one", nil); err == nil {
		t.Fatal("expected session capacity error")
	}
	now = now.Add(2 * time.Minute)
	if sessions, entries := s.SessionStats(); sessions != 0 || entries != 0 {
		t.Fatalf("expired mappings remain: %d/%d", sessions, entries)
	}
}

func TestMediaPolicy(t *testing.T) {
	r := policyRedactor(t)
	body := []byte(`{"input":[{"type":"input_image","image_url":"https://example.com/screenshot.png"}]}`)
	blocked, err := r.Transform(body, "s", false, "block")
	if err != nil || !blocked.Blocked {
		t.Fatalf("image was not blocked: %+v %v", blocked, err)
	}
	warned, err := r.Transform(body, "s", false, "warn")
	if err != nil || warned.Blocked || len(warned.Warnings) == 0 {
		t.Fatalf("image warn policy failed: %+v %v", warned, err)
	}
}

func TestFakeSplitAcrossEveryBoundary(t *testing.T) {
	r := policyRedactor(t, detectors.CustomPattern{Name: "ip", Pattern: `10\.20\.30\.40`, Action: "pseudonymize", Generator: "ipv4"})
	fake, _ := transformText(t, r, "s", "10.20.30.40")
	for split := 0; split <= len(fake); split++ {
		buf := []byte(fake[:split] + fake[split:])
		if got := string(r.RestoreForSession(buf, "s")); got != "10.20.30.40" {
			t.Fatalf("split=%d got=%q", split, got)
		}
	}
}

func TestCaseInsensitiveDisabledRule(t *testing.T) {
	f := false
	r := policyRedactor(t, detectors.CustomPattern{Name: "keyword", Pattern: `secret_project`, CaseSensitive: &f, Action: "redact"})
	got, _ := transformText(t, r, "s", "SECRET_PROJECT")
	if got != "[REDACTED]" {
		t.Fatalf("case-insensitive rule got %q", got)
	}
}
