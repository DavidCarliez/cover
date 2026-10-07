package redact

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func passwordKeyRedactor() *Redactor {
	return structuredPolicyRedactor(FieldRule{
		Name: "password_fields", Keys: []string{"password"}, Category: "password",
		Action: string(ActionPseudonymize), Generator: "password", Priority: 220,
	})
}

func mustTransform(t *testing.T, r *Redactor, session string, body []byte) TransformResult {
	t.Helper()
	result, err := r.Transform(body, session, false, "allow")
	if err != nil {
		t.Fatalf("transform %s: %v", body, err)
	}
	return result
}

func TestKnownValueProtectedOnLaterTurnAfterRestoration(t *testing.T) {
	r := passwordKeyRedactor()
	const secret = "Hunter2Hunter2"

	first := mustTransform(t, r, "request-1", []byte(`{"input":[{"type":"function_call_output","output":"{\"password\":\"`+secret+`\"}"}]}`))
	if strings.Contains(string(first.Body), secret) {
		t.Fatalf("first turn leaked: %s", first.Body)
	}
	var fake string
	for _, part := range strings.Split(string(first.Body), `\"`) {
		if len(part) >= 12 && !strings.ContainsAny(part, `:{}[] `) {
			fake = part
		}
	}
	if fake == "" {
		t.Fatalf("no fake in %s", first.Body)
	}
	restored := string(r.RestoreResponseForSession([]byte(`{"text":"your password is `+fake+`"}`), "application/json", "request-1"))
	if !strings.Contains(restored, secret) {
		t.Fatalf("response was not restored: %s", restored)
	}
	r.EndSession("request-1")

	// The next turn carries the restored prose in history, without the
	// selected key, in a new ephemeral session.
	second := mustTransform(t, r, "request-2", []byte(`{"messages":[{"role":"assistant","content":"your password is `+secret+`"}]}`))
	if strings.Contains(string(second.Body), secret) {
		t.Fatalf("later turn leaked restored value: %s", second.Body)
	}
	if !strings.Contains(string(second.Body), fake) {
		t.Fatalf("later turn did not reuse the deterministic fake %q: %s", fake, second.Body)
	}
	back := string(r.RestoreResponseForSession(second.Body, "application/json", "request-2"))
	if !strings.Contains(back, "your password is "+secret) {
		t.Fatalf("later turn did not round trip: %s", back)
	}
}

func TestKnownValueProtectedInStringsVisitedBeforeItsKey(t *testing.T) {
	r := passwordKeyRedactor()
	const secret = "Hunter2Hunter2"
	body := []byte(`{"a_note":"log in with ` + secret + `","password":"` + secret + `","z":"mysql -p` + secret + `"}`)
	result := mustTransform(t, r, "s", body)
	if strings.Contains(string(result.Body), secret) {
		t.Fatalf("leaked: %s", result.Body)
	}
	got := decodePolicyJSON(t, result.Body).(map[string]any)
	fake := got["password"].(string)
	if got["a_note"] != "log in with "+fake {
		t.Fatalf("a_note=%q, want fake %q", got["a_note"], fake)
	}
	if got["z"] != "mysql -p"+fake {
		t.Fatalf("z=%q, want fake %q", got["z"], fake)
	}
	if result.Transformed != 3 {
		t.Fatalf("Transformed=%d, want 3", result.Transformed)
	}
}

func TestKnownValueProtectedInEscapedForms(t *testing.T) {
	r := passwordKeyRedactor()
	const secret = `p@ss"w/rd&<x>!`
	selected, _ := json.Marshal(map[string]string{"password": secret})
	mustTransform(t, r, "s", selected)

	jsonEscaped := strings.Trim(string(must(json.Marshal(secret))), `"`)
	for name, text := range map[string]string{
		"raw":   "plain " + secret + " text",
		"json":  `log line {"pw":"` + jsonEscaped + `"} trailing prose`,
		"query": "see postgres://app:" + url.QueryEscape(secret) + "@db.internal/app",
		"path":  "GET /login/" + url.PathEscape(secret),
		"html":  "<p>password: p@ss&#34;w/rd&amp;&lt;x&gt;!</p> and more",
	} {
		body, _ := json.Marshal(map[string]string{"text": text})
		result := mustTransform(t, r, "s", body)
		out := decodePolicyJSON(t, result.Body).(map[string]any)["text"].(string)
		for _, form := range []string{secret, jsonEscaped, url.QueryEscape(secret), url.PathEscape(secret), "p@ss&#34;w/rd&amp;&lt;x&gt;!", "p@ss"} {
			if strings.Contains(out, form) {
				t.Errorf("%s: leaked %q in %q", name, form, out)
			}
		}
	}
}

func TestShortKnownValueOnlyMatchesWholeWords(t *testing.T) {
	r := passwordKeyRedactor()
	mustTransform(t, r, "s", []byte(`{"password":"admin"}`))
	result := mustTransform(t, r, "s", []byte(`{"a":"administrator","b":"badmin","c":"login admin now","d":"adm"}`))
	got := decodePolicyJSON(t, result.Body).(map[string]any)
	if got["a"] != "administrator" || got["b"] != "badmin" || got["d"] != "adm" {
		t.Fatalf("partial words changed: %#v", got)
	}
	if strings.Contains(got["c"].(string), "admin") {
		t.Fatalf("whole-word password leaked: %#v", got)
	}

	// Values shorter than the minimum are never swept.
	mustTransform(t, r, "s", []byte(`{"password":"abc"}`))
	result = mustTransform(t, r, "s", []byte(`{"a":"abc def"}`))
	if got := decodePolicyJSON(t, result.Body).(map[string]any)["a"]; got != "abc def" {
		t.Fatalf("value below minimum length changed: %q", got)
	}
}

func TestKnownNumericValueProtectedInUnselectedNumbersAndProse(t *testing.T) {
	r := structuredPolicyRedactor(FieldRule{
		Name: "customer", Keys: []string{"customer_number"}, Category: "customer",
		Action: string(ActionPseudonymize), Generator: "number", Priority: 100,
	})
	first := mustTransform(t, r, "s", []byte(`{"customer_number":48213377}`))
	if strings.Contains(string(first.Body), "48213377") {
		t.Fatalf("leaked: %s", first.Body)
	}
	result := mustTransform(t, r, "s", []byte(`{"ref":48213377,"max_tokens":4821,"text":"customer 48213377 called; order 148213377"}`))
	got := decodePolicyJSON(t, result.Body).(map[string]any)
	if got["ref"] == json.Number("48213377") {
		t.Fatalf("unselected numeric copy leaked: %s", result.Body)
	}
	if got["max_tokens"] != json.Number("4821") {
		t.Fatalf("short unrelated number changed: %s", result.Body)
	}
	text := got["text"].(string)
	if strings.Contains(text, "customer 48213377") || !strings.Contains(text, "order 148213377") {
		t.Fatalf("prose number handling: %q", text)
	}
	restored := string(r.RestoreResponseForSession(result.Body, "application/json", "s"))
	if !strings.Contains(restored, `"ref":48213377`) || !strings.Contains(restored, "customer 48213377 called") {
		t.Fatalf("numeric round trip failed: %s", restored)
	}
}

func TestNumericAliasLeftInHistoryDoesNotRejectSession(t *testing.T) {
	r := structuredPolicyRedactor(FieldRule{
		Name: "account", Keys: []string{"account_id"}, Category: "account",
		Action: string(ActionPseudonymize), Generator: "number", Priority: 100,
	})
	first := mustTransform(t, r, "s", []byte(`{"account_id":555123}`))
	fake := decodePolicyJSON(t, first.Body).(map[string]any)["account_id"].(json.Number).String()
	// A client kept the alias in its history and sends the account again.
	second := mustTransform(t, r, "s", []byte(`{"history":"Account `+fake+` is active","account_id":555123}`))
	if strings.Contains(string(second.Body), "555123") {
		t.Fatalf("leaked: %s", second.Body)
	}
}

func TestKnownValueOverridesAllowedSpanButNotAllowedField(t *testing.T) {
	r := structuredPolicyRedactor(
		FieldRule{Name: "password_fields", Keys: []string{"password"}, Action: string(ActionPseudonymize), Generator: "password", Priority: 220},
		FieldRule{Name: "public_note", Keys: []string{"public_note"}, Action: string(ActionAllow), Priority: 300},
	)
	mustTransform(t, r, "s", []byte(`{"password":"Hunter2Hunter2"}`))
	result := mustTransform(t, r, "s", []byte(`{"public_note":"Hunter2Hunter2","other":"Hunter2Hunter2"}`))
	got := decodePolicyJSON(t, result.Body).(map[string]any)
	if got["public_note"] != "Hunter2Hunter2" {
		t.Fatalf("explicitly allowed field changed: %#v", got)
	}
	if got["other"] == "Hunter2Hunter2" {
		t.Fatalf("unselected copy leaked: %#v", got)
	}
}

func TestKnownValuesExpireAndEvict(t *testing.T) {
	now := time.Unix(0, 0)
	known := newKnownValues(10, time.Hour, func() time.Time { return now })
	template := detectors.Match{Rule: "r", Action: string(ActionRedact)}
	if !known.remember("first-value", template) || known.remember("first-value", template) {
		t.Fatal("remember did not report new values exactly once")
	}
	if known.remember("abc", template) || known.remember("    ", template) {
		t.Fatal("short or blank values were remembered")
	}
	now = now.Add(2 * time.Hour)
	if known.current() != nil {
		t.Fatal("expired value is still protected")
	}
	for i := range 25 {
		now = now.Add(time.Second)
		known.remember(fmt.Sprintf("value-%02d", i), template)
	}
	if len(known.values) > 10 {
		t.Fatalf("known values exceed capacity: %d", len(known.values))
	}
	if _, ok := known.values["value-24"]; !ok {
		t.Fatal("newest value was evicted")
	}
	if matches := known.current().matches("x value-24 y"); len(matches) != 1 || matches[0].Value != "value-24" {
		t.Fatalf("matches=%+v", matches)
	}
}

func TestCachedKnownValuesStillExpire(t *testing.T) {
	now := time.Unix(0, 0)
	known := newKnownValues(10, time.Hour, func() time.Time { return now })
	known.remember("first-value", detectors.Match{Rule: "r", Action: string(ActionRedact)})
	if known.current().matches("first-value") == nil {
		t.Fatal("value is not protected")
	}
	// Nothing new is remembered, so only expiry can drop the cached matcher.
	now = now.Add(2 * time.Hour)
	if snapshot := known.current(); snapshot != nil {
		t.Fatalf("expired value is still protected: %+v", snapshot.matches("first-value"))
	}
	if len(known.values) != 0 {
		t.Fatalf("expired value is still retained: %d", len(known.values))
	}
}

func TestOverlappingKnownValuesExposeNoProtectedByte(t *testing.T) {
	rule := func(name string, action Action) FieldRule {
		generator := ""
		if action == ActionPseudonymize {
			generator = "secret"
		}
		return FieldRule{Name: name, Keys: []string{name}, Category: name, Action: string(action), Generator: generator, Priority: 220}
	}
	for _, together := range []bool{true, false} {
		r := structuredPolicyRedactor(rule("a", ActionPseudonymize), rule("b", ActionPseudonymize))
		if together {
			// Learned in one request, both values share one matcher.
			mustTransform(t, r, "s", []byte(`{"a":"alpha-secret-1","b":"secret-1-betaTAIL"}`))
		} else {
			mustTransform(t, r, "s", []byte(`{"a":"alpha-secret-1"}`))
			r.store.known.current()
			mustTransform(t, r, "s", []byte(`{"b":"secret-1-betaTAIL"}`))
		}
		out := mustTransform(t, r, "s", []byte(`{"messages":[{"role":"user","content":"x alpha-secret-1-betaTAIL y"}]}`))
		for _, part := range []string{"alpha", "secret-1", "betaTAIL"} {
			if strings.Contains(string(out.Body), part) {
				t.Fatalf("together=%v: overlapping values exposed %q: %s", together, part, out.Body)
			}
		}
	}

	r := structuredPolicyRedactor(rule("a", ActionPseudonymize), rule("b", ActionBlock))
	if res, _ := r.Transform([]byte(`{"a":"prefix-BLOCKME99-suffix","b":"BLOCKME99"}`), "s", false, "allow"); !res.Blocked {
		t.Fatal("selected block value did not block")
	}
	for _, text := range []string{"x prefix-BLOCKME99-suffix y", "x BLOCKME99 y"} {
		body := []byte(`{"messages":[{"role":"user","content":"` + text + `"}]}`)
		if res := mustTransform(t, r, "s", body); !res.Blocked {
			t.Fatalf("blocked value inside %q did not block: %s", text, res.Body)
		}
	}
}

func TestOverlappingKnownValuesOfOneRuleShareOneFake(t *testing.T) {
	r := passwordKeyRedactor()
	mustTransform(t, r, "s", []byte(`{"password":"alpha-secret-1","x":{"password":"secret-1-beta"}}`))
	out := mustTransform(t, r, "s", []byte(`{"messages":[{"role":"user","content":"x alpha-secret-1-beta y"}]}`))
	content := decodePolicyJSON(t, out.Body).(map[string]any)["messages"].([]any)[0].(map[string]any)["content"].(string)
	if strings.Contains(content, "secret") || strings.Count(content, " ") != 2 {
		t.Fatalf("content=%q", content)
	}
	back := string(r.RestoreResponseForSession(out.Body, "application/json", "s"))
	if !strings.Contains(back, "x alpha-secret-1-beta y") {
		t.Fatalf("merged span did not restore: %s", back)
	}
}

func TestKnownValueInsideWordRestoresExactly(t *testing.T) {
	for _, tc := range []struct{ generator, original, later string }{
		{"hostname", "dbprimary01", "restore dbprimary01_backup.sql"},
		{"hostname", "dbprimary01", "ssh xdbprimary01y"},
		{"hostname", "dbprimary01", "other host dbprimary012"},
		{"ipv4", "10.20.30.40", "host 10.20.30.40x"},
		{"ipv4", "10.20.30.40", "other host 10.20.30.401"},
	} {
		r := structuredPolicyRedactor(FieldRule{
			Name: "sel", Keys: []string{"sel"}, Category: "sel",
			Action: string(ActionPseudonymize), Generator: tc.generator, Priority: 220,
		})
		mustTransform(t, r, "s", []byte(`{"sel":"`+tc.original+`"}`))
		out := mustTransform(t, r, "s", []byte(`{"messages":[{"role":"user","content":"`+tc.later+`"}]}`))
		if strings.Contains(string(out.Body), tc.original) {
			t.Fatalf("%s: leaked: %s", tc.later, out.Body)
		}
		// The model echoes the request text unchanged.
		back := decodePolicyJSON(t, r.RestoreResponseForSession(out.Body, "application/json", "s"))
		got := back.(map[string]any)["messages"].([]any)[0].(map[string]any)["content"]
		if got != tc.later {
			t.Errorf("%s generator: restored %q, want %q", tc.generator, got, tc.later)
		}
	}

	// At a word boundary the generator's fake is still used.
	r := structuredPolicyRedactor(FieldRule{
		Name: "sel", Keys: []string{"sel"}, Category: "sel",
		Action: string(ActionPseudonymize), Generator: "hostname", Priority: 220,
	})
	first := mustTransform(t, r, "s", []byte(`{"sel":"dbprimary01"}`))
	fake := decodePolicyJSON(t, first.Body).(map[string]any)["sel"].(string)
	out := mustTransform(t, r, "s", []byte(`{"messages":[{"role":"user","content":"ssh dbprimary01 now"}]}`))
	if !strings.Contains(string(out.Body), "ssh "+fake+" now") {
		t.Fatalf("boundary occurrence did not use fake %q: %s", fake, out.Body)
	}
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}
