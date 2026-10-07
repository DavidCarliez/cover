package redact

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

var fuzzContentSeeds = []string{
	"",
	"plain prose",
	"GET /path?a=b HTTP/1.1\nHost: x\nCookie: a=b; c=d\n\n",
	"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
	"POST /login HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 3\n\na=b",
	"curl -sH 'X-Key: v' -d 'a=b' https://x.example/?q=1",
	"$ curl https://x.example | jq .",
	"Result: {\"a\":1}",
	"```json\n{\"a\":[1,2]}\n```",
	"https://x.example/a/b?c=d&e#f=g",
	"a=b&c=d",
	"db:\n  password: x\n",
	"--b\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n--b--",
}

const fuzzSecret = "Zq8Kw3Lp9Xv2Rt"

func fuzzPolicyRedactor(tb testing.TB) *Redactor {
	tb.Helper()
	d, err := detectors.NewRegexDetector(detectors.BuiltinCategories(), nil)
	if err != nil {
		tb.Fatal(err)
	}
	return New(NewStore(), 0, RedactorOptions{FieldRules: []FieldRule{
		{Name: "password", Keys: []string{"password"}, Action: string(ActionPseudonymize), Generator: "password", Priority: 220},
		{Name: "token", QueryParams: []string{"token"}, Action: string(ActionPseudonymize), Generator: "secret", Priority: 200},
		{Name: "session", Cookies: []string{"session"}, Action: string(ActionPseudonymize), Generator: "alias", Priority: 200},
		{Name: "auth", Headers: []string{"Authorization"}, Action: string(ActionPseudonymize), Generator: "secret", Priority: 200},
		{Name: "client_secret", FormFields: []string{"client_secret"}, Action: string(ActionPseudonymize), Generator: "secret", Priority: 200},
	}}, d)
}

// A value that a rule protected once is never forwarded again, wherever it
// appears in surrounding text, unless the request is rejected. JSON property
// names and HTML markup are outside the protected surface, so the generated
// context excludes quotes and angle brackets.
func FuzzKnownValueNeverLeaks(f *testing.F) {
	for _, seed := range fuzzContentSeeds {
		f.Add(seed, "")
		f.Add("", seed)
	}
	r := fuzzPolicyRedactor(f)
	if _, err := r.Transform([]byte(`{"password":"`+fuzzSecret+`"}`), "seed", false, "allow"); err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, prefix, suffix string) {
		if strings.ContainsAny(prefix+suffix, `"<`) {
			t.Skip()
		}
		body, err := json.Marshal(map[string]string{"input": prefix + " " + fuzzSecret + " " + suffix})
		if err != nil {
			t.Skip()
		}
		result, err := r.Transform(body, "fuzz", false, "allow")
		if err != nil {
			return
		}
		if strings.Contains(string(result.Body), fuzzSecret) {
			t.Fatalf("protected value leaked: %s", result.Body)
		}
	})
}

// Parsers that change nothing return their input byte for byte, so content
// that holds no protected value is forwarded unchanged.
func FuzzHTTPContentPreservesUnchangedBytes(f *testing.F) {
	for _, seed := range fuzzContentSeeds {
		f.Add(seed)
	}
	identity := func(value string) (string, error) { return value, nil }
	policy := httpContentPolicy{
		Transform:  func(_, _, value string) (string, error) { return value, nil },
		JSON:       identity,
		HTML:       identity,
		Text:       identity,
		HasHeaders: true, HasCookies: true, HasQuery: true, HasForm: true, HasJSON: true,
	}
	f.Fuzz(func(t *testing.T, text string) {
		output, handled, err := protectHTTPContent(text, policy)
		if err != nil {
			if output != "" {
				t.Fatalf("failed content returned output %q", output)
			}
			return
		}
		if output != text {
			t.Fatalf("handled=%v changed %q to %q", handled, text, output)
		}
	})
}

// Transforming never panics and its errors never contain request content.
func FuzzTransformErrorsAreGeneric(f *testing.F) {
	for _, seed := range fuzzContentSeeds {
		f.Add(seed)
	}
	r := fuzzPolicyRedactor(f)
	f.Fuzz(func(t *testing.T, text string) {
		body, err := json.Marshal(map[string]string{"input": text})
		if err != nil {
			t.Skip()
		}
		if _, err := r.Transform(body, "fuzz", false, "allow"); err != nil && len(text) >= 4 && strings.Contains(err.Error(), text) {
			t.Fatalf("error %q contains request content", err)
		}
	})
}
