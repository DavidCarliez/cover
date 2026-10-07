package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

const leakMarker = "SEKRETVALUE42"

func keyAliasRule(keys ...string) FieldRule { return aliasKeyRule("key", keys...) }

func formAliasRule(fields ...string) FieldRule {
	return FieldRule{Name: "form", FormFields: fields, Action: string(ActionPseudonymize), Generator: "alias", Priority: 100}
}

func queryAliasRule(params ...string) FieldRule {
	return FieldRule{Name: "query", QueryParams: params, Action: string(ActionPseudonymize), Generator: "alias", Priority: 100}
}

func headerAliasRule(headers ...string) FieldRule {
	return FieldRule{Name: "header", Headers: headers, Action: string(ActionPseudonymize), Generator: "alias", Priority: 100}
}

// assertContentProtected sends text as a tool-output string and requires that
// the transform succeeds and leakMarker is gone.
func assertContentProtected(t *testing.T, r *Redactor, text string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"input": text})
	result, err := r.Transform(body, "s", false, "allow")
	if err != nil {
		t.Fatalf("transform rejected %q: %v", text, err)
	}
	out := decodePolicyJSON(t, result.Body).(map[string]any)["input"].(string)
	if strings.Contains(out, leakMarker) {
		t.Fatalf("leaked in %q", out)
	}
	return out
}

func TestHTTPSurroundingTextReceivesStructuredPolicies(t *testing.T) {
	for name, tc := range map[string]struct {
		rule FieldRule
		text string
	}{
		"JSON before request":            {keyAliasRule("password"), "Result: {\"password\":\"" + leakMarker + "\"}\nGET / HTTP/1.1\nHost: x\n"},
		"JSON text/plain body":           {keyAliasRule("password"), "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n{\"password\":\"" + leakMarker + "\"}"},
		"form after zero Content-Length": {formAliasRule("password"), "POST /login HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 0\n\npassword=" + leakMarker},
		"JSON after short Content-Length": {keyAliasRule("password"),
			"POST /x HTTP/1.1\nContent-Type: application/json\nContent-Length: 2\n\n{}\n{\"password\":\"" + leakMarker + "\"}"},
	} {
		t.Run(name, func(t *testing.T) {
			assertContentProtected(t, structuredPolicyRedactor(tc.rule), tc.text)
		})
	}
}

func TestNamedSelectorsProtectAssignmentsInFreeText(t *testing.T) {
	for name, tc := range map[string]struct {
		rule FieldRule
		text string
	}{
		"JSON fence inside prose":     {keyAliasRule("password"), "Here is the output:\n```json\n{\"password\":\"" + leakMarker + "\"}\n```\nDone."},
		"JSON after prose prefix":     {keyAliasRule("password"), "note {\"password\":\"" + leakMarker + "\"}"},
		"second JSON document":        {keyAliasRule("password"), "Result: {\"a\":1} {\"password\":\"" + leakMarker + "\"}"},
		"curl output":                 {keyAliasRule("password"), "$ curl https://api\n{\"password\":\"" + leakMarker + "\"}"},
		"YAML":                        {keyAliasRule("password"), "db:\n  user: app\n  password: " + leakMarker + "\n"},
		"env file":                    {keyAliasRule("password"), "export PASSWORD=\"" + leakMarker + "\"\n"},
		"CLI flag":                    {keyAliasRule("password"), "mysql --password=" + leakMarker + " -h db"},
		"python dict":                 {keyAliasRule("password"), "cfg = {'password': '" + leakMarker + "'}"},
		"escaped JSON value":          {keyAliasRule("password"), `log {"password":"a\"` + leakMarker + `"} end`},
		"query parameter in prose":    {queryAliasRule("token"), "open https://x.example/cb?a=1&token=" + leakMarker + " now"},
		"form field in prose":         {formAliasRule("client_secret"), "sent grant_type=x&client_secret=" + leakMarker + " ok"},
		"header in log line":          {headerAliasRule("Authorization"), "2026-01-01 request Authorization: Bearer " + leakMarker + "\nnext"},
		"header in curl command":      {headerAliasRule("Authorization"), "curl -sH 'Authorization: Bearer " + leakMarker + "' https://x.example"},
		"cookie assignment in prose":  {FieldRule{Name: "c", Cookies: []string{"session"}, Action: "pseudonymize", Generator: "alias", Priority: 1}, "browser sent session=" + leakMarker + "; theme=dark"},
		"number generator, text form": {FieldRule{Name: "n", Keys: []string{"customer_number"}, Action: "pseudonymize", Generator: "number", Priority: 1}, "customer_number: " + leakMarker},
	} {
		t.Run(name, func(t *testing.T) {
			assertContentProtected(t, structuredPolicyRedactor(tc.rule), tc.text)
		})
	}
}

func TestFreeTextAssignmentsKeepUnrelatedProse(t *testing.T) {
	r := structuredPolicyRedactor(keyAliasRule("password"))
	for _, text := range []string{
		"Reset your password before Friday.",
		"password_hint: blue",
		"mypassword=abc",
		"password: true",
		"password = os.getenv(\"DB_PASSWORD\")",
		"PASSWORD=$DB_PASSWORD ./run.sh",
		"password = null",
	} {
		body, _ := json.Marshal(map[string]string{"input": text})
		result, err := r.Transform(body, "s", false, "allow")
		if err != nil {
			t.Fatalf("rejected %q: %v", text, err)
		}
		if got := decodePolicyJSON(t, result.Body).(map[string]any)["input"]; got != text {
			t.Errorf("changed %q to %q", text, got)
		}
	}
}

func TestFreeTextAssignmentRoundTripsEscapedValue(t *testing.T) {
	r := structuredPolicyRedactor(keyAliasRule("password"))
	text := `log {"password":"a\"b` + leakMarker + `"} end`
	out := assertContentProtected(t, r, text)
	restored := string(r.RestoreForSession([]byte(out), "s"))
	if restored != text {
		t.Fatalf("restored %q, want %q", restored, text)
	}
}
