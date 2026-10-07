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
