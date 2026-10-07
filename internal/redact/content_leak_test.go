package redact

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
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

func TestCurlCommandsProtectEveryCredentialForm(t *testing.T) {
	d, err := detectors.NewRegexDetector([]string{"aws_access_key"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	akia := "AKIA" + "IOSFODNN7EXAMPLE"
	for name, tc := range map[string]struct {
		rule   FieldRule
		text   string
		secret string
	}{
		"combined short flags": {headerAliasRule("Authorization"), "curl -sSH 'Authorization: Bearer " + leakMarker + "' https://x.example", leakMarker},
		"basic auth user":      {headerAliasRule("Authorization"), "curl -u admin:" + leakMarker + " https://x.example", leakMarker},
		"oauth2 bearer":        {headerAliasRule("Authorization"), "curl --oauth2-bearer " + leakMarker + " https://x.example", leakMarker},
		"multipart form field": {formAliasRule("password"), "curl -F 'password=" + leakMarker + "' https://x.example", leakMarker},
		"get with data":        {queryAliasRule("token"), "curl -G -d 'token=" + leakMarker + "' https://x.example", leakMarker},
		"uppercase scheme":     {queryAliasRule("token"), "curl 'HTTPS://x.example/?token=" + leakMarker + "'", leakMarker},
		"header without colon": {FieldRule{}, "curl -H 'X-Key " + akia + "' https://x.example", akia},
		"shell pipeline":       {headerAliasRule("Authorization"), "curl -s -H 'Authorization: Bearer " + leakMarker + "' https://x.example | jq .", leakMarker},
		"dynamic word":         {headerAliasRule("Authorization"), "curl -H \"Authorization: Bearer " + leakMarker + "\" \"$BASE/x\"", leakMarker},
		// Commands the curl parser cannot rewrite keep their credentials
		// protected through the plain-text net.
		"piped basic auth":       {headerAliasRule("Authorization"), "curl -u admin:" + leakMarker + " https://x.example | jq .", leakMarker},
		"piped oauth2 bearer":    {headerAliasRule("Authorization"), "curl --oauth2-bearer " + leakMarker + " https://x.example | jq .", leakMarker},
		"piped attached user":    {headerAliasRule("Authorization"), "curl -uadmin:" + leakMarker + " https://x.example && echo ok", leakMarker},
		"piped combined flags":   {headerAliasRule("Authorization"), "curl -sSu 'admin:" + leakMarker + "' https://x.example | jq .", leakMarker},
		"piped long equals form": {headerAliasRule("Authorization"), "curl --user=\"admin:" + leakMarker + "\" https://x.example | jq .", leakMarker},
		"piped proxy user":       {headerAliasRule("Authorization"), "curl -U proxy:" + leakMarker + " https://x.example | jq .", leakMarker},
		"script continuation":    {headerAliasRule("Authorization"), "#!/bin/sh\nset -e\ncurl -s \\\n  -u admin:" + leakMarker + " \\\n  https://x.example | jq .\n", leakMarker},
		"command in prose":       {headerAliasRule("Authorization"), "Run `curl -u admin:" + leakMarker + " https://x.example` to check.", leakMarker},
	} {
		t.Run(name, func(t *testing.T) {
			var rules []FieldRule
			if tc.rule.Name != "" {
				rules = append(rules, tc.rule)
			}
			r := New(NewStore(), 0, RedactorOptions{FieldRules: rules}, d)
			body, _ := json.Marshal(map[string]string{"input": tc.text})
			result, err := r.Transform(body, "s", false, "allow")
			if err != nil {
				t.Fatalf("rejected %q: %v", tc.text, err)
			}
			if strings.Contains(string(result.Body), tc.secret) {
				t.Fatalf("leaked: %s", result.Body)
			}
			restored := string(r.RestoreForSession(result.Body, "s"))
			if !strings.Contains(restored, tc.secret) {
				t.Fatalf("did not restore: %s", restored)
			}
		})
	}
}

func TestCurlProseAndShellCompositionAreNotRejected(t *testing.T) {
	r := structuredPolicyRedactor(keyAliasRule("password"), headerAliasRule("Authorization"))
	for _, text := range []string{
		"curl is not installed; use wget",
		"curl -s https://api.example.com/items | jq .",
		"curl 8.5.0 (x86_64-pc-linux-gnu) libcurl/8.5.0",
		"curl -X POST \"$API_URL\" && echo done",
		"curl -u \"$API_USER:$API_PASS\" https://api.example.com | jq .",
		"mysql -u root -p; curl -s https://api.example.com | jq .",
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

func TestDetectorsInspectParameterAndCookieNames(t *testing.T) {
	d, err := detectors.NewRegexDetector([]string{"aws_access_key"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	akia := "AKIA" + "IOSFODNN7EXAMPLE"
	r := New(NewStore(), 0, RedactorOptions{FieldRules: []FieldRule{queryAliasRule("token")}}, d)
	for _, text := range []string{
		"https://x.example/?" + akia,
		"https://x.example/?a=1&" + akia + "=1",
		"GET /?" + akia + " HTTP/1.1\nHost: x\n",
		"GET / HTTP/1.1\nHost: x\nCookie: " + akia + "=1; theme=dark\n",
		`<a href="https://x.example/?` + akia + `">open</a>`,
	} {
		body, _ := json.Marshal(map[string]string{"input": text})
		result, err := r.Transform(body, "s", false, "allow")
		if err != nil {
			t.Fatalf("rejected %q: %v", text, err)
		}
		if strings.Contains(string(result.Body), akia) {
			t.Fatalf("leaked: %s", result.Body)
		}
		if restored := string(r.RestoreForSession(result.Body, "s")); restored != string(body) {
			t.Fatalf("round trip changed %s to %s", body, restored)
		}
	}
}

func TestSelectedHTMLFieldsAndMultipartPartsInUnparsedText(t *testing.T) {
	for name, tc := range map[string]struct {
		rule FieldRule
		text string
	}{
		"noscript input":       {keyAliasRule("password"), `<div><noscript><input name="password" value="` + leakMarker + `"></noscript></div>`},
		"meta content":         {keyAliasRule("csrf_token"), `<html><head><meta name="csrf_token" content="` + leakMarker + `"></head><body>x</body></html>`},
		"prefixed page":        {formAliasRule("password"), "Page:\n<form><input type=password id='password' value='" + leakMarker + "'></form>"},
		"attribute order":      {keyAliasRule("password"), `<input value=` + leakMarker + ` type="password" name="PASSWORD">`},
		"comment":              {keyAliasRule("password"), `<p>x</p><!-- <input name="password" value="` + leakMarker + `"> -->`},
		"multipart form part":  {formAliasRule("password"), "--b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n" + leakMarker + "\r\n--b--\r\n"},
		"multipart with types": {keyAliasRule("api_key"), "--b\nContent-Disposition: form-data; name=\"api_key\"\nContent-Type: text/plain\n\n" + leakMarker + "\n--b--"},
	} {
		t.Run(name, func(t *testing.T) {
			assertContentProtected(t, structuredPolicyRedactor(tc.rule), tc.text)
		})
	}
	unrelated := `<input name="username" value="alice"><meta name="description" content="hello">`
	r := structuredPolicyRedactor(keyAliasRule("password"))
	body, _ := json.Marshal(map[string]string{"input": unrelated})
	result, err := r.Transform(body, "s", false, "allow")
	if err != nil || !strings.Contains(string(result.Body), "alice") || !strings.Contains(string(result.Body), "hello") {
		t.Fatalf("unselected fields changed: %v %s", err, result.Body)
	}
}

func TestMalformedStructuredTextIsProtectedNotRejected(t *testing.T) {
	for name, tc := range map[string]struct {
		rule FieldRule
		text string
	}{
		"NDJSON":                 {keyAliasRule("password"), "{\"user\":\"a\"}\n{\"password\":\"" + leakMarker + "\"}\n{\"user\":\"b\"}\n"},
		"two documents":          {keyAliasRule("password"), "{\"a\":1} {\"password\":\"" + leakMarker + "\"}"},
		"trailing comma":         {keyAliasRule("password"), "{\"password\":\"" + leakMarker + "\",}"},
		"literal percent in URL": {queryAliasRule("token"), "https://x.example/?progress=50%&token=" + leakMarker},
		"literal percent form":   {formAliasRule("password"), "progress=50%&password=" + leakMarker},
		"malformed escape":       {queryAliasRule("token"), "token=" + leakMarker + "%ZZ"},
		"data attribute":         {keyAliasRule("password"), `<div data-password="` + leakMarker + `"></div>`},
		"malformed curl JSON":    {keyAliasRule("password"), "curl https://x.example --data '{\"password\":\"" + leakMarker + "\"'"},
	} {
		t.Run(name, func(t *testing.T) {
			assertContentProtected(t, structuredPolicyRedactor(tc.rule), tc.text)
		})
	}
	r := structuredPolicyRedactor(keyAliasRule("password"))
	body, _ := json.Marshal(map[string]string{"input": `<script type="application/json"></script><p>ok</p>`})
	if _, err := r.Transform(body, "s", false, "allow"); err != nil {
		t.Fatalf("empty JSON script rejected: %v", err)
	}
}
