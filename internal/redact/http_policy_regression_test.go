package redact

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func TestAssignmentDetectorProtectsStructuredHTTPValues(t *testing.T) {
	secret := "cedar" + "xxx"
	assignment := "password=" + secret
	formRequest := func(body string) string {
		return fmt.Sprintf("POST /submit HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	}
	for _, tc := range []struct{ name, input, restored string }{
		{"standalone form", assignment, assignment},
		{"colon control", "password: " + secret, "password: " + secret},
		{"decoded form", "pass%77ord=cedar%78xx", "pass%77ord=" + secret},
		{"repeated parameters", assignment + "&" + assignment + "&keep=a%2Fb", assignment + "&" + assignment + "&keep=a%2Fb"},
		{"absolute URL", "https://example.com/?" + assignment, "https://example.com/?" + assignment},
		{"request target", "GET /?" + assignment + " HTTP/1.1\r\n\r\n", "GET /?" + assignment + " HTTP/1.1\r\n\r\n"},
		{"form body", formRequest(assignment), formRequest(assignment)},
		{"encoded form body", formRequest("password=cedar%78xx"), formRequest(assignment)},
		{"curl data", "curl https://example.com/ -d '" + assignment + "'", "curl https://example.com/ -d '" + assignment + "'"},
		{"curl urlencode", "curl https://example.com/ --data-urlencode '" + assignment + "'", "curl https://example.com/ --data-urlencode '" + assignment + "'"},
		{"HTML query", `<a href="https://example.com/?` + assignment + `">open</a>`, `<a href="https://example.com/?` + assignment + `">open</a>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			detector, err := detectors.NewRegexDetector([]string{"generic_api_key_assignment"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			r := New(NewStore(), 0, RedactorOptions{}, detector)
			body, err := json.Marshal(map[string]string{"input": tc.input})
			if err != nil {
				t.Fatal(err)
			}
			result, err := r.Transform(body, tc.name, false, "allow")
			if err != nil {
				t.Fatal(err)
			}
			protected := decodePolicyJSON(t, result.Body).(map[string]any)["input"].(string)
			if result.Transformed == 0 || strings.Contains(protected, secret) || strings.Contains(protected, "cedar%78xx") {
				t.Fatalf("assignment value was not protected: %q", protected)
			}
			restored := r.RestoreResponseForSession(result.Body, "application/json", tc.name)
			got := decodePolicyJSON(t, restored).(map[string]any)["input"].(string)
			if got != tc.restored {
				t.Fatalf("restored content=%q, want %q", got, tc.restored)
			}
		})
	}
}

func TestAssignmentDetectorPrioritiesAndAllow(t *testing.T) {
	secret := "cedar" + "xxx"
	for _, tc := range []struct {
		name    string
		custom  []detectors.CustomPattern
		rules   []FieldRule
		blocked bool
	}{
		{
			name:   "value allow outranks assignment",
			custom: []detectors.CustomPattern{{Name: "public", Pattern: "^" + secret + "$", Action: "allow", Priority: 20}},
		},
		{
			name: "assignment allow outranks value",
			custom: []detectors.CustomPattern{
				{Name: "public", Pattern: "^password=" + secret + "$", Action: "allow", Priority: 20},
				{Name: "private", Pattern: "^" + secret + "$", Action: "placeholder", Priority: 10},
			},
		},
		{
			name: "assignment block outranks value allow",
			custom: []detectors.CustomPattern{
				{Name: "private", Pattern: "^password=" + secret + "$", Action: "block", Priority: 20},
				{Name: "public", Pattern: "^" + secret + "$", Action: "allow", Priority: 10},
			},
			blocked: true,
		},
		{
			name: "explicit field allow",
			rules: []FieldRule{
				{Name: "public_form", FormFields: []string{"password"}, Action: "allow"},
				{Name: "public_query", QueryParams: []string{"password"}, Action: "allow"},
			},
		},
	} {
		for _, prefix := range []string{"", "https://example.com/?"} {
			t.Run(tc.name+prefix, func(t *testing.T) {
				detector, err := detectors.NewRegexDetector([]string{"generic_api_key_assignment"}, tc.custom)
				if err != nil {
					t.Fatal(err)
				}
				r := New(NewStore(), 0, RedactorOptions{FieldRules: tc.rules}, detector)
				body, err := json.Marshal(map[string]string{"input": prefix + "password=" + secret})
				if err != nil {
					t.Fatal(err)
				}
				result, err := r.Transform(body, "priority", false, "allow")
				if err != nil {
					t.Fatal(err)
				}
				if result.Blocked != tc.blocked {
					t.Fatalf("blocked=%v, want %v", result.Blocked, tc.blocked)
				}
				if !tc.blocked {
					assertPolicyJSONEqual(t, result.Body, body)
					if result.Transformed != 0 {
						t.Fatalf("allow transformed %d values", result.Transformed)
					}
				}
			})
		}
	}
}

func TestAssignmentCaptureMapsOnlyDecodedValue(t *testing.T) {
	secret := "cedar" + "xxx&scope=one/two?x=y + end"
	detector, err := detectors.NewRegexDetector(nil, []detectors.CustomPattern{{
		Name: "assignment", Pattern: `^password=(?P<value>.+)$`, Action: "pseudonymize", Generator: "alias",
	}})
	if err != nil {
		t.Fatal(err)
	}
	r := New(NewStore(), 0, RedactorOptions{}, detector)
	input := "https://example.com/?password=" + url.QueryEscape(secret) + "&keep=a%2Fb"
	body, err := json.Marshal(map[string]string{"input": input})
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.Transform(body, "capture", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	protected := decodePolicyJSON(t, result.Body).(map[string]any)["input"].(string)
	parsed, err := url.Parse(protected)
	if err != nil {
		t.Fatal(err)
	}
	if result.Transformed != 1 || parsed.Query().Get("password") == secret || len(parsed.Query()) != 2 || parsed.Query().Get("keep") != "a/b" {
		t.Fatalf("decoded assignment was not safely mapped: %q", protected)
	}
	assertPolicyJSONEqual(t, r.RestoreResponseForSession(result.Body, "application/json", "capture"), body)
}

func TestCookieDetectorUsesSameAliasAsPlainContent(t *testing.T) {
	email := "cedar@example.com"
	for _, input := range []string{
		"GET / HTTP/1.1\r\nCookie: owner=" + email + "; theme=light\r\n\r\n",
		"HTTP/1.1 200 OK\r\nSet-Cookie: owner=\"" + email + "\"; Path=/; HttpOnly\r\nContent-Length: 0\r\n\r\n",
		"curl https://example.com/ -H 'Cookie: owner=" + email + "'",
		"curl https://example.com/ --cookie 'owner=" + email + "'",
	} {
		t.Run(input, func(t *testing.T) {
			detector, err := detectors.NewRegexDetector(nil, []detectors.CustomPattern{{Name: "email", Detector: "email", Action: "pseudonymize", Generator: "email"}})
			if err != nil {
				t.Fatal(err)
			}
			r := New(NewStore(), 0, RedactorOptions{}, detector)
			body, err := json.Marshal(map[string]string{"plain": email, "input": input})
			if err != nil {
				t.Fatal(err)
			}
			result, err := r.Transform(body, "cookies", false, "allow")
			if err != nil {
				t.Fatal(err)
			}
			root := decodePolicyJSON(t, result.Body).(map[string]any)
			alias := root["plain"].(string)
			if alias == email || !strings.Contains(root["input"].(string), alias) || result.Transformed != 2 {
				t.Fatalf("cookie alias diverged from plain content: %s (%d transformations)", result.Body, result.Transformed)
			}
			restored := r.RestoreResponseForSession(result.Body, "application/json", "cookies")
			assertPolicyJSONEqual(t, restored, body)
			nextTurn, err := r.Transform(restored, "cookies", false, "allow")
			if err != nil {
				t.Fatal(err)
			}
			assertPolicyJSONEqual(t, nextTurn.Body, result.Body)
		})
	}
}

func TestExplicitCookieHeaderPoliciesOwnWholeValue(t *testing.T) {
	for _, action := range []string{"allow", "pseudonymize", "redact"} {
		for _, input := range []string{
			"GET / HTTP/1.1\r\nCookie: owner=cedar@example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nSet-Cookie: owner=cedar@example.com; Path=/\r\nContent-Length: 0\r\n\r\n",
			"curl https://example.com/ --cookie 'owner=cedar@example.com'",
		} {
			t.Run(action+input, func(t *testing.T) {
				detector, err := detectors.NewRegexDetector(nil, []detectors.CustomPattern{{Name: "email", Detector: "email", Action: "pseudonymize", Generator: "email"}})
				if err != nil {
					t.Fatal(err)
				}
				generator := ""
				if action == "pseudonymize" {
					generator = "alias"
				}
				r := New(NewStore(), 0, RedactorOptions{FieldRules: []FieldRule{
					{Name: "whole", Headers: []string{"cOoKiE", "sEt-CoOkIe"}, Action: action, Generator: generator},
					{Name: "inner", Cookies: []string{"owner"}, Action: "block", Priority: 100},
				}}, detector)
				body, err := json.Marshal(map[string]string{"input": input})
				if err != nil {
					t.Fatal(err)
				}
				result, err := r.Transform(body, "whole-header", false, "allow")
				if err != nil {
					t.Fatal(err)
				}
				if result.Blocked || len(result.Matches) != 1 || result.Matches[0].Rule != "whole" {
					t.Fatalf("whole-header policy lost ownership: %+v", result)
				}
				if action == "allow" {
					assertPolicyJSONEqual(t, result.Body, body)
				} else if strings.Contains(string(result.Body), "cedar@example.com") || result.Transformed != 1 {
					t.Fatalf("whole-header protection failed: %s", result.Body)
				}
				if action != "redact" {
					assertPolicyJSONEqual(t, r.RestoreResponseForSession(result.Body, "application/json", "whole-header"), body)
				}
			})
		}
	}
}

func TestHeaderOnlyHTTPTranscriptsProtectAndRestore(t *testing.T) {
	for _, newline := range []string{"\n", "\r\n"} {
		for _, finalNewline := range []bool{false, true} {
			for _, firstLine := range []string{
				"GET /?credential=CUSTOMER-ALPHA HTTP/1.1",
				"HTTP/1.1 200 OK",
			} {
				for _, framing := range []string{"", "Content-Length: 67108864", "Transfer-Encoding: chunked"} {
					t.Run(fmt.Sprintf("%q/%v/%s/%s", newline, finalNewline, firstLine, framing), func(t *testing.T) {
						cookie := "Cookie: session=CUSTOMER-ALPHA; theme=light"
						if strings.HasPrefix(firstLine, "HTTP/") {
							cookie = "Set-Cookie: session=CUSTOMER-ALPHA; Path=/; HttpOnly"
						}
						lines := []string{
							firstLine,
							"Host: example.com",
							"X-Private: CUSTOMER-ALPHA",
							cookie,
							"Content-Encoding: gzip",
						}
						if framing != "" {
							lines = append(lines, framing)
						}
						input := strings.Join(lines, newline)
						if finalNewline {
							input += newline
						}
						r := structuredPolicyRedactor(
							FieldRule{Name: "header", Headers: []string{"X-Private"}, Action: "pseudonymize", Generator: "alias"},
							FieldRule{Name: "cookie", Cookies: []string{"session"}, Action: "pseudonymize", Generator: "alias"},
							FieldRule{Name: "query", QueryParams: []string{"credential"}, Action: "pseudonymize", Generator: "alias"},
						)
						body, err := json.Marshal(map[string]string{"input": input})
						if err != nil {
							t.Fatal(err)
						}
						result, err := r.Transform(body, "headers-only", false, "allow")
						if err != nil {
							t.Fatal(err)
						}
						protected := decodePolicyJSON(t, result.Body).(map[string]any)["input"].(string)
						wantCount := 2
						if strings.HasPrefix(firstLine, "GET ") {
							wantCount++
						}
						if strings.Contains(protected, "CUSTOMER-ALPHA") || result.Transformed != wantCount {
							t.Fatalf("header-only values were not protected: %q", protected)
						}
						if framing != "" && !strings.Contains(protected, framing) {
							t.Fatalf("omitted-body framing metadata changed: %q", protected)
						}
						if strings.HasSuffix(protected, newline) != finalNewline || strings.Contains(protected, newline+newline) {
							t.Fatalf("header-only framing changed: %q", protected)
						}
						assertPolicyJSONEqual(t, r.RestoreResponseForSession(result.Body, "application/json", "headers-only"), body)
					})
				}
			}
		}
	}
}

func TestHeaderOnlyHTTPDoesNotAcceptTruncatedFullMessages(t *testing.T) {
	r := structuredPolicyRedactor(FieldRule{
		Name: "header", Headers: []string{"X-Private"}, Action: "pseudonymize", Generator: "alias",
	})
	for _, input := range []string{
		"HTTP/1.1 200 OK\nContent-Length: 9\n\nshort",
		"HTTP/1.1 200 OK\r\nContent-Length: 67108864\r\n\r\n",
		"HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n",
		"HTTP/1.1 200 OK\nX-Private",
		"HTTP/1.1 200 OK\nX-Private: CUSTOMER-ALPHA\r",
		"HTTP/1.1 200 OK\nX-Private: CUSTOMER-ALPHA\npayload without separator",
		"HTTP/1.1 200 OK\nContent-Length: invalid",
		"HTTP/1.1 200 OK\nContent-Length: 9\nContent-Length: 10",
		"GET / HTTP/1.1\nCookie: session=\"unterminated",
	} {
		t.Run(input, func(t *testing.T) {
			body, err := json.Marshal(map[string]string{"input": input})
			if err != nil {
				t.Fatal(err)
			}
			if result, err := r.Transform(body, "invalid-headers", false, "allow"); !errors.Is(err, ErrUnsafeRequest) || len(result.Body) != 0 {
				t.Fatalf("invalid transcript returned body=%s err=%v", result.Body, err)
			}
		})
	}
}
