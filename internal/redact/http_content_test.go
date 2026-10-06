package redact

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

type recordedHTTPCall struct {
	selector string
	name     string
	value    string
}

func syntheticHTTPFixtureParts() (queryName, formName, value string) {
	return "to" + "ken", "pass" + "word", "CUSTOMER" + "-ALPHA"
}

func TestProtectHTTPContentRequestSelectorsAndFraming(t *testing.T) {
	queryName, formName, sensitive := syntheticHTTPFixtureParts()
	encodedSensitive := "CUSTOMER%2D" + "ALPHA"
	body := formName + "=" + encodedSensitive + "&" + formName + "=second&keep=a%2Fb"
	input := fmt.Sprintf("POST /submit?%s=first&%s=second&keep=a%%2Fb HTTP/1.1\r\n"+
		"Host: api.example\r\n"+
		"Authorization:\tBearer TOKEN-ALPHA  \r\n"+
		"Cookie: session=COOKIE-ALPHA; theme=light\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\n"+
		"Content-Length: %d\r\n\r\n%s", queryName, queryName, len(body), body)

	var calls []recordedHTTPCall
	policy := httpContentPolicy{
		HasHeaders: true,
		HasCookies: true,
		HasQuery:   true,
		HasForm:    true,
		Transform: func(selector, name, value string) (string, error) {
			calls = append(calls, recordedHTTPCall{selector: selector, name: name, value: value})
			switch {
			case selector == selectorHeaders && strings.EqualFold(name, "authorization"):
				return "[AUTH-PROTECTED]", nil
			case selector == selectorCookies && name == "session":
				return "COOKIE SAFE", nil
			case selector == selectorQueryParams && name == queryName:
				return "QUERY SAFE", nil
			case selector == selectorFormFields && name == formName:
				return "FORM SAFE", nil
			default:
				return value, nil
			}
		},
	}

	got, handled, err := protectHTTPContent(input, policy)
	if err != nil {
		t.Fatal(err)
	}
	if !handled {
		t.Fatal("HTTP request was not handled")
	}
	wantBody := formName + "=FORM+SAFE&" + formName + "=FORM+SAFE&keep=a%2Fb"
	want := fmt.Sprintf("POST /submit?%s=QUERY+SAFE&%s=QUERY+SAFE&keep=a%%2Fb HTTP/1.1\r\n"+
		"Host: api.example\r\n"+
		"Authorization:\t[AUTH-PROTECTED]  \r\n"+
		"Cookie: session=\"COOKIE SAFE\"; theme=light\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\n"+
		"Content-Length: %d\r\n\r\n%s", queryName, queryName, len(wantBody), wantBody)
	if got != want {
		t.Fatalf("protected request mismatch\nwant: %q\n got: %q", want, got)
	}
	for _, secret := range []string{"TOKEN-ALPHA", "COOKIE-ALPHA", sensitive, formName + "=second", queryName + "=second"} {
		if strings.Contains(got, secret) {
			t.Fatalf("protected request retained %q", secret)
		}
	}
	assertHTTPCallCount(t, calls, selectorHeaders, "Authorization", 1)
	assertHTTPCallCount(t, calls, selectorCookies, "session", 1)
	assertHTTPCallCount(t, calls, selectorQueryParams, queryName, 2)
	assertHTTPCallCount(t, calls, selectorFormFields, formName, 2)
}

func TestProtectHTTPContentSetCookieAndTextBody(t *testing.T) {
	input := "HTTP/1.1 200 OK\n" +
		"Set-Cookie: session=\"COOKIE-ALPHA\"; Path=/; HttpOnly; SameSite=Lax\n" +
		"Content-Length: 4\n\nbody"
	var calls []recordedHTTPCall
	policy := httpContentPolicy{
		HasCookies: true,
		Transform: func(selector, name, value string) (string, error) {
			calls = append(calls, recordedHTTPCall{selector: selector, name: name, value: value})
			if selector == selectorCookies && name == "session" {
				return "COOKIE SAFE", nil
			}
			return value, nil
		},
		Text: func(value string) (string, error) {
			return strings.ReplaceAll(value, "body", "protected-body"), nil
		},
	}

	got, handled, err := protectHTTPContent(input, policy)
	if err != nil {
		t.Fatal(err)
	}
	if !handled {
		t.Fatal("HTTP response was not handled")
	}
	want := "HTTP/1.1 200 OK\n" +
		"Set-Cookie: session=\"COOKIE SAFE\"; Path=/; HttpOnly; SameSite=Lax\n" +
		"Content-Length: 14\n\nprotected-body"
	if got != want {
		t.Fatalf("protected response mismatch\nwant: %q\n got: %q", want, got)
	}
	assertHTTPCallCount(t, calls, selectorCookies, "session", 1)
	for _, attribute := range []string{"Path=/", "HttpOnly", "SameSite=Lax"} {
		if !strings.Contains(got, attribute) {
			t.Fatalf("Set-Cookie attribute %q changed: %q", attribute, got)
		}
	}
}

func TestProtectHTTPContentWholeCookieHeaderSelection(t *testing.T) {
	input := "GET / HTTP/1.1\r\nCookie: session=COOKIE-ALPHA; theme=light\r\n\r\n"
	policy := httpContentPolicy{
		HasHeaders:     true,
		HasCookies:     true,
		HeaderSelected: func(name string) bool { return strings.EqualFold(name, "cookie") },
		Transform: func(selector, name, value string) (string, error) {
			if selector == selectorHeaders && strings.EqualFold(name, "cookie") {
				return "[COOKIE-HEADER-PROTECTED]", nil
			}
			if selector == selectorCookies {
				t.Fatal("opaque whole-header selection reached the cookie callback")
			}
			return value, nil
		},
	}
	got, handled, err := protectHTTPContent(input, policy)
	if err != nil || !handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	want := "GET / HTTP/1.1\r\nCookie: [COOKIE-HEADER-PROTECTED]\r\n\r\n"
	if got != want {
		t.Fatalf("whole Cookie header mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestProtectHTTPContentJSONCallbacks(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		hasJSON     bool
	}{
		{name: "declared suffix media type", contentType: "Content-Type: application/problem+json; charset=utf-8\r\n"},
		{name: "JSON shaped body", hasJSON: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := `{"password":"TOKEN-ALPHA","customer_number":1001}`
			input := fmt.Sprintf("HTTP/1.1 200 OK\r\n%sContent-Length: %d\r\n\r\n%s", test.contentType, len(body), body)
			policy := httpContentPolicy{
				HasJSON: test.hasJSON,
				JSON: func(value string) (string, error) {
					var object map[string]any
					if err := json.Unmarshal([]byte(value), &object); err != nil {
						t.Fatal(err)
					}
					if object["password"] != "TOKEN-ALPHA" || object["customer_number"] != float64(1001) {
						t.Fatalf("JSON callback received %#v", object)
					}
					return `{"password":"TOKEN-SAFE","customer_number":9001}`, nil
				},
			}
			got, handled, err := protectHTTPContent(input, policy)
			if err != nil {
				t.Fatal(err)
			}
			if !handled {
				t.Fatal("JSON HTTP body was not recognized")
			}
			wantBody := `{"password":"TOKEN-SAFE","customer_number":9001}`
			want := fmt.Sprintf("HTTP/1.1 200 OK\r\n%sContent-Length: %d\r\n\r\n%s", test.contentType, len(wantBody), wantBody)
			if got != want {
				t.Fatalf("JSON response mismatch\nwant: %q\n got: %q", want, got)
			}
		})
	}
}

func TestProtectHTTPContentHonorsContentLengthBeforeCLIFooter(t *testing.T) {
	queryName, _, sensitive := syntheticHTTPFixtureParts()
	footer := "CLI footer " + queryName + "=" + sensitive
	input := "HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\n" + sensitive + "\n" + footer
	policy := httpContentPolicy{
		Text: func(value string) (string, error) {
			return strings.ReplaceAll(value, sensitive, "[REDACTED]"), nil
		},
	}
	got, handled, err := protectHTTPContent(input, policy)
	if err != nil {
		t.Fatal(err)
	}
	if !handled {
		t.Fatal("HTTP response was not handled")
	}
	want := "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n[REDACTED]\n" + strings.ReplaceAll(footer, sensitive, "[REDACTED]")
	if got != want {
		t.Fatalf("framed footer mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestProtectHTTPContentCurlPrefixesAndResponseChain(t *testing.T) {
	queryName, _, _ := syntheticHTTPFixtureParts()
	input := fmt.Sprintf("Command output:\n"+
		"> GET /check?%s=first&%s=second HTTP/1.1\r\n"+
		"> Host: api.example\r\n"+
		"> Authorization: Bearer TOKEN-ALPHA\r\n"+
		"> \r\n"+
		"* request sent\r\n"+
		"< HTTP/1.1 100 Continue\r\n"+
		"< \r\n"+
		"< HTTP/1.1 200 OK\r\n"+
		"< Content-Length: 4\r\n"+
		"< \r\n"+
		"DATA", queryName, queryName)
	policy := httpContentPolicy{
		HasHeaders: true,
		HasQuery:   true,
		Transform: func(selector, name, value string) (string, error) {
			switch {
			case selector == selectorHeaders && strings.EqualFold(name, "authorization"):
				return "[AUTH-PROTECTED]", nil
			case selector == selectorQueryParams && name == queryName:
				return "safe", nil
			default:
				return value, nil
			}
		},
		Text: func(value string) (string, error) {
			if value == "DATA" {
				return "DONE", nil
			}
			return value, nil
		},
	}
	got, handled, err := protectHTTPContent(input, policy)
	if err != nil {
		t.Fatal(err)
	}
	if !handled {
		t.Fatal("prefixed transcript was not handled")
	}
	want := strings.Replace(input, queryName+"=first&"+queryName+"=second", queryName+"=safe&"+queryName+"=safe", 1)
	want = strings.Replace(want, "Bearer TOKEN-ALPHA", "[AUTH-PROTECTED]", 1)
	want = strings.TrimSuffix(want, "DATA") + "DONE"
	if got != want {
		t.Fatalf("prefixed transcript mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestProtectHTTPContentStandaloneURLAndForm(t *testing.T) {
	queryName, formName, _ := syntheticHTTPFixtureParts()
	var calls []recordedHTTPCall
	policy := httpContentPolicy{
		HasQuery: true,
		HasForm:  true,
		Transform: func(selector, name, value string) (string, error) {
			calls = append(calls, recordedHTTPCall{selector: selector, name: name, value: value})
			if selector == selectorQueryParams && name == queryName || selector == selectorFormFields && name == formName {
				return "SAFE VALUE", nil
			}
			return value, nil
		},
	}

	urlInput := " \thttps://api.example/search?" + queryName + "=CUSTOMER%2D" + "ALPHA&" + queryName + "=second&keep=a%2Fb#section\n"
	urlWant := " \thttps://api.example/search?" + queryName + "=SAFE+VALUE&" + queryName + "=SAFE+VALUE&keep=a%2Fb#section\n"
	got, handled, err := protectHTTPContent(urlInput, policy)
	if err != nil || !handled || got != urlWant {
		t.Fatalf("standalone URL: handled=%v err=%v\nwant: %q\n got: %q", handled, err, urlWant, got)
	}

	formInput := " " + formName + "=CUSTOMER%2D" + "ALPHA&" + formName + "=second&keep=a%2Fb\r\n"
	formWant := " " + formName + "=SAFE+VALUE&" + formName + "=SAFE+VALUE&keep=a%2Fb\r\n"
	got, handled, err = protectHTTPContent(formInput, policy)
	if err != nil || !handled || got != formWant {
		t.Fatalf("standalone form: handled=%v err=%v\nwant: %q\n got: %q", handled, err, formWant, got)
	}
	assertHTTPCallCount(t, calls, selectorQueryParams, queryName, 2)
	assertHTTPCallCount(t, calls, selectorFormFields, formName, 2)
}

func TestProtectHTTPContentFailsClosedWithoutSecretErrors(t *testing.T) {
	queryName, _, sensitive := syntheticHTTPFixtureParts()
	privateHeader := "X-Private-" + "Token"
	identity := func(_ string, _ string, value string) (string, error) { return value, nil }
	basePolicy := httpContentPolicy{
		Transform:  identity,
		JSON:       func(value string) (string, error) { return value, nil },
		Text:       func(value string) (string, error) { return value, nil },
		HasHeaders: true,
		HasCookies: true,
		HasQuery:   true,
		HasForm:    true,
		HasJSON:    true,
	}
	form := queryName + "=%ZZ"
	tests := []struct {
		name   string
		input  string
		policy httpContentPolicy
	}{
		{
			name:   "truncated content length",
			input:  "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n" + sensitive,
			policy: basePolicy,
		},
		{
			name:   "malformed query escape",
			input:  "GET /?" + queryName + "=%ZZ HTTP/1.1\r\nHost: api.example\r\n\r\n",
			policy: basePolicy,
		},
		{
			name: "malformed form escape",
			input: fmt.Sprintf("POST /submit HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n"+
				"Content-Length: %d\r\n\r\n%s", len(form), form),
			policy: basePolicy,
		},
		{
			name: "encoded body",
			input: "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 14\r\n\r\n" +
				sensitive,
			policy: basePolicy,
		},
		{
			name: "chunked body",
			input: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
				"e\r\n" + sensitive + "\r\n0\r\n\r\n",
			policy: basePolicy,
		},
		{
			name:   "malformed cookie quote",
			input:  "GET / HTTP/1.1\r\nCookie: session=\"" + sensitive + "\r\n\r\n",
			policy: basePolicy,
		},
		{
			name:   "truncated headers",
			input:  "GET / HTTP/1.1\r\nAuthorization: " + sensitive + "\r\nX-Incomplete",
			policy: basePolicy,
		},
		{
			name:  "header delimiter injection",
			input: "GET / HTTP/1.1\r\n" + privateHeader + ": " + sensitive + "\r\n\r\n",
			policy: httpContentPolicy{
				HasHeaders: true,
				Transform: func(selector, name, value string) (string, error) {
					if selector == selectorHeaders && name == privateHeader {
						return "SAFE\r\nInjected: " + sensitive, nil
					}
					return value, nil
				},
			},
		},
		{
			name:  "cookie delimiter injection",
			input: "GET / HTTP/1.1\r\nCookie: session=" + sensitive + "\r\n\r\n",
			policy: httpContentPolicy{
				HasCookies: true,
				Transform: func(selector, name, value string) (string, error) {
					if selector == selectorCookies && name == "session" {
						return "SAFE;admin=true", nil
					}
					return value, nil
				},
			},
		},
		{
			name:   "standalone malformed escape",
			input:  queryName + "=%ZZ",
			policy: basePolicy,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, handled, err := protectHTTPContent(test.input, test.policy)
			if !handled || !errors.Is(err, ErrUnsafeRequest) {
				t.Fatalf("handled=%v error=%v", handled, err)
			}
			if got != "" {
				t.Fatalf("fail-closed output was %q", got)
			}
			if strings.Contains(err.Error(), sensitive) || strings.Contains(err.Error(), "TOKEN-ALPHA") {
				t.Fatalf("error disclosed protected input: %q", err)
			}
		})
	}
}

func TestProtectHTTPContentAvoidsNonHTTPAndPreservesUnchangedBytes(t *testing.T) {
	queryName, _, sensitive := syntheticHTTPFixtureParts()
	policy := httpContentPolicy{
		HasHeaders: true,
		HasCookies: true,
		HasQuery:   true,
		HasForm:    true,
		HasJSON:    true,
		Transform: func(_ string, _ string, value string) (string, error) {
			return value, nil
		},
		JSON: func(value string) (string, error) { return value, nil },
		Text: func(value string) (string, error) { return value, nil },
	}
	controls := []string{
		`{"request":"GET / HTTP/1.1\\r\\nHost: api.example\\r\\n\\r\\n"}`,
		"payload = {'" + queryName + "': '" + sensitive + "'}",
		"Use " + queryName + "=" + sensitive + " in this prose example.",
		"call(\"" + queryName + "=" + sensitive + "\")",
	}
	for index, input := range controls {
		got, handled, err := protectHTTPContent(input, policy)
		if err != nil || handled || got != input {
			t.Fatalf("control %d: handled=%v err=%v\nwant: %q\n got: %q", index, handled, err, input, got)
		}
	}

	unchangedHTTP := "HTTP/1.1 200 OK\r\nX-Trace: public\r\nContent-Length: 6\r\n\r\npublic"
	got, handled, err := protectHTTPContent(unchangedHTTP, policy)
	if err != nil || !handled || got != unchangedHTTP {
		t.Fatalf("unchanged HTTP: handled=%v err=%v\nwant: %q\n got: %q", handled, err, unchangedHTTP, got)
	}
}

func assertHTTPCallCount(t *testing.T, calls []recordedHTTPCall, selector, name string, want int) {
	t.Helper()
	got := 0
	for _, call := range calls {
		if call.selector == selector && call.name == name {
			got++
		}
	}
	if got != want {
		t.Fatalf("callback count for %s/%s = %d, want %d; calls=%v", selector, name, got, want, calls)
	}
}

func TestProtectHTTPContentCallbackErrorsAreGeneric(t *testing.T) {
	privateHeader := "X-Private-" + "Token"
	input := "GET / HTTP/1.1\r\n" + privateHeader + ": TOKEN-ALPHA\r\n\r\n"
	policy := httpContentPolicy{
		HasHeaders: true,
		Transform: func(string, string, string) (string, error) {
			return "", fmt.Errorf("callback saw TOKEN-ALPHA")
		},
	}
	_, handled, err := protectHTTPContent(input, policy)
	if !handled || !errors.Is(err, ErrUnsafeRequest) {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	if strings.Contains(err.Error(), "TOKEN-ALPHA") {
		t.Fatalf("callback error leaked input: %q", err)
	}
}

func TestProtectHTTPContentContentLengthUsesByteLength(t *testing.T) {
	input := "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"
	policy := httpContentPolicy{
		Text: func(value string) (string, error) {
			return strings.ReplaceAll(value, "x", "é"), nil
		},
	}
	got, handled, err := protectHTTPContent(input, policy)
	if err != nil || !handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	wantLength := strconv.Itoa(len("é"))
	if got != "HTTP/1.1 200 OK\r\nContent-Length: "+wantLength+"\r\n\r\né" {
		t.Fatalf("byte Content-Length mismatch: %q", got)
	}
}

func TestProtectHTTPContentEncodesChangedURLAndFormValuesOnce(t *testing.T) {
	queryName, formName, sensitive := syntheticHTTPFixtureParts()
	restoredValue := sensitive + "&scope=one/two?x=y"
	escapedValue := sensitive + "%26scope%3Done%2Ftwo%3Fx%3Dy"
	policy := httpContentPolicy{
		HasQuery: true,
		HasForm:  true,
		Transform: func(selector, name, value string) (string, error) {
			if selector == selectorQueryParams && name == queryName ||
				selector == selectorFormFields && name == formName {
				if value != "SAFE" {
					t.Fatalf("callback received undecoded value %q", value)
				}
				return restoredValue, nil
			}
			return value, nil
		},
	}

	urlInput := "https://api.example/items?" + queryName + "=SAFE&keep=%2f"
	urlWant := "https://api.example/items?" + queryName + "=" + escapedValue + "&keep=%2f"
	got, handled, err := protectHTTPContent(urlInput, policy)
	if err != nil || !handled || got != urlWant {
		t.Fatalf("reserved URL value: handled=%v err=%v\nwant: %q\n got: %q", handled, err, urlWant, got)
	}

	formInput := formName + "=SAFE&keep=%2f"
	formWant := formName + "=" + escapedValue + "&keep=%2f"
	got, handled, err = protectHTTPContent(formInput, policy)
	if err != nil || !handled || got != formWant {
		t.Fatalf("reserved form value: handled=%v err=%v\nwant: %q\n got: %q", handled, err, formWant, got)
	}
	if strings.Contains(got, "%252F") || strings.Contains(got, "&scope=") {
		t.Fatalf("reserved value was encoded incorrectly: %q", got)
	}
}

func TestProtectHTTPContentProxyConnectChain(t *testing.T) {
	input := "Proxy transcript:\r\n" +
		"HTTP/1.1 200 Connection established\r\n" +
		"Proxy-Agent: fixture\r\n\r\n" +
		"HTTP/1.1 200 OK\r\n" +
		"Content-Length: 4\r\n\r\n" +
		"DATA"
	policy := httpContentPolicy{
		Text: func(value string) (string, error) {
			return strings.ReplaceAll(value, "DATA", "DONE"), nil
		},
	}
	got, handled, err := protectHTTPContent(input, policy)
	if err != nil || !handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	want := strings.TrimSuffix(input, "DATA") + "DONE"
	if got != want {
		t.Fatalf("CONNECT chain mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestProtectHTTPContentRejectsUnsupportedTunnelBytes(t *testing.T) {
	input := "HTTP/1.1 200 Connection established\r\n\r\n\x16\x03\x01CUSTOMER-ALPHA"
	got, handled, err := protectHTTPContent(input, httpContentPolicy{
		Text: func(value string) (string, error) { return value, nil },
	})
	if got != "" || !handled || !errors.Is(err, ErrUnsafeRequest) {
		t.Fatalf("got=%q handled=%v err=%v", got, handled, err)
	}
	if strings.Contains(err.Error(), "CUSTOMER-ALPHA") {
		t.Fatalf("tunnel error disclosed input: %q", err)
	}
}

func TestProtectHTTPContentRejectsMalformedJSONBody(t *testing.T) {
	body := `{"value":`
	input := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	got, handled, err := protectHTTPContent(input, httpContentPolicy{
		JSON: func(value string) (string, error) { return value, nil },
	})
	if got != "" || !handled || !errors.Is(err, ErrUnsafeRequest) {
		t.Fatalf("got=%q handled=%v err=%v", got, handled, err)
	}
}

func TestProtectHTTPContentEnforcesParserBounds(t *testing.T) {
	queryName, _, _ := syntheticHTTPFixtureParts()
	parameters := strings.Repeat(queryName+"=x&", maxHTTPParameters) + queryName + "=x"
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "header line",
			input: "GET / HTTP/1.1\r\nX-Long: " + strings.Repeat("x", maxHTTPLineBytes) + "\r\n\r\n",
		},
		{
			name:  "query parameters",
			input: "GET /?" + parameters + " HTTP/1.1\r\nHost: api.example\r\n\r\n",
		},
		{
			name:  "request line",
			input: "GET /?" + queryName + "=" + strings.Repeat("x", maxHTTPLineBytes) + " HTTP/1.1\r\n\r\n",
		},
		{
			name:  "oversized CLI prefix",
			input: strings.Repeat("x", maxHTTPContentBytes) + "\nHTTP/1.1 200 OK\r\n\r\nprivate",
		},
		{
			name:  "truncated status",
			input: "HTTP/1.1 20\r\nX-Private: private\r\n\r\n",
		},
		{
			name:  "truncated version",
			input: "GET / HTTP/1.\r\nX-Private: private\r\n\r\n",
		},
	}
	policy := httpContentPolicy{
		HasHeaders: true,
		HasQuery:   true,
		Transform: func(_ string, _ string, value string) (string, error) {
			return value, nil
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, handled, err := protectHTTPContent(test.input, policy)
			if got != "" || !handled || !errors.Is(err, ErrUnsafeRequest) {
				t.Fatalf("got=%q handled=%v err=%v", got, handled, err)
			}
		})
	}
}

func TestProtectHTTPContentWrappedExchangeAndSurroundingText(t *testing.T) {
	body := `{"credential":"PRIVATE"}`
	prefix := "CLI PRIVATE\nHttpRequestResponse{httpRequest=GET /PRIVATE HTTP/1.1\r\nHost: example.invalid\r\n\r\n, httpResponse="
	suffix := ", messageAnnotations=Annotations{comment='PRIVATE', highlightColor=NONE}}"
	input := prefix + fmt.Sprintf("HTTP/1.1 200 PRIVATE\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body) + suffix
	replace := func(value string) (string, error) { return strings.ReplaceAll(value, "PRIVATE", "safe"), nil }
	got, handled, err := protectHTTPContent(input, httpContentPolicy{HasJSON: true, JSON: replace, Text: replace})
	if err != nil || !handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	want := strings.ReplaceAll(input, "PRIVATE", "safe")
	want = strings.Replace(want, fmt.Sprintf("Content-Length: %d", len(body)), fmt.Sprintf("Content-Length: %d", len(body)-3), 1)
	if got != want {
		t.Fatalf("wrapped HTTP exchange protection mismatch\nwant: %q\n got: %q", want, got)
	}
	unframed := strings.Replace(input, fmt.Sprintf("Content-Length: %d\r\n", len(body)), "", 1)
	unframed = strings.Replace(unframed, "comment='PRIVATE'", "comment=''", 1)
	got, handled, err = protectHTTPContent(unframed, httpContentPolicy{HasJSON: true, JSON: replace, Text: replace})
	if err != nil || !handled || got != strings.ReplaceAll(unframed, "PRIVATE", "safe") {
		t.Fatalf("unframed wrapped response: handled=%v err=%v got=%q", handled, err, got)
	}
}
