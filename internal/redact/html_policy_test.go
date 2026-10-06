package redact

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	stdhtml "html"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
	xhtml "golang.org/x/net/html"
)

func htmlPolicyValues(t *testing.T, source string) (map[string]string, string) {
	t.Helper()
	doc, err := xhtml.Parse(strings.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string)
	var text strings.Builder
	var walk func(*xhtml.Node)
	walk = func(node *xhtml.Node) {
		if node.Type == xhtml.TextNode {
			text.WriteString(node.Data)
		}
		id, value := "", ""
		for _, attribute := range node.Attr {
			switch attribute.Key {
			case "id":
				id = attribute.Val
			case "value":
				value = attribute.Val
			}
		}
		if id != "" {
			values[id] = value
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return values, text.String()
}

func htmlToolRequest(text string) []byte {
	request, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "tool", "content": text}}})
	return request
}

func htmlToolContent(t *testing.T, body []byte) string {
	t.Helper()
	var envelope struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Messages[0].Content
}

func htmlFixtureMarkup(t *testing.T, format, content string) string {
	t.Helper()
	switch format {
	case "http":
		response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(content)), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.ContentLength != int64(len(body)) {
			t.Fatal("HTML Content-Length is inconsistent")
		}
		return string(body)
	case "json-string":
		var value map[string]string
		if err := json.Unmarshal([]byte(content), &value); err != nil {
			t.Fatal(err)
		}
		return value["page"]
	case "curl":
		shell, err := exec.LookPath("sh")
		if err != nil {
			t.Skip("POSIX shell is required for quoting verification")
		}
		// Parse the fixed synthetic command with a real shell, without executing curl.
		output, err := exec.Command(shell, "-c", "set -- "+strings.TrimPrefix(content, "curl ")+"; printf '%s\\000' \"$@\"").Output()
		if err != nil {
			t.Fatal(err)
		}
		arguments := bytes.Split(output, []byte{0})
		for index, argument := range arguments {
			if string(argument) == "--data-raw" && index+1 < len(arguments) {
				return string(arguments[index+1])
			}
		}
		t.Fatal("restoration lost the curl body argument")
	}
	return content
}

func TestHTMLPolicyProtectsLogicalFieldsEntitiesAndSplitText(t *testing.T) {
	const secret = "cedar'\"<&\\value"
	const split = "Case-742981-ZX"
	detector, err := detectors.NewRegexDetector(nil, []detectors.CustomPattern{{Name: "case", Pattern: split, Action: "pseudonymize", Generator: "alias"}})
	if err != nil {
		t.Fatal(err)
	}
	r := New(NewStore(), 0, RedactorOptions{FieldRules: []FieldRule{
		aliasKeyRule("credentials", "password", "client_secret"),
		{Name: "form", FormFields: []string{"passphrase"}, Action: "pseudonymize", Generator: "alias", Priority: 100},
		{Name: "public", Keys: []string{"public"}, Action: "allow", Priority: 200},
	}}, detector)
	markup := `<div><input id="first" name="password" value="` + stdhtml.EscapeString(secret) + `">` +
		`<input id="second" name="confirmation" type="password" value="` + stdhtml.EscapeString(secret) + `">` +
		`<input id="third" value="` + stdhtml.EscapeString(secret) + `"><label for="third">client_secret</label>` +
		`<input id="fourth" name="passphrase" value="` + stdhtml.EscapeString(secret) + `">` +
		`<input id="allowed" name="public" type="password" value="public-control">` +
		`<p>before <b>Case-742</b><span>981-ZX</span> after</p></div>`
	for _, format := range []string{"html", "http", "json-string", "curl"} {
		t.Run(format, func(t *testing.T) {
			content := markup
			switch format {
			case "http":
				content = fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s", len(markup), markup)
			case "json-string":
				encoded, _ := json.Marshal(map[string]string{"page": markup})
				content = string(encoded)
			case "curl":
				content = "curl -H 'Content-Type: text/html' --data-raw '" + strings.ReplaceAll(markup, "'", "'\\''") + "' 'http://example.invalid/submit'"
			}
			result, err := r.Transform(htmlToolRequest(content), format, false, "allow")
			if err != nil {
				t.Fatal(err)
			}
			protected := htmlToolContent(t, result.Body)
			if strings.Contains(stdhtml.UnescapeString(protected), secret) {
				t.Fatal("HTML credential escaped inspection")
			}
			restored := htmlToolContent(t, r.RestoreResponseForSession(result.Body, "application/json", format))
			values, visible := htmlPolicyValues(t, htmlFixtureMarkup(t, format, protected))
			for _, id := range []string{"first", "second", "third", "fourth"} {
				if values[id] == secret || !strings.HasPrefix(values[id], "alias-") {
					t.Fatalf("unprotected %s", id)
				}
			}
			if values["allowed"] != "public-control" || strings.Contains(visible, split) {
				t.Fatal("priority or split-inline protection failed")
			}
			originalValues, originalText := htmlPolicyValues(t, htmlFixtureMarkup(t, format, restored))
			for _, id := range []string{"first", "second", "third", "fourth"} {
				if originalValues[id] != secret {
					t.Fatalf("restoration changed %s", id)
				}
			}
			if !strings.Contains(originalText, "before "+split+" after") {
				t.Fatalf("restoration lost inline text: %s", originalText)
			}
			// A restored request must be protected again before the next model turn.
			again, err := r.Transform(htmlToolRequest(restored), format, false, "allow")
			if err != nil {
				t.Fatal(err)
			}
			againValues, againText := htmlPolicyValues(t, htmlFixtureMarkup(t, format, htmlToolContent(t, again.Body)))
			for _, id := range []string{"first", "second", "third", "fourth"} {
				if againValues[id] == secret {
					t.Fatal("restored history leaked a field")
				}
			}
			if strings.Contains(againText, split) {
				t.Fatal("restored history leaked split text")
			}
		})
	}
}

func TestHTMLPolicyNumericIdentityAndSafeScriptRestoration(t *testing.T) {
	const secret = `cedar</script><input id="injected">&value`
	r := structuredPolicyRedactor(aliasKeyRule("credentials", "client_secret"), FieldRule{Name: "number", Keys: []string{"customer_number"}, Action: "pseudonymize", Generator: "number"})
	state, _ := json.Marshal(map[string]any{"client_secret": secret, "customer_number": 937165})
	markup := `<input id="number" name="customer_number" value="937165"><script type="application/json">` + string(state) + `</script>`
	result, err := r.Transform(htmlToolRequest(markup), "number", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	protected := htmlToolContent(t, result.Body)
	values, _ := htmlPolicyValues(t, protected)
	start, end := strings.Index(protected, ">{"), strings.Index(protected, "</script>")
	if start < 0 || end < 0 {
		t.Fatal("missing structured script")
	}
	var decoded map[string]any
	decoder := json.NewDecoder(strings.NewReader(protected[start+1 : end]))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["customer_number"].(json.Number).String() != values["number"] || values["number"] == "937165" {
		t.Fatal("HTML and JSON numeric identities diverged")
	}
	restored := htmlToolContent(t, r.RestoreResponseForSession(result.Body, "application/json", "number"))
	restoredValues, restoredText := htmlPolicyValues(t, restored)
	if restoredValues["number"] != "937165" {
		t.Fatal("numeric HTML value did not restore")
	}
	if _, exists := restoredValues["injected"]; exists {
		t.Fatal("restoration created active HTML from script data")
	}
	if err := json.Unmarshal([]byte(restoredText), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["client_secret"] != secret {
		t.Fatal("script string was not restored exactly")
	}
}

func TestHTMLPolicyRequestBudgetAndTruncationFailClosed(t *testing.T) {
	r := structuredPolicyRedactor(aliasKeyRule("credentials", "password"))
	for name, request := range map[string][]byte{
		"truncated control": htmlToolRequest(`<input name="password" value="cedar`),
		"cumulative HTML": func() []byte {
			page := "<p>" + strings.Repeat("x", maxEmbeddedJSONBytes/2) + "</p>"
			request, _ := json.Marshal(map[string]any{"pages": []string{page, page}})
			return request
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			result, err := r.Transform(request, name, false, "allow")
			if !errors.Is(err, ErrUnsafeRequest) || len(result.Body) != 0 {
				t.Fatalf("unsafe HTML was not rejected: %v", err)
			}
		})
	}
}

func TestHTMLRecoveredControlsStillReceiveFieldPolicies(t *testing.T) {
	r := structuredPolicyRedactor(aliasKeyRule("credentials", "password"))
	request := htmlToolRequest(`<select><input id="inside" name="password" value="cedar-private"></select>`)
	result, err := r.Transform(request, "recovered", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	values, _ := htmlPolicyValues(t, htmlToolContent(t, result.Body))
	if !strings.HasPrefix(values["inside"], "alias-") {
		t.Fatal("retained control escaped field inspection")
	}
}

func TestHTMLFencesInsideHTTPPreserveHeaderPolicies(t *testing.T) {
	r := New(NewStore(), 0, RedactorOptions{FieldRules: []FieldRule{
		aliasKeyRule("credentials", "password"),
		{Name: "header", Headers: []string{"X-Private-Token"}, Action: "pseudonymize", Generator: "alias"},
	}})
	markup := "```html\n<input name=\"password\" value=\"cedar-private\">\n```"
	content := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Private-Token: cedar-header\r\nContent-Length: %d\r\n\r\n%s", len(markup), markup)
	result, err := r.Transform(htmlToolRequest(content), "fenced-http", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	protected := htmlToolContent(t, result.Body)
	if strings.Contains(protected, "cedar-header") || strings.Contains(protected, "cedar-private") {
		t.Fatal("a nested HTML fence bypassed its containing HTTP policies")
	}
	restored := htmlToolContent(t, r.RestoreResponseForSession(result.Body, "application/json", "fenced-http"))
	response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(restored)), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.ContentLength != int64(len(body)) {
		t.Fatal("restored HTML fence has inconsistent HTTP framing")
	}
	if response.Header.Get("X-Private-Token") != "cedar-header" {
		t.Fatal("restoration lost the containing HTTP header")
	}
	if !strings.HasPrefix(string(body), "```html\n") || !strings.HasSuffix(string(body), "\n```") {
		t.Fatal("restoration lost the HTML fence")
	}
	if htmlAttr(htmlTestElement(t, string(body), "input", 0), "value") != "cedar-private" {
		t.Fatal("restoration lost the nested HTML field value")
	}
}
