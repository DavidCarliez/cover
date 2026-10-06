package redact

import (
	"encoding/json"
	stdhtml "html"
	"net/url"
	"strings"
	"testing"

	xhtml "golang.org/x/net/html"
)

func htmlAttributeValue(t *testing.T, source, id, name string) string {
	t.Helper()
	doc, err := xhtml.Parse(strings.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	var found string
	var walk func(*xhtml.Node)
	walk = func(node *xhtml.Node) {
		matches := false
		for _, attribute := range node.Attr {
			if attribute.Key == "id" && attribute.Val == id {
				matches = true
			}
		}
		if matches {
			for _, attribute := range node.Attr {
				if attribute.Key == name {
					found = attribute.Val
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return found
}

func TestHTMLNestedDocumentsAndRelativeURLValues(t *testing.T) {
	const secret = "cedar'\"<&\\value?"
	r := structuredPolicyRedactor(aliasKeyRule("credentials", "password"), FieldRule{Name: "query", QueryParams: []string{"access_token"}, Action: "pseudonymize", Generator: "alias"})
	target := "/next?access_token=" + url.QueryEscape(secret) + "&public=ok"
	frame := `<input id="inside" name="password" value="` + stdhtml.EscapeString(secret) + `">`
	state, _ := json.Marshal(map[string]string{"password": secret})
	page := `<div><a id="link" href="` + stdhtml.EscapeString(target) + `">next</a>` +
		`<iframe id="frame" srcdoc="` + stdhtml.EscapeString(frame) + `"></iframe>` +
		`<div id="state" data-state="` + stdhtml.EscapeString(string(state)) + `"></div></div>`
	result, err := r.Transform(htmlToolRequest(page), "nested", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	protected := htmlToolContent(t, result.Body)
	protectedURL, err := url.Parse(htmlAttributeValue(t, protected, "link", "href"))
	if err != nil {
		t.Fatal(err)
	}
	if protectedURL.Query().Get("access_token") == secret || protectedURL.Query().Get("public") != "ok" {
		t.Fatal("relative URL query protection failed")
	}
	inside, _ := htmlPolicyValues(t, htmlAttributeValue(t, protected, "frame", "srcdoc"))
	if inside["inside"] == secret || !strings.HasPrefix(inside["inside"], "alias-") {
		t.Fatal("nested HTML attribute leaked")
	}
	var protectedState map[string]string
	if err := json.Unmarshal([]byte(htmlAttributeValue(t, protected, "state", "data-state")), &protectedState); err != nil {
		t.Fatal(err)
	}
	if protectedState["password"] == secret {
		t.Fatal("JSON attribute leaked")
	}
	restored := htmlToolContent(t, r.RestoreResponseForSession(result.Body, "application/json", "nested"))
	restoredURL, err := url.Parse(htmlAttributeValue(t, restored, "link", "href"))
	if err != nil {
		t.Fatal(err)
	}
	if restoredURL.Query().Get("access_token") != secret || restoredURL.Query().Get("public") != "ok" {
		t.Fatal("URL restoration changed value boundaries")
	}
	inside, _ = htmlPolicyValues(t, htmlAttributeValue(t, restored, "frame", "srcdoc"))
	if inside["inside"] != secret {
		t.Fatal("nested HTML restoration changed value")
	}
	if err := json.Unmarshal([]byte(htmlAttributeValue(t, restored, "state", "data-state")), &protectedState); err != nil {
		t.Fatal(err)
	}
	if protectedState["password"] != secret {
		t.Fatal("JSON attribute restoration changed value")
	}
}
