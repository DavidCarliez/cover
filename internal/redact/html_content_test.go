package redact

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

const (
	htmlFixtureContact = "ada" + "@" + "example.test"
	htmlFixtureAlias   = "person" + "@" + "masked.test"
)

func htmlReplaceText(from, to string) func(string) ([]htmlTextEdit, error) {
	return func(text string) ([]htmlTextEdit, error) {
		var edits []htmlTextEdit
		for cursor := 0; cursor < len(text); {
			index := strings.Index(text[cursor:], from)
			if index < 0 {
				break
			}
			start := cursor + index
			edits = append(edits, htmlTextEdit{start, start + len(from), to})
			cursor = start + len(from)
		}
		return edits, nil
	}
}

func htmlTestProtect(t *testing.T, source string, policy htmlContentPolicy) string {
	t.Helper()
	out, handled, err := protectHTMLContent(source, policy)
	if err != nil || !handled {
		t.Fatalf("HTML protection failed: handled=%v err=%v", handled, err)
	}
	return out
}

func htmlTestNodes(t *testing.T, text string) []*html.Node {
	t.Helper()
	context := &html.Node{Type: html.ElementNode, Data: "div", DataAtom: atom.Div}
	roots, err := html.ParseFragment(strings.NewReader(text), context)
	if err != nil {
		t.Fatal(err)
	}
	var nodes []*html.Node
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		nodes = append(nodes, node)
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	for _, node := range roots {
		walk(node)
	}
	return nodes
}

func htmlTestElement(t *testing.T, text, tag string, index int) *html.Node {
	t.Helper()
	for _, node := range htmlTestNodes(t, text) {
		if node.Type == html.ElementNode && node.Data == tag {
			if index == 0 {
				return node
			}
			index--
		}
	}
	t.Fatalf("missing %s element", tag)
	return nil
}

func TestHTMLContentEntitiesAndSplitInlineText(t *testing.T) {
	fixture := `<p>Contact: ad&#97;<strong>@exa</strong><em>mple.test</em>; keep <i>this</i>.</p>`
	out := htmlTestProtect(t, fixture, htmlContentPolicy{Text: htmlReplaceText(htmlFixtureContact, htmlFixtureAlias)})
	want := `<p>Contact: ` + htmlFixtureAlias + `<strong></strong><em></em>; keep <i>this</i>.</p>`
	if out != want {
		t.Fatalf("inline replacement lost unrelated content:\n got %s\nwant %s", out, want)
	}
}

func TestHTMLContentNormalizedWhitespaceMapsBackToNodes(t *testing.T) {
	fixture := "<p>Before <b>Ada</b>\n\t <i>Lovelace</i> after\n untouched.</p>"
	out := htmlTestProtect(t, fixture, htmlContentPolicy{Text: htmlReplaceText("Ada Lovelace", "Person")})
	want := "<p>Before <b>Person</b><i></i> after\n untouched.</p>"
	if out != want {
		t.Fatalf("normalized span moved or removed unrelated text:\n got %q\nwant %q", out, want)
	}
	unicodeFixture := `<p>Zoë&nbsp;<b>Ångström</b> / ✓</p>`
	out = htmlTestProtect(t, unicodeFixture, htmlContentPolicy{Text: htmlReplaceText("Zoë Ångström", "Person")})
	if out != `<p>Person<b></b> / ✓</p>` {
		t.Fatalf("Unicode/entity span was not preserved: %s", out)
	}
}

func TestHTMLContentDoesNotJoinSeparateBlocks(t *testing.T) {
	for _, source := range []string{
		`<div>ada@</div><div>example.test</div>`,
		`<p>ada@<br>example.test</p>`,
		`<p>ada@<input value="public">example.test</p>`,
	} {
		out := htmlTestProtect(t, source, htmlContentPolicy{Text: htmlReplaceText(htmlFixtureContact, htmlFixtureAlias)})
		if out != source {
			t.Fatalf("different logical text blocks were joined: %s", out)
		}
	}
}

func TestHTMLContentFormIdentitiesAndLaterLabels(t *testing.T) {
	selectField := func(names []string, value string) (string, error) {
		for _, name := range names {
			switch strings.ToLower(name) {
			case "credential", "password", "access phrase", "customer_name":
				return "opaque-" + value, nil
			}
		}
		return strings.ReplaceAll(value, htmlFixtureContact, htmlFixtureAlias), nil
	}
	fixtures := []string{
		`<input name="credential" value="amber-owl">`,
		`<input id="credential" value="amber-owl">`,
		`<input type="PASSWORD" value="amber-owl">`,
		`<input aria-label="Access phrase" value="amber-owl">`,
		`<label for="field">Access <b>phrase</b>:</label><input id="field" value="amber-owl">`,
		`<input id="field" value="amber-owl"><label for="field">Access phrase</label>`,
		`<label>Access phrase<input value="amber-owl"></label>`,
		`<input aria-labelledby="caption" value="amber-owl"><span id="caption">Access phrase</span>`,
		`<input name="customer&#95;name" value="amber&#45;owl">`,
	}
	for index, source := range fixtures {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			out := htmlTestProtect(t, source, htmlContentPolicy{Field: selectField})
			input := htmlTestElement(t, out, "input", 0)
			if got := htmlAttr(input, "value"); got != "opaque-amber-owl" {
				t.Fatalf("selected form value survived: %q", got)
			}
		})
	}
	out := htmlTestProtect(t, `<input name="ordinary" value="ada&#64;example.test">`, htmlContentPolicy{Field: selectField})
	if got := htmlAttr(htmlTestElement(t, out, "input", 0), "value"); got != htmlFixtureAlias {
		t.Fatalf("unselected field did not receive the detector fallback: %q", got)
	}
}

func TestHTMLContentTextareaAndSelectValues(t *testing.T) {
	policy := htmlContentPolicy{Field: func(names []string, value string) (string, error) {
		for _, name := range names {
			if name == "credential" {
				return "opaque-" + value, nil
			}
		}
		return value, nil
	}}
	fixture := `<textarea id="memo">amber &amp; owl</textarea><label for="memo">credential</label><select name="credential"><optgroup label="Group"><option value="amber">Owl</option><option>Heron</option></optgroup></select>`
	out := htmlTestProtect(t, fixture, policy)
	textarea := htmlTestElement(t, out, "textarea", 0)
	if got := joinHTMLNodes(htmlTextNodes(textarea)); got != "opaque-amber & owl" {
		t.Fatalf("textarea contents survived: %q", got)
	}
	first := htmlTestElement(t, out, "option", 0)
	if htmlAttr(first, "value") != "opaque-amber" || joinHTMLNodes(htmlTextNodes(first)) != "opaque-Owl" {
		t.Fatalf("select values did not inherit their field policy: %s", out)
	}
	second := htmlTestElement(t, out, "option", 1)
	if got := joinHTMLNodes(htmlTextNodes(second)); got != "opaque-Heron" {
		t.Fatalf("implicit option value survived: %q", got)
	}
}

func TestHTMLContentAttributeEntitiesAndURLValues(t *testing.T) {
	fixture := `<a title="ada&#64;example.test" href="https://example.test/search?owner=ada%40example.test&amp;page=2">public</a>`
	out := htmlTestProtect(t, fixture, htmlContentPolicy{Attribute: func(name, value string) (string, error) {
		value = strings.ReplaceAll(value, htmlFixtureContact, htmlFixtureAlias)
		return strings.ReplaceAll(value, "ada%40example.test", "person%40masked.test"), nil
	}})
	link := htmlTestElement(t, out, "a", 0)
	if htmlAttr(link, "title") != htmlFixtureAlias || htmlAttr(link, "href") != "https://example.test/search?owner=person%40masked.test&page=2" {
		t.Fatalf("decoded attribute content was not protected: %s", out)
	}
}

func TestHTMLContentRawTextAndComments(t *testing.T) {
	fixture := `<div><!--` + htmlFixtureContact + `--><script>const contact = "` + htmlFixtureContact + `"; if (1 < 2) {}</script><style>.card { content: "` + htmlFixtureContact + `"; }</style><p>` + htmlFixtureContact + `</p></div>`
	out := htmlTestProtect(t, fixture, htmlContentPolicy{Text: htmlReplaceText(htmlFixtureContact, htmlFixtureAlias)})
	if strings.Contains(out, htmlFixtureContact) || strings.Count(out, htmlFixtureAlias) != 4 || !strings.Contains(out, "if (1 < 2)") {
		t.Fatalf("literal script/style/comment text was not safely inspected: %s", out)
	}
}

func TestHTMLContentJSONScriptsAndClosingTagEscaping(t *testing.T) {
	for _, mediaType := range []string{"application/json", "application/ld+json", "application/vendor+json; charset=utf-8"} {
		t.Run(mediaType, func(t *testing.T) {
			key := "access" + "_phrase"
			source := `<script type="` + mediaType + `">{"` + key + `":"amber-owl","count":42}</script>`
			replacement := `</script><img src=x>`
			out := htmlTestProtect(t, source, htmlContentPolicy{JSON: func(value string) (string, error) {
				var data map[string]any
				if err := json.Unmarshal([]byte(value), &data); err != nil {
					return "", err
				}
				data[key] = replacement
				data["count"] = 73
				encoded, err := json.Marshal(data)
				// Deliberately undo Go's optional HTML escaping. The HTML
				// adapter, not this callback, owns its script boundary.
				return strings.ReplaceAll(string(encoded), `\u003c`, "<"), err
			}})
			script := htmlTestElement(t, out, "script", 0)
			var data map[string]any
			if err := json.Unmarshal([]byte(joinHTMLNodes(htmlTextNodes(script))), &data); err != nil {
				t.Fatal(err)
			}
			if data[key] != replacement || data["count"] != float64(73) || strings.Contains(out, "<img") {
				t.Fatalf("typed JSON protection or boundary escaping failed: %s", out)
			}
		})
	}
}

func TestHTMLContentJSONIdentityPrecedesAttributeTransformation(t *testing.T) {
	out := htmlTestProtect(t, `<script type="application/json">{"value":"amber-owl"}</script>`, htmlContentPolicy{
		Attribute: func(name, value string) (string, error) {
			if name == "type" {
				return "application/opaque", nil
			}
			return value, nil
		},
		JSON: func(value string) (string, error) {
			return strings.ReplaceAll(value, "amber-owl", "opaque-heron"), nil
		},
	})
	if strings.Contains(out, "amber-owl") || !strings.Contains(out, "opaque-heron") {
		t.Fatalf("changing the MIME attribute bypassed its original structured policy: %s", out)
	}
}

func TestHTMLContentRestorationCannotCreateMarkup(t *testing.T) {
	replacement := `Alice <img src=x> & "Bob"`
	policy := htmlContentPolicy{
		TextNodes: true,
		Field: func(_ []string, value string) (string, error) {
			return strings.ReplaceAll(value, "OPAQUE", replacement), nil
		},
		Attribute: func(_ string, value string) (string, error) {
			return strings.ReplaceAll(value, "OPAQUE", replacement), nil
		},
		Text: htmlReplaceText("OPAQUE", replacement),
	}
	fixture := `<p title="OPAQUE">OPAQUE<b> unaffected</b></p><input value="OPAQUE"><textarea>OPAQUE</textarea>`
	out := htmlTestProtect(t, fixture, policy)
	if strings.Contains(out, "<img") {
		t.Fatalf("restored content became markup: %s", out)
	}
	paragraph := htmlTestElement(t, out, "p", 0)
	if htmlAttr(paragraph, "title") != replacement || paragraph.FirstChild.Data != replacement || paragraph.FirstChild.NextSibling.Data != "b" {
		t.Fatalf("restoration did not preserve attribute/text/inline structure: %s", out)
	}
	if htmlAttr(htmlTestElement(t, out, "input", 0), "value") != replacement || joinHTMLNodes(htmlTextNodes(htmlTestElement(t, out, "textarea", 0))) != replacement {
		t.Fatalf("restored form values did not round trip: %s", out)
	}
}

func TestHTMLContentRestorationPreservesWhitespaceAndOtherNodes(t *testing.T) {
	fixture := "<p>OPAQUE  \n<b> public text </b>\t trailing</p>"
	out := htmlTestProtect(t, fixture, htmlContentPolicy{TextNodes: true, Text: htmlReplaceText("OPAQUE", "Ada Lovelace")})
	want := "<p>Ada Lovelace  \n<b> public text </b>\t trailing</p>"
	if out != want {
		t.Fatalf("node-local restoration changed unrelated text: %q", out)
	}
}

func TestHTMLContentRawReplacementCannotCloseItsContainer(t *testing.T) {
	for _, tag := range []string{"script", "style"} {
		source := "<" + tag + `>"OPAQUE"</` + tag + ">"
		out := htmlTestProtect(t, source, htmlContentPolicy{Text: htmlReplaceText("OPAQUE", "</"+tag+"><img src=x>")})
		if strings.Contains(out, "<img") || strings.Count(out, "</"+tag+">") != 1 {
			t.Fatalf("restored raw text escaped its container: %s", out)
		}
	}
	out := htmlTestProtect(t, `<!--OPAQUE--><p>public</p>`, htmlContentPolicy{Text: htmlReplaceText("OPAQUE", `--><img src=x>`)})
	for _, node := range htmlTestNodes(t, out) {
		if node.Type == html.ElementNode && node.Data == "img" {
			t.Fatalf("comment replacement became active markup: %s", out)
		}
	}
}

func TestHTMLContentRecognitionAndNoChangePreservation(t *testing.T) {
	ordinary := []string{
		"ordinary prose about <div> elements",
		`const markup = "<input value='public'>";`,
		"if (value < limit) { return value; }",
		"<T> generic(value T)",
		"<vector>items</vector>",
		"```go\nvar s = `<div>public</div>`\n```",
		"https://example.test/search?q=public",
	}
	for _, source := range ordinary {
		out, handled, err := protectHTMLContent(source, htmlContentPolicy{Text: htmlReplaceText("public", "private")})
		if err != nil || handled || out != source {
			t.Fatalf("ordinary source was treated as HTML: %q, %v, %v", source, handled, err)
		}
	}
	unchanged := []string{
		` <DIV title='A &amp; B'>public<br /></DIV> `,
		"<!DOCTYPE html>\r\n<html><head><title>public</title></head><body><p>public</p></body></html>",
		`<table><tbody><tr><td>public</td></tr></tbody></table>`,
		`<tr><td>public</td></tr>`,
		`<td>public</td>`,
		"```html\n<p>public</p>\n```",
		"Before\n~~~HTML\n<p>public</p>\n~~~\nAfter",
	}
	for _, source := range unchanged {
		out := htmlTestProtect(t, source, htmlContentPolicy{Text: htmlReplaceText("not-present", "private")})
		if out != source {
			t.Fatalf("unmodified HTML was normalized: %q => %q", source, out)
		}
	}
}

func TestHTMLContentFencesAndForcedBodies(t *testing.T) {
	source := "Before " + htmlFixtureContact + "\n```html\n<p>ada@<b>example.test</b></p>\n```\nAfter\n~~~html\n<p>" + htmlFixtureContact + "</p>\n~~~"
	out := htmlTestProtect(t, source, htmlContentPolicy{Text: htmlReplaceText(htmlFixtureContact, htmlFixtureAlias)})
	if strings.Contains(out, htmlFixtureContact) || strings.Count(out, htmlFixtureAlias) != 3 || !strings.Contains(out, "```html") || !strings.Contains(out, "~~~html") {
		t.Fatalf("fenced HTML or surrounding prose was not protected: %s", out)
	}
	out = htmlTestProtect(t, "Contact: "+htmlFixtureContact, htmlContentPolicy{Force: true, Text: htmlReplaceText(htmlFixtureContact, htmlFixtureAlias)})
	if out != "Contact: "+htmlFixtureAlias {
		t.Fatalf("known HTML body did not inspect plain text: %q", out)
	}
	out = htmlTestProtect(t, `<customer-card title="`+htmlFixtureContact+`"></customer-card>`, htmlContentPolicy{Force: true, Attribute: func(_ string, value string) (string, error) {
		return strings.ReplaceAll(value, htmlFixtureContact, htmlFixtureAlias), nil
	}})
	if !strings.Contains(out, htmlFixtureAlias) {
		t.Fatalf("forced custom element was not protected: %s", out)
	}
}

func TestHTMLContentRejectsTruncationAndAmbiguousRecovery(t *testing.T) {
	fixtures := []string{
		`<input value="amber-owl`,
		`<div><span`,
		`<script>const data = "amber-owl";`,
		`<style>.item { content: "amber-owl"; }`,
		`<textarea>amber-owl`,
		`<div><!--amber-owl`,
		`<input value="public" VALUE="amber-owl">`,
		`<input title="public"value="amber-owl">`,
		`<input value=amber=owl>`,
		`<input value=amber<owl>`,
		`<div title='amber-owl'/><p>public</p>`,
		`<table><tr><td>public</td></tr>amber-owl</table>`,
		`<plaintext>amber-owl`,
		`<!DOCTYPE html PUBLIC "amber-owl"><p>public</p>`,
		"```html\n<p>amber-owl</p>",
		"<p>amber\x00owl</p>",
		"<p>amber\xffowl</p>",
	}
	for index, source := range fixtures {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			out, handled, err := protectHTMLContent(source, htmlContentPolicy{})
			if !handled || !errors.Is(err, ErrUnsafeRequest) || out != "" {
				t.Fatalf("unsafe HTML was accepted: handled=%v err=%v out=%q", handled, err, out)
			}
			if strings.Contains(err.Error(), "amber") {
				t.Fatalf("error revealed source data: %v", err)
			}
		})
	}
}

func TestHTMLContentBounds(t *testing.T) {
	atLimit := "<p>" + strings.Repeat("x", maxHTMLContentBytes-len("<p></p>")) + "</p>"
	if got := htmlTestProtect(t, atLimit, htmlContentPolicy{}); got != atLimit {
		t.Fatal("exact input size limit changed unmodified HTML")
	}
	atDepth := strings.Repeat("<div>", maxHTMLDepth) + "public" + strings.Repeat("</div>", maxHTMLDepth)
	if got := htmlTestProtect(t, atDepth, htmlContentPolicy{}); got != atDepth {
		t.Fatal("exact nesting limit changed unmodified HTML")
	}
	fixtures := []string{
		atLimit + "x",
		"<div>" + atDepth + "</div>",
		"<div>" + strings.Repeat("<br>", maxHTMLNodes) + "</div>",
	}
	for index, source := range fixtures {
		out, handled, err := protectHTMLContent(source, htmlContentPolicy{})
		if !handled || !errors.Is(err, ErrUnsafeRequest) || out != "" {
			t.Fatalf("bound %d was not enforced: handled=%v err=%v", index, handled, err)
		}
	}
}

func TestHTMLContentRejectsInvalidPoliciesWithoutLeakingErrors(t *testing.T) {
	policies := []htmlContentPolicy{
		{Text: func(string) ([]htmlTextEdit, error) { return nil, errors.New("amber-owl") }},
		{Text: func(string) ([]htmlTextEdit, error) { return []htmlTextEdit{{-1, 2, "private"}}, nil }},
		{Text: func(string) ([]htmlTextEdit, error) { return []htmlTextEdit{{0, 9, "private"}, {1, 4, "private"}}, nil }},
		{Attribute: func(string, string) (string, error) { return "", errors.New("amber-owl") }},
		{Field: func([]string, string) (string, error) { return "", errors.New("amber-owl") }},
	}
	for index, policy := range policies {
		out, handled, err := protectHTMLContent(`<p title="amber-owl">amber-owl</p><input value="amber-owl">`, policy)
		if !handled || !errors.Is(err, ErrUnsafeRequest) || out != "" || strings.Contains(err.Error(), "amber-owl") {
			t.Fatalf("policy failure %d was not fail-closed: handled=%v err=%v out=%q", index, handled, err, out)
		}
	}
	for _, source := range []string{`<script type="application/json">{</script>`, `<script type="application/json">{"value":1}</script>`} {
		out, handled, err := protectHTMLContent(source, htmlContentPolicy{JSON: func(string) (string, error) { return "invalid", nil }})
		if !handled || !errors.Is(err, ErrUnsafeRequest) || out != "" {
			t.Fatalf("uninspectable JSON script was accepted: handled=%v err=%v", handled, err)
		}
	}
}

func TestHTMLContentForeignNamespacesAndIconShapes(t *testing.T) {
	source := `<div><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><path d="M0 0 L10 10"/><text>ad&#97;@<tspan>example.test</tspan></text><a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="https://example.test/?owner=amber-owl"><title>public</title></a></svg><math><mi>amber-owl</mi></math></div>`
	out := htmlTestProtect(t, source, htmlContentPolicy{
		Text: func(text string) ([]htmlTextEdit, error) {
			if strings.Contains(text, htmlFixtureContact) {
				return htmlReplaceText(htmlFixtureContact, htmlFixtureAlias)(text)
			}
			return htmlReplaceText("amber-owl", "opaque-heron")(text)
		},
		Attribute: func(_ string, value string) (string, error) {
			return strings.ReplaceAll(value, "amber-owl", "opaque-heron"), nil
		},
	})
	if strings.Contains(out, "amber-owl") || strings.Contains(out, htmlFixtureContact) {
		t.Fatalf("foreign text or URL attributes leaked: %s", out)
	}
	svg := htmlTestElement(t, out, "svg", 0)
	path := htmlTestElement(t, out, "path", 0)
	if svg.Namespace != "svg" || path.Namespace != "svg" || htmlAttr(svg, "viewBox") != "0 0 10 10" || htmlAttr(path, "d") != "M0 0 L10 10" {
		t.Fatalf("SVG namespace, case-sensitive attributes or icon geometry changed: %s", out)
	}
	link := htmlTestElement(t, out, "a", 0)
	found := false
	for _, attr := range link.Attr {
		if attr.Namespace == "xlink" && attr.Key == "href" && attr.Val == "https://example.test/?owner=opaque-heron" {
			found = true
		}
	}
	if !found || htmlTestElement(t, out, "mi", 0).Namespace != "math" {
		t.Fatalf("qualified attributes or MathML namespace were lost: %s", out)
	}
}

func TestHTMLContentForeignCDATAAndSafeRestoration(t *testing.T) {
	source := `<svg><text><![CDATA[` + htmlFixtureContact + `]]></text></svg>`
	replacement := `</text><script>public</script> & quoted`
	out := htmlTestProtect(t, source, htmlContentPolicy{Text: htmlReplaceText(htmlFixtureContact, replacement)})
	text := htmlTestElement(t, out, "text", 0)
	if joinHTMLNodes(htmlTextNodes(text)) != replacement || strings.Contains(out, "<script>") {
		t.Fatalf("foreign text replacement became markup: %s", out)
	}
	for _, node := range htmlTestNodes(t, out) {
		if node.Type == html.ElementNode && node.Data == "script" {
			t.Fatalf("foreign text created a script element: %s", out)
		}
	}
	broken := `<svg><text><![CDATA[amber-owl</text></svg>`
	out, handled, err := protectHTMLContent(broken, htmlContentPolicy{})
	if !handled || !errors.Is(err, ErrUnsafeRequest) || out != "" {
		t.Fatalf("incomplete foreign CDATA was accepted: handled=%v err=%v", handled, err)
	}
}

func TestHTMLContentOptionalEndTagsAndForeignNoChange(t *testing.T) {
	for _, source := range []string{
		"<ul>" + strings.Repeat("<li>public", maxHTMLDepth+1) + "</ul>",
		`<svg viewBox="0 0 10 10"><path d='M0 0 L10 10'/></svg>`,
		`<svg/>`,
		`<math><mrow><mi>x</mi><mo>+</mo><mn>1</mn></mrow></math>`,
	} {
		if out := htmlTestProtect(t, source, htmlContentPolicy{}); out != source {
			t.Fatalf("unmodified supported HTML changed: %s", out)
		}
	}
}

func TestHTMLContentCumulativeFenceAndIdentityBounds(t *testing.T) {
	fence := "```html\n<div>" + strings.Repeat("<br>", maxHTMLNodes/2) + "</div>\n```\n"
	label := strings.Repeat("x", 1024)
	fields := `<label for="shared">` + label + `</label>` + strings.Repeat(`<input id="shared" value="public">`, maxHTMLContentBytes/len(label)+1)
	for index, source := range []string{fence + fence, fields} {
		out, handled, err := protectHTMLContent(source, htmlContentPolicy{})
		if !handled || !errors.Is(err, ErrUnsafeRequest) || out != "" {
			t.Fatalf("cumulative budget %d was not enforced: handled=%v err=%v", index, handled, err)
		}
	}
}
