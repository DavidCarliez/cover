package redact

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Coordinates refer to bytes in the decoded, whitespace-normalized text passed
// to Text, not bytes in the original HTML source.
type htmlTextEdit struct {
	start, end  int
	replacement string
}

type htmlContentPolicy struct {
	Force bool
	// TextNodes is for restoration: generated aliases live wholly in one
	// text node, so the cached literal replacer need not join inline runs.
	TextNodes bool
	Field     func(names []string, value string) (string, error)
	Attribute func(name, value string) (string, error)
	Text      func(text string) ([]htmlTextEdit, error)
	JSON      func(text string) (string, error)
}

const (
	maxHTMLContentBytes = 4 << 20
	maxHTMLNodes        = 100000
	maxHTMLDepth        = 64
)

type htmlInspectionBudget struct {
	nodes, identityBytes int
}

func unsafeHTMLContentError() error {
	return fmt.Errorf("%w: malformed or unsupported HTML content", ErrUnsafeRequest)
}

// protectHTMLContent deliberately recognizes only a leading known HTML tag,
// an HTML5 doctype, or explicitly labelled HTML fences. Known HTTP bodies and
// srcdoc attributes use Force. Parser recovery must not discard source values.
func protectHTMLContent(text string, policy htmlContentPolicy) (output string, handled bool, err error) {
	candidate := policy.Force || looksLikeHTMLContent(strings.TrimSpace(text))
	var fences []htmlFence
	var fenceErr error
	if !candidate {
		fences, fenceErr = findHTMLFences(text)
	}
	if !candidate && len(fences) == 0 && fenceErr == nil {
		return text, false, nil
	}
	if len(text) > maxHTMLContentBytes || !utf8.ValidString(text) || strings.IndexByte(text, 0) >= 0 || fenceErr != nil {
		return "", true, unsafeHTMLContentError()
	}
	budget := &htmlInspectionBudget{identityBytes: maxHTMLContentBytes}
	if candidate {
		out, err := transformHTMLDocument(text, policy, budget)
		if err != nil {
			return "", true, unsafeHTMLContentError()
		}
		return out, true, nil
	}
	var out strings.Builder
	cursor := 0
	for _, fence := range fences {
		gap, err := transformHTMLLiteral(text[cursor:fence.start], policy.Text)
		if err != nil {
			return "", true, unsafeHTMLContentError()
		}
		body, err := transformHTMLDocument(text[fence.start:fence.end], policy, budget)
		if err != nil {
			return "", true, unsafeHTMLContentError()
		}
		out.WriteString(gap)
		out.WriteString(body)
		cursor = fence.end
	}
	gap, err := transformHTMLLiteral(text[cursor:], policy.Text)
	if err != nil {
		return "", true, unsafeHTMLContentError()
	}
	out.WriteString(gap)
	return out.String(), true, nil
}

type htmlFence struct{ start, end int }

func findHTMLFences(text string) ([]htmlFence, error) {
	var fences []htmlFence
	var marker byte
	width, bodyStart := 0, 0
	isHTML := false
	for start := 0; start < len(text); {
		end := strings.IndexByte(text[start:], '\n')
		next := len(text)
		if end < 0 {
			end = len(text)
		} else {
			end += start
			next = end + 1
		}
		line := strings.TrimSuffix(text[start:end], "\r")
		indent := 0
		for indent < len(line) && line[indent] == ' ' {
			indent++
		}
		if indent <= 3 {
			line = line[indent:]
			if len(line) >= 3 && (line[0] == '`' || line[0] == '~') {
				n := 1
				for n < len(line) && line[n] == line[0] {
					n++
				}
				if marker == 0 && n >= 3 {
					marker, width = line[0], n
					isHTML = strings.EqualFold(strings.TrimSpace(line[n:]), "html")
					bodyStart = next
				} else if marker == line[0] && n >= width && strings.TrimSpace(line[n:]) == "" {
					if isHTML {
						fences = append(fences, htmlFence{bodyStart, start})
					}
					marker, isHTML = 0, false
				}
			}
		}
		start = next
	}
	if marker != 0 && isHTML {
		return nil, unsafeHTMLContentError()
	}
	return fences, nil
}

func looksLikeHTMLContent(text string) bool {
	if strings.HasPrefix(text, "<!--") {
		return true
	}
	if len(text) >= 9 && strings.EqualFold(text[:9], "<!doctype") {
		return true
	}
	if len(text) < 2 || text[0] != '<' {
		return false
	}
	i := 1
	if text[i] == '/' {
		i++
	}
	start := i
	for i < len(text) && (text[i] >= 'a' && text[i] <= 'z' || text[i] >= 'A' && text[i] <= 'Z' || text[i] >= '0' && text[i] <= '9') {
		i++
	}
	if i == start || i < len(text) && !htmlSpace(text[i]) && text[i] != '>' && text[i] != '/' {
		return false
	}
	switch strings.ToLower(text[start:i]) {
	case "a", "abbr", "address", "area", "article", "aside", "audio", "b", "base", "bdi", "bdo", "blockquote", "body", "br", "button", "canvas", "caption", "cite", "code", "col", "colgroup", "data", "datalist", "dd", "del", "details", "dfn", "dialog", "div", "dl", "dt", "em", "embed", "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "head", "header", "hgroup", "hr", "html", "i", "iframe", "img", "input", "ins", "kbd", "label", "legend", "li", "link", "main", "map", "mark", "math", "menu", "meta", "meter", "nav", "noscript", "object", "ol", "optgroup", "option", "output", "p", "picture", "plaintext", "pre", "progress", "q", "rp", "rt", "ruby", "s", "samp", "script", "search", "section", "select", "slot", "small", "source", "span", "strong", "style", "sub", "summary", "sup", "svg", "table", "tbody", "td", "template", "textarea", "tfoot", "th", "thead", "time", "title", "tr", "track", "u", "ul", "var", "video", "wbr", "xmp":
		return true
	}
	return false
}

func htmlSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

func htmlVoid(tag string) bool {
	switch tag {
	case "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr":
		return true
	}
	return false
}

func htmlRaw(tag string) bool {
	switch tag {
	case "script", "style", "title", "textarea", "xmp", "iframe", "noembed", "noframes", "noscript":
		return true
	}
	return false
}

type htmlSourceProjection struct {
	text     strings.Builder
	attrs    map[html.Attribute]int
	comments map[string]int
	firstTag string
	document bool
}

// Tokenization is a preflight, not a substitute HTML parser. In particular it
// bounds nesting before tree construction and rejects incomplete/bogus tokens,
// duplicate attributes and lexical recovery that loses attribute boundaries.
func inspectHTMLSource(text string) (*htmlSourceProjection, error) {
	projection := &htmlSourceProjection{attrs: make(map[html.Attribute]int), comments: make(map[string]int)}
	z := html.NewTokenizer(strings.NewReader(text))
	z.SetMaxBuf(maxHTMLContentBytes)
	stack := make([]string, 0, maxHTMLDepth)
	count := 0
	for {
		foreign := htmlForeignContext(stack)
		z.AllowCDATA(foreign)
		kind := z.Next()
		raw := string(z.Raw())
		if kind == html.ErrorToken {
			if z.Err() != io.EOF || len(raw) != 0 || !foreign && len(stack) > 0 && htmlRaw(stack[len(stack)-1]) {
				return nil, unsafeHTMLContentError()
			}
			break
		}
		if kind != html.EndTagToken {
			count++
			if count > maxHTMLNodes {
				return nil, unsafeHTMLContentError()
			}
		}
		token := z.Token()
		switch kind {
		case html.TextToken:
			if strings.HasPrefix(raw, "<![CDATA[") && !strings.HasSuffix(raw, "]]>") {
				return nil, unsafeHTMLContentError()
			}
			projection.text.WriteString(token.Data)
		case html.CommentToken:
			if !strings.HasPrefix(raw, "<!--") || !strings.HasSuffix(raw, "-->") {
				return nil, unsafeHTMLContentError()
			}
			projection.comments[token.Data]++
		case html.DoctypeToken:
			if !strings.EqualFold(strings.TrimSpace(token.Data), "html") {
				return nil, unsafeHTMLContentError()
			}
			projection.document = true
		case html.StartTagToken, html.SelfClosingTagToken, html.EndTagToken:
			if !validHTMLTagLexeme(raw, kind == html.EndTagToken) || token.Data == "plaintext" {
				return nil, unsafeHTMLContentError()
			}
			if kind == html.EndTagToken {
				for i := len(stack) - 1; i >= 0; i-- {
					if stack[i] == token.Data {
						stack = stack[:i]
						break
					}
				}
				continue
			}
			if projection.firstTag == "" {
				projection.firstTag = token.Data
			}
			if token.Data == "html" || token.Data == "head" || token.Data == "body" {
				projection.document = true
			}
			for _, attr := range token.Attr {
				projection.attrs[htmlProjectionAttribute(attr)]++
			}
			if foreign {
				z.NextIsNotRawText()
			}
			if !htmlVoid(token.Data) {
				if kind == html.SelfClosingTagToken {
					if foreign || token.Data == "svg" || token.Data == "math" {
						continue
					}
					return nil, unsafeHTMLContentError()
				}
				// Account for the common optional end tags without treating a
				// long flat list or table as deeply nested input.
				if !foreign {
					stack = closeHTMLOptionalTag(stack, token.Data)
				}
				stack = append(stack, token.Data)
				if len(stack) > maxHTMLDepth {
					return nil, unsafeHTMLContentError()
				}
			}
		}
	}
	return projection, nil
}

// This lexical context is deliberately conservative at HTML integration
// points. The tree/source projection below still rejects any recovery that
// loses or reorders values, including ambiguous foreign-content transitions.
func htmlForeignContext(stack []string) bool {
	for i := len(stack) - 1; i >= 0; i-- {
		switch stack[i] {
		case "svg", "math":
			return true
		case "foreignobject", "desc", "title", "mi", "mo", "mn", "ms", "mtext", "annotation-xml":
			return false
		}
	}
	return false
}

func htmlProjectionAttribute(attr html.Attribute) html.Attribute {
	key := attr.Key
	if attr.Namespace != "" {
		key = attr.Namespace + ":" + key
	}
	return html.Attribute{Key: strings.ToLower(key), Val: attr.Val}
}

func closeHTMLOptionalTag(stack []string, next string) []string {
	for i := len(stack) - 1; i >= 0; i-- {
		current := stack[i]
		close := current == "li" && next == "li" ||
			(current == "dt" || current == "dd") && (next == "dt" || next == "dd") ||
			current == "option" && (next == "option" || next == "optgroup") ||
			current == "optgroup" && next == "optgroup" ||
			(current == "td" || current == "th") && (next == "td" || next == "th" || next == "tr") ||
			current == "tr" && next == "tr" ||
			(current == "thead" || current == "tbody" || current == "tfoot") && (next == "thead" || next == "tbody" || next == "tfoot") ||
			current == "p" && htmlBlock(next)
		if close {
			return closeHTMLOptionalTag(stack[:i], next)
		}
		if htmlBlock(current) && current != "p" && current != "td" && current != "th" && current != "option" {
			break
		}
	}
	return stack
}

func validHTMLTagLexeme(raw string, endTag bool) bool {
	if len(raw) < 3 || raw[0] != '<' || raw[len(raw)-1] != '>' {
		return false
	}
	i := 1
	if endTag {
		i++
	}
	for i < len(raw)-1 && !htmlSpace(raw[i]) && raw[i] != '/' {
		if strings.ContainsRune("<='\"`", rune(raw[i])) {
			return false
		}
		i++
	}
	// The tokenizer can discard duplicate attributes. Check the original
	// lexeme so a hidden later value is never mistaken for inspected content.
	seen := make(map[string]bool)
	for i < len(raw)-1 {
		space := false
		for i < len(raw)-1 && htmlSpace(raw[i]) {
			space = true
			i++
		}
		if i == len(raw)-1 {
			return true
		}
		if raw[i] == '/' {
			return !endTag && i == len(raw)-2
		}
		if endTag || !space {
			return false
		}
		start := i
		for i < len(raw)-1 && !htmlSpace(raw[i]) && raw[i] != '=' && raw[i] != '/' {
			if strings.ContainsRune("<'\"`", rune(raw[i])) {
				return false
			}
			i++
		}
		if i == start {
			return false
		}
		name := strings.ToLower(raw[start:i])
		if seen[name] {
			return false
		}
		seen[name] = true
		nameEnd := i
		for i < len(raw)-1 && htmlSpace(raw[i]) {
			i++
		}
		if i == len(raw)-1 || raw[i] != '=' {
			i = nameEnd
			continue
		}
		i++
		for i < len(raw)-1 && htmlSpace(raw[i]) {
			i++
		}
		if i == len(raw)-1 {
			return false
		}
		if raw[i] == '\'' || raw[i] == '"' {
			quote := raw[i]
			i++
			for i < len(raw)-1 && raw[i] != quote {
				i++
			}
			if i == len(raw)-1 {
				return false
			}
			i++
		} else {
			for i < len(raw)-1 && !htmlSpace(raw[i]) {
				if strings.ContainsRune("<='\"`", rune(raw[i])) {
					return false
				}
				i++
			}
		}
	}
	return true
}

func transformHTMLDocument(text string, policy htmlContentPolicy, budget *htmlInspectionBudget) (string, error) {
	source, err := inspectHTMLSource(text)
	if err != nil {
		return "", err
	}
	var root *html.Node
	if source.document {
		root, err = html.Parse(strings.NewReader(text))
	} else {
		contextTag := "div"
		switch source.firstTag {
		case "tr":
			contextTag = "tbody"
		case "td", "th":
			contextTag = "tr"
		case "tbody", "thead", "tfoot", "caption", "colgroup":
			contextTag = "table"
		case "col":
			contextTag = "colgroup"
		}
		context := &html.Node{Type: html.ElementNode, Data: contextTag, DataAtom: atom.Lookup([]byte(contextTag))}
		var nodes []*html.Node
		nodes, err = html.ParseFragment(strings.NewReader(text), context)
		root = &html.Node{Type: html.DocumentNode}
		for _, node := range nodes {
			root.AppendChild(node)
		}
	}
	if err != nil {
		return "", unsafeHTMLContentError()
	}
	var elements []*html.Node
	var treeText strings.Builder
	var inspect func(*html.Node, int) error
	inspect = func(node *html.Node, depth int) error {
		budget.nodes++
		if budget.nodes > maxHTMLNodes || depth > maxHTMLDepth {
			return unsafeHTMLContentError()
		}
		switch node.Type {
		case html.ElementNode:
			elements = append(elements, node)
			for _, attr := range node.Attr {
				source.attrs[htmlProjectionAttribute(attr)]--
			}
		case html.TextNode:
			treeText.WriteString(node.Data)
		case html.CommentNode:
			source.comments[node.Data]--
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			nextDepth := depth
			if child.Type == html.ElementNode {
				nextDepth++
			}
			if err := inspect(child, nextDepth); err != nil {
				return err
			}
		}
		return nil
	}
	if err := inspect(root, 0); err != nil {
		return "", err
	}
	for _, remaining := range source.attrs {
		if remaining != 0 {
			return "", unsafeHTMLContentError()
		}
	}
	for _, remaining := range source.comments {
		if remaining != 0 {
			return "", unsafeHTMLContentError()
		}
	}
	if !sameHTMLSourceText(source.text.String(), treeText.String()) {
		return "", unsafeHTMLContentError()
	}

	fields, err := collectHTMLFields(elements, budget)
	if err != nil {
		return "", err
	}
	jsonScripts := make(map[*html.Node]bool)
	for _, node := range elements {
		if node.Data == "script" {
			jsonScripts[node] = htmlJSONScript(node)
		}
	}
	changed := false
	blocked := make(map[*html.Node]bool)
	for _, node := range elements {
		names, field := fields[node]
		for i := range node.Attr {
			attr := &node.Attr[i]
			before := attr.Val
			value := before
			fieldValue := attr.Key == "value" || attr.Key == "content" && node.Data == "meta"
			if field && fieldValue && node.Data != "textarea" && node.Data != "select" && policy.Field != nil {
				value, err = policy.Field(names, before)
			} else if policy.Attribute != nil {
				name := attr.Key
				if attr.Namespace != "" {
					name = attr.Namespace + ":" + name
				}
				value, err = policy.Attribute(name, before)
			}
			if err != nil || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
				return "", unsafeHTMLContentError()
			}
			attr.Val = value
			changed = changed || value != before
		}
		if field && (node.Data == "textarea" || node.Data == "option") && policy.Field != nil {
			nodes := htmlTextNodes(node)
			before := joinHTMLNodes(nodes)
			value, fieldErr := policy.Field(names, before)
			if fieldErr != nil || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
				return "", unsafeHTMLContentError()
			}
			for _, textNode := range nodes {
				blocked[textNode] = true
			}
			if value != before {
				if len(nodes) == 0 {
					child := &html.Node{Type: html.TextNode, Data: value}
					node.AppendChild(child)
					blocked[child] = true
				} else {
					applyHTMLNodeEdits(nodes, []htmlTextEdit{{0, len(before), value}})
				}
				changed = true
			}
		}
	}

	var run []*html.Node
	flush := func() error {
		if len(run) == 0 {
			return nil
		}
		before := joinHTMLNodes(run)
		normalized := before
		if !policy.TextNodes {
			normalized = normalizeHTMLText(before)
		}
		edits, err := htmlPolicyTextEdits(normalized, policy.Text)
		if err != nil {
			return err
		}
		if len(edits) > 0 {
			if normalized != before {
				mapHTMLNormalizedEdits(before, edits)
			}
			changed = applyHTMLNodeEdits(run, edits) || changed
		}
		run = run[:0]
		return nil
	}
	var walk func(*html.Node) error
	walk = func(node *html.Node) error {
		if node.Type == html.TextNode {
			if blocked[node] {
				return flush()
			}
			run = append(run, node)
			if policy.TextNodes {
				return flush()
			}
			return nil
		}
		if node.Type == html.CommentNode {
			value, err := transformHTMLLiteral(node.Data, policy.Text)
			if err != nil {
				return err
			}
			changed = changed || value != node.Data
			node.Data = value
			return nil
		}
		boundary := node.Type == html.ElementNode && (htmlBlock(node.Data) || htmlRaw(node.Data) || node.Data == "input" || node.Data == "br" || node.Data == "option" || node.Namespace != "" && (node.Data == "svg" || node.Data == "math" || node.Data == "text"))
		if boundary {
			if err := flush(); err != nil {
				return err
			}
		}
		if node.Type == html.ElementNode && (node.Namespace == "" && htmlRaw(node.Data) && node.Data != "textarea" && node.Data != "title" || node.Data == "script" && jsonScripts[node]) {
			nodes := htmlTextNodes(node)
			before := joinHTMLNodes(nodes)
			value := before
			if node.Data == "script" && jsonScripts[node] && policy.JSON != nil {
				if !json.Valid([]byte(before)) {
					return unsafeHTMLContentError()
				}
				value, err = policy.JSON(before)
				if err == nil && (!utf8.ValidString(value) || !json.Valid([]byte(value))) {
					return unsafeHTMLContentError()
				}
				if value != before {
					value = strings.ReplaceAll(value, "<", `\u003c`)
				}
			} else {
				value, err = transformHTMLRaw(before, node.Data, policy.Text)
			}
			if err != nil {
				return unsafeHTMLContentError()
			}
			if value != before {
				if node.Namespace == "" && !safeHTMLRawText(node.Data, value) {
					return unsafeHTMLContentError()
				}
				if len(nodes) == 0 {
					node.AppendChild(&html.Node{Type: html.TextNode, Data: value})
				} else {
					applyHTMLNodeEdits(nodes, []htmlTextEdit{{0, len(before), value}})
				}
				changed = true
			}
			return nil
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if err := walk(child); err != nil {
				return err
			}
		}
		if boundary {
			return flush()
		}
		return nil
	}
	if err := walk(root); err != nil {
		return "", err
	}
	if err := flush(); err != nil {
		return "", err
	}
	if !changed {
		return text, nil
	}
	var out strings.Builder
	if err := html.Render(&out, root); err != nil {
		return "", unsafeHTMLContentError()
	}
	return out.String(), nil
}

// HTML recovery may drop whitespace around the document or the first newline
// in a pre/textarea. No non-whitespace text may disappear or change order.
func sameHTMLSourceText(source, tree string) bool {
	for i, j := 0, 0; ; {
		for i < len(source) && htmlSpace(source[i]) {
			i++
		}
		for j < len(tree) && htmlSpace(tree[j]) {
			j++
		}
		if i == len(source) || j == len(tree) {
			return i == len(source) && j == len(tree)
		}
		if source[i] != tree[j] {
			return false
		}
		i++
		j++
	}
}

func htmlAttr(node *html.Node, name string) string {
	for _, attr := range node.Attr {
		if attr.Key == name {
			return attr.Val
		}
	}
	return ""
}

func collectHTMLFields(elements []*html.Node, budget *htmlInspectionBudget) (map[*html.Node][]string, error) {
	labels := make(map[string][]string)
	ids := make(map[string]*html.Node)
	labelText := make(map[*html.Node]string)
	textFor := func(node *html.Node) string {
		if value, ok := labelText[node]; ok {
			return value
		}
		value := htmlLabelText(node)
		labelText[node] = value
		return value
	}
	for _, node := range elements {
		if id := htmlAttr(node, "id"); id != "" {
			ids[id] = node
		}
		if node.Data == "label" {
			id := htmlAttr(node, "for")
			if id != "" {
				labels[id] = append(labels[id], textFor(node))
			}
		}
	}
	fields := make(map[*html.Node][]string)
	// Repeated references to one large label must not multiply bounded input
	// into unbounded policy work. Charge even duplicate candidates.
	for _, node := range elements {
		if node.Namespace != "" {
			continue
		}
		switch node.Data {
		case "input", "textarea", "select", "option", "button", "meta", "param", "data":
		default:
			continue
		}
		var names []string
		seen := make(map[string]bool)
		add := func(value string) {
			budget.identityBytes -= len(value)
			if budget.identityBytes < 0 {
				return
			}
			value = strings.TrimSpace(value)
			if value == "" {
				return
			}
			if seen[value] {
				return
			}
			seen[value] = true
			names = append(names, value)
		}
		add(htmlAttr(node, "name"))
		add(htmlAttr(node, "id"))
		if strings.EqualFold(htmlAttr(node, "type"), "password") {
			add("password")
		}
		add(htmlAttr(node, "aria-label"))
		// Metadata pairs a name with a content or value attribute.
		add(htmlAttr(node, "property"))
		add(htmlAttr(node, "itemprop"))
		for _, label := range labels[htmlAttr(node, "id")] {
			add(label)
			add(strings.TrimSuffix(label, ":"))
		}
		for _, id := range strings.Fields(htmlAttr(node, "aria-labelledby")) {
			if label := ids[id]; label != nil {
				add(textFor(label))
			}
		}
		for parent := node.Parent; parent != nil; parent = parent.Parent {
			if parent.Data == "label" {
				label := textFor(parent)
				add(label)
				add(strings.TrimSuffix(label, ":"))
			}
			if node.Data == "option" && parent.Data == "select" {
				for _, name := range fields[parent] {
					add(name)
				}
				break
			}
		}
		if budget.identityBytes < 0 {
			return nil, unsafeHTMLContentError()
		}
		fields[node] = names
	}
	return fields, nil
}

func htmlLabelText(node *html.Node) string {
	var out strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n != node && n.Type == html.ElementNode {
			switch n.Data {
			case "input", "textarea", "select", "button", "script", "style":
				return
			}
		}
		if n.Type == html.TextNode {
			out.WriteString(n.Data)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return strings.Join(strings.Fields(out.String()), " ")
}

func htmlTextNodes(node *html.Node) []*html.Node {
	var nodes []*html.Node
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			nodes = append(nodes, n)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return nodes
}

func joinHTMLNodes(nodes []*html.Node) string {
	if len(nodes) == 1 {
		return nodes[0].Data
	}
	var out strings.Builder
	for _, node := range nodes {
		out.WriteString(node.Data)
	}
	return out.String()
}

func htmlBlock(tag string) bool {
	switch tag {
	case "address", "article", "aside", "blockquote", "body", "caption", "colgroup", "dd", "details", "dialog", "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "head", "header", "hgroup", "hr", "html", "legend", "li", "main", "menu", "nav", "ol", "p", "pre", "search", "section", "select", "summary", "table", "tbody", "td", "template", "tfoot", "th", "thead", "tr", "ul":
		return true
	}
	return false
}

func htmlJSONScript(node *html.Node) bool {
	mediaType, _, err := mime.ParseMediaType(htmlAttr(node, "type"))
	return err == nil && (mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"))
}

func htmlPolicyTextEdits(text string, transform func(string) ([]htmlTextEdit, error)) ([]htmlTextEdit, error) {
	if transform == nil {
		return nil, nil
	}
	edits, err := transform(text)
	if err != nil {
		return nil, unsafeHTMLContentError()
	}
	sort.SliceStable(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	end := 0
	for _, edit := range edits {
		if edit.start < end || edit.end < edit.start || edit.end > len(text) ||
			edit.start < len(text) && !utf8.RuneStart(text[edit.start]) ||
			edit.end < len(text) && !utf8.RuneStart(text[edit.end]) ||
			!utf8.ValidString(edit.replacement) || strings.IndexByte(edit.replacement, 0) >= 0 {
			return nil, unsafeHTMLContentError()
		}
		end = edit.end
	}
	return edits, nil
}

func transformHTMLLiteral(text string, transform func(string) ([]htmlTextEdit, error)) (string, error) {
	edits, err := htmlPolicyTextEdits(text, transform)
	if err != nil || len(edits) == 0 {
		return text, err
	}
	var out strings.Builder
	cursor := 0
	for _, edit := range edits {
		out.WriteString(text[cursor:edit.start])
		out.WriteString(edit.replacement)
		cursor = edit.end
	}
	out.WriteString(text[cursor:])
	return out.String(), nil
}

func transformHTMLRaw(text, tag string, transform func(string) ([]htmlTextEdit, error)) (string, error) {
	return transformHTMLLiteral(text, func(value string) ([]htmlTextEdit, error) {
		edits, err := htmlPolicyTextEdits(value, transform)
		for i := range edits {
			escape := "&lt;"
			if tag == "script" {
				escape = `\u003c`
			} else if tag == "style" {
				escape = `\3c `
			}
			edits[i].replacement = strings.ReplaceAll(edits[i].replacement, "<", escape)
		}
		return edits, err
	})
}

func safeHTMLRawText(tag, value string) bool {
	z := html.NewTokenizer(strings.NewReader("<" + tag + ">" + value + "</" + tag + ">"))
	if z.Next() != html.StartTagToken {
		return false
	}
	kind := z.Next()
	if value != "" {
		if kind != html.TextToken || string(z.Text()) != value {
			return false
		}
		kind = z.Next()
	}
	if kind != html.EndTagToken || z.Token().Data != tag {
		return false
	}
	return z.Next() == html.ErrorToken && z.Err() == io.EOF
}

func normalizeHTMLText(text string) string {
	needsNormalization, wasSpace := false, false
	for _, r := range text {
		space := unicode.IsSpace(r)
		if space && (r != ' ' || wasSpace) {
			needsNormalization = true
			break
		}
		wasSpace = space
	}
	if !needsNormalization {
		return text
	}
	var out strings.Builder
	inSpace := false
	for _, r := range text {
		if unicode.IsSpace(r) {
			if !inSpace {
				out.WriteByte(' ')
			}
			inSpace = true
		} else {
			out.WriteRune(r)
			inSpace = false
		}
	}
	return out.String()
}

// Map edit boundaries in normalized text back to the original decoded nodes.
// Each collapsed whitespace run is one indivisible normalized byte.
func mapHTMLNormalizedEdits(text string, edits []htmlTextEdit) {
	original, normalized := 0, 0
	boundary := func(target int) int {
		for normalized < target {
			r, size := utf8.DecodeRuneInString(text[original:])
			original += size
			if unicode.IsSpace(r) {
				for original < len(text) {
					next, width := utf8.DecodeRuneInString(text[original:])
					if !unicode.IsSpace(next) {
						break
					}
					original += width
				}
				normalized++
			} else {
				normalized += size
			}
		}
		return original
	}
	for i := range edits {
		start, end := edits[i].start, edits[i].end
		edits[i].start = boundary(start)
		edits[i].end = boundary(end)
	}
}

func applyHTMLNodeEdits(nodes []*html.Node, edits []htmlTextEdit) bool {
	changed, base, index := false, 0, 0
	for n, node := range nodes {
		before := node.Data
		end := base + len(before)
		var out strings.Builder
		cursor, touched := 0, false
		for index < len(edits) {
			edit := edits[index]
			if edit.start >= end && !(n == len(nodes)-1 && edit.start == end) {
				break
			}
			if edit.end <= base && edit.start < base {
				index++
				continue
			}
			touched = true
			start := max(cursor, edit.start-base)
			out.WriteString(before[cursor:start])
			if edit.start >= base {
				out.WriteString(edit.replacement)
			}
			cursor = max(cursor, min(len(before), edit.end-base))
			if edit.end > end {
				break
			}
			index++
		}
		if touched {
			out.WriteString(before[cursor:])
			node.Data = out.String()
			changed = changed || node.Data != before
		}
		base = end
	}
	return changed
}
