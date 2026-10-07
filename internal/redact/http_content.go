package redact

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/url"
	"strconv"
	"strings"
)

// httpContentPolicy supplies the protocol-agnostic transformations used while
// walking an HTTP transcript. Transform receives decoded scalars, JSON receives
// JSON bodies, and Text receives text bodies and surrounding non-HTTP text.
type httpContentPolicy struct {
	Transform func(selector, name, value string) (string, error)
	JSON      func(text string) (string, error)
	HTML      func(text string) (string, error)
	Text      func(text string) (string, error)

	// HeaderSelected identifies explicit whole-header policies. A nil callback
	// also permits restoration of an opaque whole-header alias.
	HeaderSelected func(name string) bool
	// Selected reports whether a rule selects a parameter name.
	Selected func(selector, name string) bool

	HasHeaders bool
	HasCookies bool
	HasQuery   bool
	HasForm    bool
	HasJSON    bool
}

const (
	maxHTTPContentBytes = 8 << 20
	maxHTTPLineBytes    = 64 << 10
	maxHTTPHeaders      = 256
	maxHTTPParameters   = 4096
	maxHTTPCookies      = 256
	maxHTTPMessages     = 32
)

// protectHTTPContent recognizes and safely rewrites HTTP transcripts and the
// two unframed protocol values that commonly appear in tool output: absolute
// URLs and application/x-www-form-urlencoded strings. A false handled result
// always returns text byte-for-byte so the caller can try another parser.
func protectHTTPContent(text string, policy httpContentPolicy) (output string, handled bool, err error) {
	if len(text) > maxHTTPContentBytes {
		if oversizedHTTPCandidate(text, policy) {
			return "", true, unsafeHTTPContentError()
		}
		return text, false, nil
	}
	if protected, handled, protectErr := protectCurlContent(text, policy); handled {
		return protected, true, protectErr
	}

	first, found := findHTTPMessageStart(text, 0)
	if found {
		if !policy.hasWork() {
			return text, true, nil
		}
		if policy.Transform == nil && (policy.HasHeaders || policy.HasCookies || policy.HasQuery || policy.HasForm) {
			return "", true, unsafeHTTPContentError()
		}

		var out strings.Builder
		out.Grow(len(text))
		cursor := 0
		messages := 0
		start := first
		for {
			messages++
			if messages > maxHTTPMessages {
				return "", true, unsafeHTTPContentError()
			}
			prefix, prefixErr := transformHTTPGap(text[cursor:start.line.start], policy)
			if prefixErr != nil {
				return "", true, unsafeHTTPContentError()
			}
			out.WriteString(prefix)

			message, end, expectsChain, transformErr := transformHTTPMessage(text, start, policy)
			if transformErr != nil {
				return "", true, unsafeHTTPContentError()
			}
			out.WriteString(message)
			cursor = end

			next, nextFound := findHTTPMessageStart(text, cursor)
			if expectsChain && cursor < len(text) {
				if !nextFound || !safeHTTPChainGap(text[cursor:next.line.start]) {
					return "", true, unsafeHTTPContentError()
				}
			}
			if !nextFound {
				suffix, suffixErr := transformHTTPGap(text[cursor:], policy)
				if suffixErr != nil {
					return "", true, unsafeHTTPContentError()
				}
				out.WriteString(suffix)
				return out.String(), true, nil
			}
			start = next
		}
	}

	if policy.HasQuery {
		if protected, ok, protectErr := protectStandaloneURL(text, policy); ok || protectErr != nil {
			if protectErr != nil {
				return "", true, unsafeHTTPContentError()
			}
			return protected, true, nil
		}
	}
	if policy.HasForm {
		if protected, ok, protectErr := protectStandaloneForm(text, policy); ok || protectErr != nil {
			if protectErr != nil {
				return "", true, unsafeHTTPContentError()
			}
			return protected, true, nil
		}
	}
	return text, false, nil
}

func transformHTTPGap(text string, policy httpContentPolicy) (string, error) {
	if text == "" || policy.Text == nil {
		return text, nil
	}
	return policy.Text(text)
}

func (p httpContentPolicy) hasWork() bool {
	return p.Transform != nil || p.JSON != nil || p.HTML != nil || p.Text != nil ||
		p.HasHeaders || p.HasCookies || p.HasQuery || p.HasForm || p.HasJSON
}

func unsafeHTTPContentError() error {
	return fmt.Errorf("%w: malformed or unsupported HTTP content", ErrUnsafeRequest)
}

func oversizedHTTPCandidate(text string, policy httpContentPolicy) bool {
	if _, ok := findHTTPMessageStart(text, 0); ok {
		return policy.hasWork()
	}
	start, end := trimHTTPOuterSpace(text)
	if start == end {
		return false
	}
	candidate := text[start:end]
	if strings.HasPrefix(candidate, "curl ") || strings.HasPrefix(candidate, "curl\t") || strings.HasPrefix(candidate, "$ curl ") {
		return policy.hasWork()
	}
	isURL := len(candidate) >= 7 && strings.EqualFold(candidate[:7], "http://") ||
		len(candidate) >= 8 && strings.EqualFold(candidate[:8], "https://")
	if policy.HasQuery && isURL {
		return true
	}
	return policy.HasForm && looksLikeStandaloneForm(candidate)
}

type httpLine struct {
	start      int
	contentEnd int
	end        int
}

func lineAt(text string, start int) (httpLine, bool) {
	if start < 0 || start >= len(text) {
		return httpLine{}, false
	}
	relativeEnd := strings.IndexByte(text[start:], '\n')
	if relativeEnd < 0 {
		return httpLine{start: start, contentEnd: len(text), end: len(text)}, true
	}
	newline := start + relativeEnd
	contentEnd := newline
	if contentEnd > start && text[contentEnd-1] == '\r' {
		contentEnd--
	}
	return httpLine{start: start, contentEnd: contentEnd, end: newline + 1}, true
}

type httpStartLine struct {
	line            httpLine
	indent          string
	marker          byte
	request         bool
	invalid         bool
	method          string
	targetStart     int
	targetEnd       int
	status          int
	reason          string
	reasonStart     int
	wrappedResponse bool
}

func findHTTPMessageStart(text string, from int) (httpStartLine, bool) {
	if from < 0 || from >= len(text) {
		return httpStartLine{}, false
	}
	position := from
	for position < len(text) {
		line, ok := lineAt(text, position)
		if !ok {
			return httpStartLine{}, false
		}
		if start, matched := parseHTTPStartLine(text, line); matched {
			start.invalid = start.invalid || line.contentEnd-line.start > maxHTTPLineBytes
			return start, true
		}
		if line.end <= position {
			break
		}
		position = line.end
	}
	return httpStartLine{}, false
}

func parseHTTPStartLine(text string, line httpLine) (httpStartLine, bool) {
	physical := text[line.start:line.contentEnd]
	indentEnd := 0
	for indentEnd < len(physical) && (physical[indentEnd] == ' ' || physical[indentEnd] == '\t') {
		indentEnd++
	}
	indent := physical[:indentEnd]

	type candidate struct {
		at        int
		marker    byte
		labelKind int // 0 is neutral, 1 requires a request, 2 requires a response.
	}
	candidates := []candidate{{at: indentEnd}}
	if indentEnd < len(physical) && (physical[indentEnd] == '>' || physical[indentEnd] == '<') {
		at := indentEnd + 1
		if at < len(physical) && physical[at] == ' ' {
			at++
		}
		candidates = append(candidates, candidate{at: at, marker: physical[indentEnd]})
	}
	labels := []struct {
		text string
		kind int
	}{
		{"raw request:", 1},
		{"raw response:", 2},
		{"http request:", 1},
		{"http response:", 2},
		{"request:", 1},
		{"response:", 2},
		{"httprequestresponse{httprequest=", 1},
		{", httpresponse=", 2},
	}
	remaining := physical[indentEnd:]
	for _, label := range labels {
		if len(remaining) < len(label.text) || !strings.EqualFold(remaining[:len(label.text)], label.text) {
			continue
		}
		at := indentEnd + len(label.text)
		for at < len(physical) && (physical[at] == ' ' || physical[at] == '\t') {
			at++
		}
		candidates = append(candidates, candidate{at: at, labelKind: label.kind})
	}

	for _, candidate := range candidates {
		wire := physical[candidate.at:]
		parsed, ok := parseHTTPWireStart(wire)
		if !ok {
			continue
		}
		if candidate.marker == '>' && !parsed.request {
			continue
		}
		if candidate.marker == '<' && parsed.request {
			continue
		}
		if candidate.labelKind == 1 && !parsed.request {
			continue
		}
		if candidate.labelKind == 2 && parsed.request {
			continue
		}
		parsed.line = line
		protocolAt := line.start + candidate.at
		parsed.indent = indent
		parsed.marker = candidate.marker
		parsed.wrappedResponse = strings.EqualFold(strings.TrimSpace(physical[indentEnd:candidate.at]), ", httpResponse=")
		if parsed.request {
			parsed.targetStart += protocolAt
			parsed.targetEnd += protocolAt
		} else if parsed.reason != "" {
			parsed.reasonStart += protocolAt
		}
		return parsed, true
	}
	return httpStartLine{}, false
}

func parseHTTPWireStart(wire string) (httpStartLine, bool) {
	spans, count := httpFieldSpans(wire)
	if count == 0 {
		return httpStartLine{}, false
	}
	first := wire[spans[0][0]:spans[0][1]]
	if strings.HasPrefix(first, "HTTP/") {
		if !validHTTPVersion(first) || count < 2 {
			return httpStartLine{invalid: true}, true
		}
		statusText := wire[spans[1][0]:spans[1][1]]
		if len(statusText) != 3 || !allASCIIDigits(statusText) {
			return httpStartLine{invalid: true}, true
		}
		status, _ := strconv.Atoi(statusText)
		reason := ""
		reasonStart := 0
		if count > 2 {
			reason = strings.TrimSpace(wire[spans[2][0]:])
			reasonStart = spans[2][0]
		}
		return httpStartLine{status: status, reason: reason, reasonStart: reasonStart}, true
	}
	if count != 3 || !validHTTPMethod(first) {
		return httpStartLine{}, false
	}
	target := wire[spans[1][0]:spans[1][1]]
	version := wire[spans[2][0]:spans[2][1]]
	if !validHTTPVersion(version) && strings.HasPrefix(version, "HTTP/") {
		return httpStartLine{request: true, invalid: true}, true
	}
	if !validHTTPVersion(version) || !recognizableHTTPRequestTarget(first, target) {
		return httpStartLine{}, false
	}
	return httpStartLine{
		request:     true,
		method:      first,
		targetStart: spans[1][0],
		targetEnd:   spans[1][1],
	}, true
}

func httpFieldSpans(text string) ([4][2]int, int) {
	var spans [4][2]int
	count := 0
	for position := 0; position < len(text); {
		for position < len(text) && (text[position] == ' ' || text[position] == '\t') {
			position++
		}
		if position == len(text) {
			break
		}
		start := position
		for position < len(text) && text[position] != ' ' && text[position] != '\t' {
			if text[position] < 0x20 || text[position] == 0x7f {
				return spans, 0
			}
			position++
		}
		spans[count] = [2]int{start, position}
		count++
		if count == len(spans) {
			break
		}
	}
	return spans, count
}

func validHTTPVersion(version string) bool {
	switch version {
	case "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0", "HTTP/3", "HTTP/3.0":
		return true
	default:
		return false
	}
}

func validHTTPMethod(method string) bool {
	if method == "" || len(method) > 32 {
		return false
	}
	hasLetter := false
	for i := range len(method) {
		character := method[i]
		if character >= 'A' && character <= 'Z' {
			hasLetter = true
			continue
		}
		if (character >= '0' && character <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character)) {
			continue
		}
		return false
	}
	return hasLetter
}

func recognizableHTTPRequestTarget(method, target string) bool {
	if target == "*" {
		return method == "OPTIONS"
	}
	if method == "CONNECT" {
		return target != "" && !strings.ContainsAny(target, " /?#\t\r\n")
	}
	if strings.HasPrefix(target, "/") {
		return true
	}
	lower := strings.ToLower(target)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func validateHTTPRequestTarget(method, target string) bool {
	if !recognizableHTTPRequestTarget(method, target) || !validPercentEscapes(target) {
		return false
	}
	if method == "CONNECT" || target == "*" {
		return true
	}
	lower := strings.ToLower(target)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		parsed, err := url.Parse(target)
		return err == nil && parsed.Fragment == "" && parsed.Host != "" &&
			(strings.EqualFold(parsed.Scheme, "http") || strings.EqualFold(parsed.Scheme, "https"))
	}
	parsed, err := url.ParseRequestURI(target)
	return err == nil && parsed.Fragment == "" && strings.HasPrefix(parsed.Path, "/")
}

type httpHeader struct {
	name       string
	lowerName  string
	value      string
	newValue   string
	valueStart int
	valueEnd   int
}

func parseHTTPHeaders(text string, start httpStartLine) ([]httpHeader, int, bool, error) {
	if start.line.end <= start.line.contentEnd {
		return nil, 0, false, unsafeHTTPContentError()
	}
	position := start.line.end
	headers := make([]httpHeader, 0, 16)
	for position < len(text) {
		line, ok := lineAt(text, position)
		if !ok || line.contentEnd-line.start > maxHTTPLineBytes {
			return nil, 0, false, unsafeHTTPContentError()
		}
		decorationEnd, decorationOK := httpHeaderDecorationEnd(text[line.start:line.contentEnd], start)
		if !decorationOK {
			return nil, 0, false, unsafeHTTPContentError()
		}
		wireStart := line.start + decorationEnd
		wire := text[wireStart:line.contentEnd]
		if wire == "" {
			return headers, line.end, false, nil
		}
		if wire[0] == ' ' || wire[0] == '\t' {
			return nil, 0, false, unsafeHTTPContentError()
		}
		colon := strings.IndexByte(wire, ':')
		if colon == 0 && len(wire) > 1 {
			if next := strings.IndexByte(wire[1:], ':'); next >= 0 {
				colon = next + 1
			}
		}
		if colon <= 0 {
			return nil, 0, false, unsafeHTTPContentError()
		}
		name := wire[:colon]
		if !validHTTPHeaderName(name) {
			return nil, 0, false, unsafeHTTPContentError()
		}
		rawValue := wire[colon+1:]
		if !validHTTPHeaderValue(rawValue) {
			return nil, 0, false, unsafeHTTPContentError()
		}
		leading := 0
		for leading < len(rawValue) && (rawValue[leading] == ' ' || rawValue[leading] == '\t') {
			leading++
		}
		trailing := len(rawValue)
		for trailing > leading && (rawValue[trailing-1] == ' ' || rawValue[trailing-1] == '\t') {
			trailing--
		}
		valueStart := wireStart + colon + 1 + leading
		valueEnd := wireStart + colon + 1 + trailing
		value := text[valueStart:valueEnd]
		headers = append(headers, httpHeader{
			name:       name,
			lowerName:  strings.ToLower(name),
			value:      value,
			newValue:   value,
			valueStart: valueStart,
			valueEnd:   valueEnd,
		})
		if len(headers) > maxHTTPHeaders {
			return nil, 0, false, unsafeHTTPContentError()
		}
		if line.end == len(text) {
			// EOF after a complete header is a header-only capture, not a
			// full message with a truncated body. A blank separator above
			// remains an explicit claim that body framing follows.
			return headers, len(text), true, nil
		}
		position = line.end
	}
	return nil, 0, false, unsafeHTTPContentError()
}

func httpHeaderDecorationEnd(physical string, start httpStartLine) (int, bool) {
	if start.marker != 0 {
		base := start.indent + string(start.marker)
		if !strings.HasPrefix(physical, base) {
			return 0, false
		}
		position := len(base)
		if position < len(physical) && physical[position] == ' ' {
			position++
		}
		return position, true
	}
	if start.indent == "" {
		return 0, true
	}
	if strings.HasPrefix(physical, start.indent) {
		return len(start.indent), true
	}
	if strings.Trim(physical, " \t") == "" {
		return len(physical), true
	}
	return 0, false
}

func validHTTPHeaderName(name string) bool {
	if name == "" {
		return false
	}
	start := 0
	if name[0] == ':' {
		if len(name) == 1 {
			return false
		}
		start = 1
	}
	for i := start; i < len(name); i++ {
		character := name[i]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func validHTTPHeaderValue(value string) bool {
	for i := range len(value) {
		if value[i] == '\t' {
			continue
		}
		if value[i] < 0x20 || value[i] == 0x7f {
			return false
		}
	}
	return true
}

type httpEdit struct {
	start       int
	end         int
	replacement string
}

func transformHTTPMessage(text string, start httpStartLine, policy httpContentPolicy) (string, int, bool, error) {
	if start.invalid {
		return "", 0, false, unsafeHTTPContentError()
	}
	headers, bodyStart, headersOnly, err := parseHTTPHeaders(text, start)
	if err != nil {
		return "", 0, false, err
	}

	var edits []httpEdit
	if start.request {
		target := text[start.targetStart:start.targetEnd]
		if !validateHTTPRequestTarget(start.method, target) {
			return "", 0, false, unsafeHTTPContentError()
		}
		transformedTarget, changed, targetErr := transformURLQuery(target, policy, true)
		if targetErr != nil {
			return "", 0, false, targetErr
		}
		if changed {
			edits = append(edits, httpEdit{start: start.targetStart, end: start.targetEnd, replacement: transformedTarget})
		}
	} else if start.reason != "" {
		transformedReason, reasonErr := callHTTPBody(policy.Text, start.reason)
		if reasonErr != nil || !validHTTPHeaderValue(transformedReason) {
			return "", 0, false, unsafeHTTPContentError()
		}
		if transformedReason != start.reason {
			edits = append(edits, httpEdit{start: start.reasonStart, end: start.reasonStart + len(start.reason), replacement: transformedReason})
		}
	}

	contentLength, hasContentLength, lengthErr := parseHTTPContentLength(headers, headersOnly)
	if lengthErr != nil {
		return "", 0, false, lengthErr
	}
	transferEncoded := hasUnsupportedTransferEncoding(headers)
	if !headersOnly && transferEncoded && policy.hasBodyWork() {
		return "", 0, false, unsafeHTTPContentError()
	}

	bodyEnd := bodyStart
	expectsChain := false
	if headersOnly {
		bodyEnd = bodyStart
	} else if hasContentLength {
		if contentLength > len(text)-bodyStart {
			return "", 0, false, unsafeHTTPContentError()
		}
		bodyEnd = bodyStart + contentLength
	} else if start.request {
		bodyEnd = bodyStart
	} else if responseHasNoBody(start.status) {
		expectsChain = start.status >= 100 && start.status < 200 && start.status != 101
		bodyEnd = bodyStart
	} else if responseEstablishesTunnel(start) {
		expectsChain = true
		bodyEnd = bodyStart
	} else {
		next, found := findHTTPMessageStart(text, bodyStart)
		if !found {
			bodyEnd = len(text)
			const emptyAnnotations = ", messageAnnotations=Annotations{comment='', highlightColor=NONE}}"
			if start.wrappedResponse && strings.HasSuffix(text[bodyStart:], emptyAnnotations) {
				bodyEnd -= len(emptyAnnotations)
			}
		} else {
			if !safeHTTPChainGap(text[bodyStart:next.line.start]) {
				return "", 0, false, unsafeHTTPContentError()
			}
			bodyEnd = bodyStart
			expectsChain = true
		}
	}
	if !headersOnly && !start.request && responseHasNoBody(start.status) && hasContentLength && contentLength != 0 {
		return "", 0, false, unsafeHTTPContentError()
	}
	if start.status == 101 && bodyStart < len(text) && policy.hasBodyWork() {
		return "", 0, false, unsafeHTTPContentError()
	}

	mediaType, mediaErr := httpMediaType(headers)
	if mediaErr != nil && bodyEnd > bodyStart && policy.hasBodyWork() {
		return "", 0, false, unsafeHTTPContentError()
	}
	if start.request && !hasContentLength && !transferEncoded && bodyStart < len(text) {
		next, found := findHTTPMessageStart(text, bodyStart)
		gapEnd := len(text)
		if found {
			gapEnd = next.line.start
		}
		if !safeHTTPChainGap(text[bodyStart:gapEnd]) {
			return "", 0, false, unsafeHTTPContentError()
		}
	}

	body := text[bodyStart:bodyEnd]
	if body != "" && hasUnsupportedContentEncoding(headers) && bodyNeedsProtection(mediaType, body, policy) {
		return "", 0, false, unsafeHTTPContentError()
	}

	for index := range headers {
		transformed, transformErr := transformHTTPHeader(headers[index], policy)
		if transformErr != nil {
			return "", 0, false, transformErr
		}
		if transformed != headers[index].value && structuralHTTPHeader(headers[index].lowerName) {
			return "", 0, false, unsafeHTTPContentError()
		}
		headers[index].newValue = transformed
	}

	transformedBody, bodyErr := transformHTTPBody(body, mediaType, policy)
	if bodyErr != nil {
		return "", 0, false, bodyErr
	}
	bodyChanged := transformedBody != body
	if hasContentLength && !headersOnly {
		canonicalLength := strconv.Itoa(len(transformedBody))
		for index := range headers {
			if headers[index].lowerName != "content-length" {
				continue
			}
			if bodyChanged || headers[index].newValue != headers[index].value {
				headers[index].newValue = canonicalLength
			}
		}
	}
	for _, header := range headers {
		if header.newValue != header.value {
			edits = append(edits, httpEdit{start: header.valueStart, end: header.valueEnd, replacement: header.newValue})
		}
	}
	if bodyChanged {
		edits = append(edits, httpEdit{start: bodyStart, end: bodyEnd, replacement: transformedBody})
	}

	block, applyErr := applyHTTPEdits(text, start.line.start, bodyEnd, edits)
	if applyErr != nil {
		return "", 0, false, applyErr
	}
	return block, bodyEnd, expectsChain, nil
}

func (p httpContentPolicy) hasBodyWork() bool {
	return p.Transform != nil || p.JSON != nil || p.HTML != nil || p.Text != nil || p.HasForm || p.HasJSON
}

func responseHasNoBody(status int) bool {
	return status >= 100 && status < 200 || status == 204 || status == 304
}

func responseEstablishesTunnel(start httpStartLine) bool {
	return !start.request && start.status >= 200 && start.status < 300 &&
		strings.Contains(strings.ToLower(start.reason), "connection established")
}

func parseHTTPContentLength(headers []httpHeader, headersOnly bool) (int, bool, error) {
	length := -1
	found := false
	for _, header := range headers {
		if header.lowerName != "content-length" {
			continue
		}
		for _, part := range strings.Split(header.value, ",") {
			part = strings.TrimSpace(part)
			if part == "" || !allASCIIDigits(part) {
				return 0, false, unsafeHTTPContentError()
			}
			parsed, err := strconv.ParseUint(part, 10, 63)
			// Header-only captures retain length metadata for an omitted body;
			// the content-size bound still applies to every body we inspect.
			if err != nil || !headersOnly && parsed > maxHTTPContentBytes {
				return 0, false, unsafeHTTPContentError()
			}
			if found && length != int(parsed) {
				return 0, false, unsafeHTTPContentError()
			}
			length = int(parsed)
			found = true
		}
	}
	return length, found, nil
}

func hasUnsupportedTransferEncoding(headers []httpHeader) bool {
	for _, header := range headers {
		if header.lowerName != "transfer-encoding" {
			continue
		}
		for _, encoding := range strings.Split(header.value, ",") {
			encoding = strings.TrimSpace(encoding)
			if encoding != "" && !strings.EqualFold(encoding, "identity") {
				return true
			}
		}
	}
	return false
}

func hasUnsupportedContentEncoding(headers []httpHeader) bool {
	for _, header := range headers {
		if header.lowerName != "content-encoding" {
			continue
		}
		for _, encoding := range strings.Split(header.value, ",") {
			encoding = strings.TrimSpace(encoding)
			if encoding != "" && !strings.EqualFold(encoding, "identity") {
				return true
			}
		}
	}
	return false
}

func httpMediaType(headers []httpHeader) (string, error) {
	value := ""
	for _, header := range headers {
		if header.lowerName != "content-type" {
			continue
		}
		if value != "" && !strings.EqualFold(value, header.value) {
			return "", unsafeHTTPContentError()
		}
		value = header.value
	}
	if value == "" {
		return "", nil
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return "", unsafeHTTPContentError()
	}
	return strings.ToLower(mediaType), nil
}

func structuralHTTPHeader(name string) bool {
	switch name {
	case "content-length", "content-type", "content-encoding", "transfer-encoding":
		return true
	default:
		return false
	}
}

func bodyNeedsProtection(mediaType, body string, policy httpContentPolicy) bool {
	if body == "" {
		return false
	}
	if mediaType == "application/x-www-form-urlencoded" {
		return policy.Transform != nil || policy.Text != nil || policy.HasForm
	}
	if isJSONMediaType(mediaType) || policy.HasJSON && looksLikeJSONContainer(body) {
		return policy.JSON != nil || policy.HasJSON
	}
	return policy.Text != nil
}

func transformHTTPHeader(header httpHeader, policy httpContentPolicy) (string, error) {
	value := header.value
	if header.lowerName == "cookie" || header.lowerName == "set-cookie" {
		wholeHeader := policy.HeaderSelected != nil && policy.HeaderSelected(header.name)
		// Whole-header policies own the original value, including allow rules.
		// Never feed their output into a second cookie-value transformation.
		if wholeHeader {
			transformed, err := callHTTPTransform(policy, selectorHeaders, header.name, value, true)
			if err != nil {
				return "", err
			}
			value = transformed
		} else if policy.Transform != nil || policy.HasCookies {
			transformed, err := transformCookieHeader(value, header.lowerName == "set-cookie", policy)
			if err != nil {
				// Restoration may receive an alias for the complete header
				// rather than cookie syntax. Never retry malformed pairs as text.
				if policy.HeaderSelected != nil || !policy.HasHeaders || strings.ContainsAny(value, "=;") {
					return "", err
				}
				transformed, err = callHTTPTransform(policy, selectorHeaders, header.name, value, true)
				if err != nil || transformed == value {
					return "", unsafeHTTPContentError()
				}
			}
			value = transformed
		}
	} else {
		var err error
		value, err = callHTTPTransform(policy, selectorHeaders, header.name, value, policy.HasHeaders)
		if err != nil {
			return "", err
		}
	}
	if !validHTTPHeaderValue(value) || strings.ContainsAny(value, "\r\n") {
		return "", unsafeHTTPContentError()
	}
	return value, nil
}

func transformCookieHeader(value string, setCookie bool, policy httpContentPolicy) (string, error) {
	segments, err := splitCookieSegments(value)
	if err != nil || len(segments) == 0 {
		return "", unsafeHTTPContentError()
	}
	limit := len(segments)
	if setCookie {
		limit = 1
	}
	var out strings.Builder
	out.Grow(len(value))
	cursor := 0
	for index, segment := range segments {
		if index >= limit {
			break
		}
		out.WriteString(value[cursor:segment.start])
		protected, protectErr := transformCookiePair(value[segment.start:segment.end], policy)
		if protectErr != nil {
			return "", protectErr
		}
		out.WriteString(protected)
		cursor = segment.end
	}
	suffix, suffixErr := callHTTPBody(policy.Text, value[cursor:])
	if suffixErr != nil {
		return "", suffixErr
	}
	out.WriteString(suffix)
	return out.String(), nil
}

type cookieSegment struct {
	start int
	end   int
}

func splitCookieSegments(value string) ([]cookieSegment, error) {
	segments := make([]cookieSegment, 0, 4)
	start := 0
	quoted := false
	escaped := false
	for index := range len(value) {
		character := value[index]
		if escaped {
			escaped = false
			continue
		}
		if quoted && character == '\\' {
			escaped = true
			continue
		}
		if character == '"' {
			quoted = !quoted
			continue
		}
		if character == ';' && !quoted {
			segments = append(segments, cookieSegment{start: start, end: index})
			start = index + 1
			if len(segments) > maxHTTPCookies {
				return nil, unsafeHTTPContentError()
			}
		}
	}
	if quoted || escaped {
		return nil, unsafeHTTPContentError()
	}
	segments = append(segments, cookieSegment{start: start, end: len(value)})
	if len(segments) > maxHTTPCookies {
		return nil, unsafeHTTPContentError()
	}
	return segments, nil
}

func transformCookiePair(segment string, policy httpContentPolicy) (string, error) {
	leading := 0
	for leading < len(segment) && (segment[leading] == ' ' || segment[leading] == '\t') {
		leading++
	}
	trailing := len(segment)
	for trailing > leading && (segment[trailing-1] == ' ' || segment[trailing-1] == '\t') {
		trailing--
	}
	pair := segment[leading:trailing]
	equals := strings.IndexByte(pair, '=')
	if equals <= 0 {
		return "", unsafeHTTPContentError()
	}
	name := strings.TrimSpace(pair[:equals])
	if !validHTTPHeaderName(name) || name[0] == ':' {
		return "", unsafeHTTPContentError()
	}
	rawValue := pair[equals+1:]
	decoded, quoted, err := decodeCookieValue(rawValue)
	if err != nil {
		return "", err
	}
	newName, err := callHTTPBody(policy.Text, name)
	if err != nil {
		return "", err
	}
	if newName != name && !validHTTPHeaderName(newName) {
		// Percent-encoding keeps a placeholder a valid cookie-name token.
		newName = url.QueryEscape(newName)
	}
	if newName != name && (!validHTTPHeaderName(newName) || newName[0] == ':') {
		return "", unsafeHTTPContentError()
	}
	transformed, err := callHTTPTransform(policy, selectorCookies, name, decoded, policy.HasCookies)
	if err != nil {
		return "", err
	}
	if transformed == decoded && newName == name {
		return segment, nil
	}
	encoded := rawValue
	if transformed != decoded {
		if encoded, err = encodeCookieValue(transformed, quoted); err != nil {
			return "", err
		}
	}
	return segment[:leading] + newName + pair[len(name):equals+1] + encoded + segment[trailing:], nil
}

func decodeCookieValue(value string) (string, bool, error) {
	if value == "" {
		return "", false, nil
	}
	if value[0] != '"' {
		if strings.ContainsAny(value, "\",;\r\n") || !validCookieBytes(value) {
			return "", false, unsafeHTTPContentError()
		}
		return value, false, nil
	}
	if len(value) < 2 || value[len(value)-1] != '"' {
		return "", false, unsafeHTTPContentError()
	}
	inner := value[1 : len(value)-1]
	var decoded strings.Builder
	decoded.Grow(len(inner))
	for index := 0; index < len(inner); index++ {
		if inner[index] == '\\' {
			index++
			if index >= len(inner) {
				return "", false, unsafeHTTPContentError()
			}
		}
		decoded.WriteByte(inner[index])
	}
	if strings.ContainsAny(decoded.String(), ";\r\n") || !validCookieBytes(decoded.String()) {
		return "", false, unsafeHTTPContentError()
	}
	return decoded.String(), true, nil
}

func encodeCookieValue(value string, quoted bool) (string, error) {
	if strings.ContainsAny(value, ";\r\n") || !validCookieBytes(value) {
		return "", unsafeHTTPContentError()
	}
	needsQuotes := quoted || strings.ContainsAny(value, " \t,\"\\")
	if !needsQuotes {
		return value, nil
	}
	var encoded strings.Builder
	encoded.Grow(len(value) + 2)
	encoded.WriteByte('"')
	for index := range len(value) {
		if value[index] == '"' || value[index] == '\\' {
			encoded.WriteByte('\\')
		}
		encoded.WriteByte(value[index])
	}
	encoded.WriteByte('"')
	return encoded.String(), nil
}

func validCookieBytes(value string) bool {
	for index := range len(value) {
		if value[index] < 0x20 || value[index] == 0x7f {
			return false
		}
	}
	return true
}

func transformHTTPBody(body, mediaType string, policy httpContentPolicy) (string, error) {
	if body == "" {
		return body, nil
	}
	if mediaType == "application/x-www-form-urlencoded" {
		if policy.Transform == nil {
			if policy.HasForm {
				return "", unsafeHTTPContentError()
			}
			return callHTTPBody(policy.Text, body)
		}
		transformed, _, err := transformParameterString(body, selectorFormFields, policy, policy.HasForm)
		return transformed, err
	}
	if isJSONMediaType(mediaType) || policy.HasJSON && looksLikeJSONContainer(body) {
		if policy.JSON == nil {
			return "", unsafeHTTPContentError()
		}
		transformed, err := callHTTPBody(policy.JSON, body)
		if err != nil || !json.Valid([]byte(transformed)) {
			return "", unsafeHTTPContentError()
		}
		return transformed, nil
	}
	if (mediaType == "text/html" || mediaType == "application/xhtml+xml") && policy.HTML != nil {
		return policy.HTML(body)
	}
	return callHTTPBody(policy.Text, body)
}

func isJSONMediaType(mediaType string) bool {
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

func looksLikeJSONContainer(text string) bool {
	trimmed := strings.TrimSpace(text)
	if len(trimmed) < 2 {
		return false
	}
	return trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}' ||
		trimmed[0] == '[' && trimmed[len(trimmed)-1] == ']'
}

func transformURLQuery(target string, policy httpContentPolicy, requestTarget bool) (string, bool, error) {
	queryAt := strings.IndexByte(target, '?')
	if queryAt < 0 {
		transformed, err := callHTTPBody(policy.Text, target)
		return transformed, transformed != target, err
	}
	queryEnd := len(target)
	if fragment := strings.IndexByte(target[queryAt+1:], '#'); fragment >= 0 {
		if requestTarget {
			return "", false, unsafeHTTPContentError()
		}
		queryEnd = queryAt + 1 + fragment
	}
	prefix, err := callHTTPBody(policy.Text, target[:queryAt])
	if err != nil {
		return "", false, err
	}
	transformed, changed, err := transformParameterString(target[queryAt+1:queryEnd], selectorQueryParams, policy, policy.HasQuery)
	if err != nil {
		return "", false, err
	}
	suffix, err := callHTTPBody(policy.Text, target[queryEnd:])
	if err != nil {
		return "", false, err
	}
	if !changed && prefix == target[:queryAt] && suffix == target[queryEnd:] {
		return target, false, nil
	}
	return prefix + "?" + transformed + suffix, true, nil
}

func transformParameterString(raw, selector string, policy httpContentPolicy, required bool) (string, bool, error) {
	if raw == "" {
		return raw, false, nil
	}
	var out strings.Builder
	out.Grow(len(raw))
	changed := false
	parameters := 0
	for position := 0; position <= len(raw); {
		end := strings.IndexByte(raw[position:], '&')
		if end < 0 {
			end = len(raw)
		} else {
			end += position
		}
		part := raw[position:end]
		parameters++
		if parameters > maxHTTPParameters {
			return "", false, unsafeHTTPContentError()
		}
		if part != "" {
			equals := strings.IndexByte(part, '=')
			rawName := part
			rawValue := ""
			if equals >= 0 {
				rawName = part[:equals]
				rawValue = part[equals+1:]
			}
			name, nameErr := url.QueryUnescape(rawName)
			value, valueErr := url.QueryUnescape(rawValue)
			if nameErr != nil || valueErr != nil {
				return "", false, unsafeHTTPContentError()
			}
			// Names and value-less parameters can carry data too, for example
			// ?AKIA... or a token used as a key, so detectors inspect them.
			newName, nameErr := callHTTPBody(policy.Text, name)
			if nameErr != nil {
				return "", false, nameErr
			}
			if newName != name {
				rawName = url.QueryEscape(newName)
			}
			transformed := value
			if equals >= 0 {
				var transformErr error
				transformed, transformErr = callHTTPTransform(policy, selector, name, value, required)
				if transformErr != nil {
					return "", false, transformErr
				}
			}
			switch {
			case transformed != value:
				out.WriteString(rawName)
				out.WriteByte('=')
				out.WriteString(url.QueryEscape(transformed))
				changed = true
			case newName != name:
				out.WriteString(rawName)
				if equals >= 0 {
					out.WriteString(part[equals:])
				}
				changed = true
			default:
				out.WriteString(part)
			}
		}
		if end == len(raw) {
			break
		}
		out.WriteByte('&')
		position = end + 1
	}
	if !changed {
		return raw, false, nil
	}
	return out.String(), true, nil
}

func protectStandaloneURL(text string, policy httpContentPolicy) (string, bool, error) {
	start, end := trimHTTPOuterSpace(text)
	if start == end {
		return text, false, nil
	}
	candidate := text[start:end]
	if strings.ContainsAny(candidate, " \t\r\n") {
		return text, false, nil
	}
	lower := strings.ToLower(candidate)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return text, false, nil
	}
	if !strings.Contains(candidate, "?") {
		return text, false, nil
	}
	// A literal % such as ?progress=50% is not a parseable query; the
	// plain-text pipeline protects its assignments instead.
	if !validPercentEscapes(candidate) {
		query := candidate[strings.IndexByte(candidate, '?')+1:]
		if fragment := strings.IndexByte(query, '#'); fragment >= 0 {
			query = query[:fragment]
		}
		if encodedSelectedParameter(query, selectorQueryParams, policy) {
			return "", true, unsafeHTTPContentError()
		}
		return text, false, nil
	}
	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Host == "" || parsed.User != nil ||
		(!strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https")) {
		return "", true, unsafeHTTPContentError()
	}
	transformed, _, err := transformURLQuery(candidate, policy, false)
	if err != nil {
		return "", true, err
	}
	return text[:start] + transformed + text[end:], true, nil
}

func protectStandaloneForm(text string, policy httpContentPolicy) (string, bool, error) {
	start, end := trimHTTPOuterSpace(text)
	if start == end {
		return text, false, nil
	}
	candidate := text[start:end]
	if !looksLikeStandaloneForm(candidate) {
		return text, false, nil
	}
	if !validPercentEscapes(candidate) {
		if encodedSelectedParameter(candidate, selectorFormFields, policy) {
			return "", true, unsafeHTTPContentError()
		}
		return text, false, nil
	}
	transformed, _, err := transformParameterString(candidate, selectorFormFields, policy, true)
	if err != nil {
		return "", true, err
	}
	return text[:start] + transformed + text[end:], true, nil
}

func looksLikeStandaloneForm(text string) bool {
	if text == "" || strings.ContainsAny(text, " \t\r\n?#/:{}\"'\\") {
		return false
	}
	parts := strings.Split(text, "&")
	if len(parts) > maxHTTPParameters {
		return true
	}
	seen := false
	for _, part := range parts {
		if part == "" {
			continue
		}
		equals := strings.IndexByte(part, '=')
		if equals <= 0 {
			return false
		}
		for index := range equals {
			character := part[index]
			if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') || strings.ContainsRune("_-.[]%+", rune(character)) {
				continue
			}
			return false
		}
		seen = true
	}
	return seen
}

func trimHTTPOuterSpace(text string) (int, int) {
	start := 0
	for start < len(text) && (text[start] == ' ' || text[start] == '\t' || text[start] == '\r' || text[start] == '\n') {
		start++
	}
	end := len(text)
	for end > start && (text[end-1] == ' ' || text[end-1] == '\t' || text[end-1] == '\r' || text[end-1] == '\n') {
		end--
	}
	return start, end
}

func callHTTPTransform(policy httpContentPolicy, selector, name, value string, required bool) (output string, err error) {
	if policy.Transform == nil {
		if required {
			return "", unsafeHTTPContentError()
		}
		return value, nil
	}
	defer func() {
		if recover() != nil {
			output = ""
			err = unsafeHTTPContentError()
		}
	}()
	transformed, transformErr := policy.Transform(selector, name, value)
	if transformErr != nil {
		return "", unsafeHTTPContentError()
	}
	return transformed, nil
}

func callHTTPBody(callback func(string) (string, error), body string) (output string, err error) {
	if callback == nil {
		return body, nil
	}
	defer func() {
		if recover() != nil {
			output = ""
			err = unsafeHTTPContentError()
		}
	}()
	transformed, transformErr := callback(body)
	if transformErr != nil {
		return "", unsafeHTTPContentError()
	}
	return transformed, nil
}

func applyHTTPEdits(text string, blockStart, blockEnd int, edits []httpEdit) (string, error) {
	if len(edits) == 0 {
		return text[blockStart:blockEnd], nil
	}
	var out strings.Builder
	out.Grow(blockEnd - blockStart)
	cursor := blockStart
	for _, edit := range edits {
		if edit.start < cursor || edit.end < edit.start || edit.end > blockEnd {
			return "", unsafeHTTPContentError()
		}
		out.WriteString(text[cursor:edit.start])
		out.WriteString(edit.replacement)
		cursor = edit.end
	}
	out.WriteString(text[cursor:blockEnd])
	return out.String(), nil
}

func safeHTTPChainGap(gap string) bool {
	position := 0
	for position < len(gap) {
		line, ok := lineAt(gap, position)
		if !ok {
			return false
		}
		trimmed := strings.TrimSpace(gap[line.start:line.contentEnd])
		if !safeHTTPGapLine(trimmed) {
			return false
		}
		if line.end <= position {
			return false
		}
		position = line.end
	}
	return true
}

func safeHTTPGapLine(line string) bool {
	if line == "" || strings.HasPrefix(line, "*") {
		return true
	}
	switch strings.ToLower(line) {
	case "request:", "response:", "raw request:", "raw response:", "http request:", "http response:",
		"```", "```http":
		return true
	default:
		return false
	}
}

// encodedSelectedParameter reports whether a parameter string that cannot be
// parsed has a percent-encoded name, such as api%5Fkey, that a rule selects.
// The plain-text pipeline matches only literal names, so it cannot protect
// that parameter in place.
func encodedSelectedParameter(raw, selector string, policy httpContentPolicy) bool {
	if policy.Selected == nil {
		return false
	}
	for _, part := range strings.Split(raw, "&") {
		name, _, _ := strings.Cut(part, "=")
		if !strings.ContainsAny(name, "%+") {
			continue
		}
		if decoded := lenientQueryUnescape(name); decoded != name && policy.Selected(selector, decoded) {
			return true
		}
	}
	return false
}

// lenientQueryUnescape decodes valid percent escapes and plus signs and keeps
// any other % literally.
func lenientQueryUnescape(text string) string {
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		switch {
		case text[i] == '%' && i+2 < len(text) && isHexDigit(text[i+1]) && isHexDigit(text[i+2]):
			b.WriteByte(unhexDigit(text[i+1])<<4 | unhexDigit(text[i+2]))
			i += 2
		case text[i] == '+':
			b.WriteByte(' ')
		default:
			b.WriteByte(text[i])
		}
	}
	return b.String()
}

func unhexDigit(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func validPercentEscapes(text string) bool {
	for index := 0; index < len(text); index++ {
		if text[index] != '%' {
			continue
		}
		if index+2 >= len(text) || !isHexDigit(text[index+1]) || !isHexDigit(text[index+2]) {
			return false
		}
		index += 2
	}
	return true
}

func isHexDigit(character byte) bool {
	return character >= '0' && character <= '9' || character >= 'a' && character <= 'f' || character >= 'A' && character <= 'F'
}

func allASCIIDigits(text string) bool {
	if text == "" {
		return false
	}
	for index := range len(text) {
		if text[index] < '0' || text[index] > '9' {
			return false
		}
	}
	return true
}
