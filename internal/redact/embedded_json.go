package redact

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"
)

const (
	maxPolicyDepth       = 64
	maxPolicyNodes       = 100000
	maxEmbeddedJSONDepth = 8
	maxEmbeddedJSONBytes = 4 << 20
)

type transformBudget struct {
	nodes         int
	embeddedBytes int
}

func (b *transformBudget) visit(depth int) error {
	if depth > maxPolicyDepth || b.nodes >= maxPolicyNodes {
		return ErrUnsafeRequest
	}
	b.nodes++
	return nil
}

func (b *transformBudget) embedded(size, depth int) error {
	if depth > maxEmbeddedJSONDepth || size < 0 || size > maxEmbeddedJSONBytes-b.embeddedBytes {
		return ErrUnsafeRequest
	}
	b.embeddedBytes += size
	return nil
}

type embeddedJSONStatus uint8

const (
	embeddedJSONNone embeddedJSONStatus = iota
	embeddedJSONParsed
	embeddedJSONMalformed
)

type embeddedJSONEncoding uint8

const (
	embeddedJSONRaw embeddedJSONEncoding = iota
	embeddedJSONShellDouble
)

type embeddedJSONCandidate struct {
	start    int
	end      int
	value    any
	encoding embeddedJSONEncoding
}

// locateEmbeddedJSON recognizes complete JSON documents, fenced JSON, nested
// JSON string encodings, and JSON documents after a line-oriented result
// prefix. It never treats an arbitrary brace in prose as a document.
func locateEmbeddedJSON(text string) (embeddedJSONCandidate, embeddedJSONStatus) {
	left, right := trimSpaceBounds(text, 0, len(text))
	if left == right {
		return embeddedJSONCandidate{}, embeddedJSONNone
	}

	if strings.HasPrefix(text[left:right], "```") {
		lineEnd := strings.IndexByte(text[left+3:right], '\n')
		if lineEnd < 0 {
			return embeddedJSONCandidate{start: left, end: right}, embeddedJSONMalformed
		}
		lineEnd += left + 3
		language := strings.TrimSpace(text[left+3 : lineEnd])
		if language != "" && !strings.EqualFold(language, "json") {
			return embeddedJSONCandidate{}, embeddedJSONNone
		}
		closing := strings.LastIndex(text[lineEnd+1:right], "```")
		if closing < 0 {
			return embeddedJSONCandidate{start: lineEnd + 1, end: right}, embeddedJSONMalformed
		}
		closing += lineEnd + 1
		if strings.TrimSpace(text[closing+3:right]) != "" {
			return embeddedJSONCandidate{}, embeddedJSONNone
		}
		start, end := trimSpaceBounds(text, lineEnd+1, closing)
		if start == end {
			return embeddedJSONCandidate{}, embeddedJSONNone
		}
		value, ok := decodeJSONDocument(text[start:end])
		if !ok {
			return embeddedJSONCandidate{start: start, end: end}, embeddedJSONMalformed
		}
		if !embeddedJSONValue(value) {
			return embeddedJSONCandidate{}, embeddedJSONNone
		}
		return embeddedJSONCandidate{start: start, end: end, value: value}, embeddedJSONParsed
	}

	first := text[left]
	if first == '{' || first == '[' || first == '"' {
		value, ok := decodeJSONDocument(text[left:right])
		if ok {
			if embeddedJSONValue(value) {
				return embeddedJSONCandidate{start: left, end: right, value: value}, embeddedJSONParsed
			}
			return embeddedJSONCandidate{}, embeddedJSONNone
		}
		if first == '"' || structuredJSONStart(text[left:right]) {
			return embeddedJSONCandidate{start: left, end: right}, embeddedJSONMalformed
		}
	}

	if candidate, status := locateCurlEmbeddedJSON(text, left, right); status != embeddedJSONNone {
		return candidate, status
	}

	start := -1
	for i := left; i < right; i++ {
		if text[i] == '{' || text[i] == '[' {
			start = i
			break
		}
	}
	if start <= left || !resultPrefix(text[left:start]) {
		return embeddedJSONCandidate{}, embeddedJSONNone
	}
	value, consumed, ok := decodeJSONPrefix(text[start:right])
	if !ok {
		return embeddedJSONCandidate{start: start, end: right}, embeddedJSONMalformed
	}
	if _, object := value.(map[string]any); !object {
		if _, array := value.([]any); !array {
			return embeddedJSONCandidate{}, embeddedJSONNone
		}
	}
	end := start + consumed
	if strings.TrimSpace(text[end:right]) != "" && !strings.HasPrefix(text[end:right], "\n") && !strings.HasPrefix(text[end:right], "\r") {
		return embeddedJSONCandidate{}, embeddedJSONNone
	}
	return embeddedJSONCandidate{start: start, end: end, value: value}, embeddedJSONParsed
}

func locateCurlEmbeddedJSON(text string, left, right int) (embeddedJSONCandidate, embeddedJSONStatus) {
	command := text[left:right]
	if strings.HasPrefix(command, "$ ") {
		left += 2
		command = text[left:right]
	}
	if !strings.HasPrefix(command, "curl") || len(command) == len("curl") || command[len("curl")] != ' ' && command[len("curl")] != '\t' {
		return embeddedJSONCandidate{}, embeddedJSONNone
	}

	for i := left + len("curl"); i < right; {
		for i < right && (text[i] == ' ' || text[i] == '\t' || text[i] == '\r' || text[i] == '\n') {
			i++
		}
		if i >= right {
			break
		}
		optionStart := i
		for i < right && text[i] != ' ' && text[i] != '\t' && text[i] != '\r' && text[i] != '\n' && text[i] != '=' {
			if text[i] == '\\' && i+1 < right {
				i += 2
				continue
			}
			i++
		}
		option := text[optionStart:i]
		isData := option == "-d" || option == "--data" || option == "--data-raw" || option == "--data-binary"
		if !isData {
			for i < right && text[i] != ' ' && text[i] != '\t' && text[i] != '\r' && text[i] != '\n' {
				i++
			}
			continue
		}
		if i < right && text[i] == '=' {
			i++
		} else {
			for i < right && (text[i] == ' ' || text[i] == '\t') {
				i++
			}
		}
		if i >= right {
			return embeddedJSONCandidate{start: i, end: i}, embeddedJSONMalformed
		}

		start, end := i, i
		encoding := embeddedJSONRaw
		var payload string
		switch text[i] {
		case '\'':
			start = i + 1
			end = strings.IndexByte(text[start:right], '\'')
			if end < 0 {
				return embeddedJSONCandidate{start: start, end: right}, embeddedJSONMalformed
			}
			end += start
			payload = text[start:end]
		case '"':
			start = i + 1
			end = start
			for end < right {
				if text[end] == '\\' && end+1 < right {
					end += 2
					continue
				}
				if text[end] == '"' {
					break
				}
				end++
			}
			if end >= right {
				return embeddedJSONCandidate{start: start, end: right}, embeddedJSONMalformed
			}
			var ok bool
			payload, ok = decodeShellDouble(text[start:end])
			if !ok {
				return embeddedJSONCandidate{start: start, end: end}, embeddedJSONMalformed
			}
			encoding = embeddedJSONShellDouble
		default:
			for end < right && text[end] != ' ' && text[end] != '\t' && text[end] != '\r' && text[end] != '\n' {
				end++
			}
			payload = text[start:end]
		}

		trimmed := strings.TrimSpace(payload)
		if trimmed == "" || trimmed[0] != '{' && trimmed[0] != '[' {
			return embeddedJSONCandidate{}, embeddedJSONNone
		}
		value, ok := decodeJSONDocument(payload)
		if !ok {
			return embeddedJSONCandidate{start: start, end: end, encoding: encoding}, embeddedJSONMalformed
		}
		return embeddedJSONCandidate{start: start, end: end, value: value, encoding: encoding}, embeddedJSONParsed
	}
	return embeddedJSONCandidate{}, embeddedJSONNone
}

func decodeShellDouble(value string) (string, bool) {
	var output strings.Builder
	output.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			output.WriteByte(value[i])
			continue
		}
		if i+1 >= len(value) {
			return "", false
		}
		i++
		switch value[i] {
		case '\\', '"', '$', '`':
			output.WriteByte(value[i])
		case '\n':
		default:
			output.WriteByte('\\')
			output.WriteByte(value[i])
		}
	}
	return output.String(), true
}

func encodeShellDouble(value string) string {
	var output strings.Builder
	output.Grow(len(value))
	for i := range len(value) {
		switch value[i] {
		case '\\', '"', '$', '`':
			output.WriteByte('\\')
		}
		output.WriteByte(value[i])
	}
	return output.String()
}

func looksLikeEmbeddedJSON(text string) bool {
	left, right := trimSpaceBounds(text, 0, len(text))
	if left == right {
		return false
	}
	if strings.HasPrefix(text[left:right], "```") {
		lineEnd := strings.IndexByte(text[left+3:right], '\n')
		if lineEnd < 0 {
			return false
		}
		language := strings.TrimSpace(text[left+3 : left+3+lineEnd])
		return language == "" || strings.EqualFold(language, "json")
	}
	if text[left] == '"' || structuredJSONStart(text[left:right]) {
		return true
	}
	command := strings.TrimPrefix(text[left:right], "$ ")
	if strings.HasPrefix(command, "curl ") &&
		(strings.Contains(command, " --data ") || strings.Contains(command, " --data=") ||
			strings.Contains(command, " --data-raw ") || strings.Contains(command, " --data-raw=") ||
			strings.Contains(command, " --data-binary ") || strings.Contains(command, " --data-binary=") ||
			strings.Contains(command, " -d ") || strings.Contains(command, " -d=")) &&
		(strings.Contains(command, "{") || strings.Contains(command, "[")) {
		return true
	}
	for i := left + 1; i < right; i++ {
		if text[i] == '{' || text[i] == '[' {
			return resultPrefix(text[left:i])
		}
	}
	return false
}

func structuredJSONStart(text string) bool {
	if text == "" {
		return false
	}
	first := text[0]
	if first != '{' && first != '[' {
		return false
	}
	index := 1
	for index < len(text) && (text[index] == ' ' || text[index] == '\t' || text[index] == '\r' || text[index] == '\n') {
		index++
	}
	if index == len(text) {
		return true
	}
	if first == '{' {
		if text[index] != '}' {
			return text[index] == '"'
		}
		_, end := trimSpaceBounds(text, index+1, len(text))
		return end == index+1
	}
	switch text[index] {
	case '"', '{', '[', '-', 't', 'f', 'n':
		return true
	case ']':
		_, end := trimSpaceBounds(text, index+1, len(text))
		return end == index+1
	default:
		return text[index] >= '0' && text[index] <= '9'
	}
}

func trimSpaceBounds(text string, start, end int) (int, int) {
	for start < end {
		switch text[start] {
		case ' ', '\t', '\r', '\n':
			start++
		default:
			goto right
		}
	}
right:
	for end > start {
		switch text[end-1] {
		case ' ', '\t', '\r', '\n':
			end--
		default:
			return start, end
		}
	}
	return start, end
}

func decodeJSONDocument(text string) (any, bool) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, false
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, false
	}
	return value, true
}

func decodeJSONPrefix(text string) (any, int, bool) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, 0, false
	}
	return value, int(dec.InputOffset()), true
}

func embeddedJSONValue(value any) bool {
	switch value := value.(type) {
	case map[string]any, []any:
		return true
	case string:
		trimmed := strings.TrimSpace(value)
		return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[' || trimmed[0] == '"')
	default:
		return false
	}
}

func resultPrefix(prefix string) bool {
	trimmed := strings.TrimSpace(prefix)
	if trimmed == "" || len(trimmed) > 4096 || strings.ContainsAny(trimmed, "{}[]") {
		return false
	}
	lower := strings.ToLower(trimmed)
	recognized := false
	for _, marker := range []string{"result", "output", "response", "stdout", "stderr", "body", "returned", "received"} {
		if strings.Contains(lower, marker) {
			recognized = true
			break
		}
	}
	if !recognized && (strings.HasPrefix(lower, "$ curl ") || strings.HasPrefix(lower, "curl ") || strings.HasPrefix(lower, "$ wget ") || strings.HasPrefix(lower, "wget ")) {
		recognized = true
	}
	if !recognized {
		return false
	}
	if strings.HasSuffix(trimmed, ":") {
		return true
	}
	if (strings.HasPrefix(lower, "$ curl ") || strings.HasPrefix(lower, "curl ") ||
		strings.HasPrefix(lower, "$ wget ") || strings.HasPrefix(lower, "wget ")) &&
		(strings.Contains(prefix, "\n") || strings.Contains(prefix, "\r")) {
		return true
	}
	if !strings.HasSuffix(trimmed, "=") {
		return false
	}
	label := strings.TrimSpace(strings.TrimSuffix(lower, "="))
	switch label {
	case "result", "output", "response", "stdout", "stderr", "body":
		return true
	default:
		return false
	}
}

// selectedJSONFieldNeedsParser reports whether malformed JSON text gives a
// selected key a value that the plain-text selector net cannot protect: an
// object, an array, a string that does not end on its line, a value on
// another line than its key, or a key written with escapes. Scalar values
// of selected keys in malformed JSON, NDJSON or JSON-like source are
// protected as plain-text assignments instead of rejecting the request.
func (r *Redactor) selectedJSONFieldNeedsParser(text string) bool {
	if !r.hasKeyRules {
		return false
	}
	for i := 0; i < len(text); i++ {
		if text[i] != '"' {
			continue
		}
		start := i
		i++
		escaped := false
		for i < len(text) {
			if escaped {
				escaped = false
				i++
				continue
			}
			if text[i] == '\\' {
				escaped = true
				i++
				continue
			}
			if text[i] == '"' {
				break
			}
			i++
		}
		if i >= len(text) {
			return false
		}
		j := i + 1
		newline := false
		skipSpace := func() {
			for j < len(text) && (text[j] == ' ' || text[j] == '\t' || text[j] == '\r' || text[j] == '\n') {
				newline = newline || text[j] == '\r' || text[j] == '\n'
				j++
			}
		}
		skipSpace()
		if j >= len(text) || text[j] != ':' {
			continue
		}
		name, err := strconv.Unquote(text[start : i+1])
		if err != nil {
			continue
		}
		if _, matched := r.fieldRule(selectorKeys, name); !matched {
			continue
		}
		// The plain-text net matches a literal name and value on one line.
		if name != text[start+1:i] {
			return true
		}
		j++
		skipSpace()
		if j >= len(text) {
			continue
		}
		if newline {
			return true
		}
		switch text[j] {
		case '{', '[':
			return true
		case '"':
			if !textAssignmentQuoted.MatchString(text[j:]) {
				return true
			}
		}
	}
	return false
}

var textAssignmentQuoted = regexp.MustCompile(`^"(?:[^"\\\r\n]|\\.)*"`)

type protocolObjectKind uint8

const (
	protocolBusiness protocolObjectKind = iota
	protocolStructuredBusiness
	protocolEnvelope
	protocolMessage
	protocolToolCall
	protocolFunction
	protocolFunctionOutput
	protocolToolUse
	protocolToolResult
	protocolContentBlock
	protocolReasoning
	protocolImage
	protocolMCPEnvelope
	protocolMCPResult
	protocolMCPParams
	protocolSchemaEnvelope
	protocolToolDefinition
	protocolAnthropicToolDefinition
	protocolMCPToolDefinition
	protocolFunctionDefinition
	protocolResponseFormat
	protocolResponseText
	protocolSchemaFormat
	protocolMCPToolListEnvelope
	protocolMCPToolList
)

func classifyProtocolObject(object map[string]any, parent protocolObjectKind, edge string) protocolObjectKind {
	if parent == protocolStructuredBusiness {
		return protocolStructuredBusiness
	}
	if edge == "structuredContent" || edge == "structured_content" || edge == "arguments" ||
		edge == "input" && parent == protocolToolUse || edge == "output" && parent == protocolFunctionOutput {
		return protocolStructuredBusiness
	}

	// Schema privileges originate only at a recognizable protocol document
	// root. In particular, decoded content and arguments stay business data.
	if parent == protocolBusiness && edge == "" {
		if looksSchemaEnvelope(object) {
			return protocolSchemaEnvelope
		}
		if looksMCPToolListEnvelope(object) {
			return protocolMCPToolListEnvelope
		}
	}
	if kind, ok := classifySchemaContext(object, parent, edge); ok {
		return kind
	}

	typ := lowerString(object["type"])
	role := lowerString(object["role"])
	if object["encrypted_content"] != nil && (strings.HasPrefix(typ, "response.") || strings.Contains(typ, "reasoning")) {
		return protocolReasoning
	}

	if value, _ := object["jsonrpc"].(string); value == "2.0" {
		return protocolMCPEnvelope
	}
	if parent == protocolMCPEnvelope {
		switch edge {
		case "result", "error":
			return protocolMCPResult
		case "params":
			return protocolMCPParams
		}
	}
	if parent == protocolMCPParams && edge == "arguments" {
		return protocolStructuredBusiness
	}
	if parent == protocolToolCall && (edge == "function" || edge == "custom") {
		return protocolFunction
	}
	if (parent == protocolEnvelope || parent == protocolSchemaEnvelope) && edge == "tools" {
		return protocolToolCall
	}
	if parent != protocolBusiness && edge == "reasoning" {
		return protocolReasoning
	}
	if parent == protocolEnvelope || parent == protocolSchemaEnvelope {
		switch edge {
		case "choices":
			return protocolEnvelope
		case "message", "delta":
			return protocolMessage
		}
	}

	if parent == protocolMessage && edge == "tool_calls" && object["function"] != nil {
		return protocolToolCall
	}
	switch typ {
	case "function_call", "custom_tool_call", "tool_call":
		if object["arguments"] != nil || object["function"] != nil || object["call_id"] != nil {
			return protocolToolCall
		}
	case "function":
		if object["function"] != nil && (parent == protocolMessage || parent == protocolEnvelope || parent == protocolSchemaEnvelope) {
			return protocolToolCall
		}
	case "function_call_output", "custom_tool_call_output":
		if object["output"] != nil || object["call_id"] != nil {
			return protocolFunctionOutput
		}
	case "tool_use":
		if object["input"] != nil || object["name"] != nil || object["id"] != nil {
			return protocolToolUse
		}
	case "tool_result":
		if object["content"] != nil || object["tool_use_id"] != nil {
			return protocolToolResult
		}
	case "reasoning":
		return protocolReasoning
	case "image", "input_image", "output_image", "image_url", "image_generation_call":
		return protocolImage
	case "text", "input_text", "output_text", "document", "resource", "resource_link":
		if parent != protocolBusiness || object["text"] != nil || object["source"] != nil || object["uri"] != nil {
			return protocolContentBlock
		}
	}
	if object["b64_json"] != nil {
		return protocolImage
	}
	if imageURL, ok := object["image_url"].(string); ok && isImageDataURL(imageURL) {
		return protocolImage
	}
	for _, value := range object {
		if text, ok := value.(string); ok && isImageDataURL(text) {
			return protocolImage
		}
	}

	if role == "tool" && object["content"] != nil {
		return protocolMessage
	}
	if parent != protocolBusiness && edge == "messages" && knownMessageRole(role) {
		return protocolMessage
	}
	if knownMessageRole(role) && object["content"] != nil && (parent == protocolEnvelope || parent == protocolSchemaEnvelope || parent == protocolMessage) {
		return protocolMessage
	}
	if parent == protocolMCPResult && edge == "content" {
		return protocolContentBlock
	}
	if looksAgentEnvelope(object) {
		return protocolEnvelope
	}
	return protocolBusiness
}

// These shapes identify provider envelopes, not arbitrary objects with
// a "tools", "parameters", "schema", or "type" business field.
func looksSchemaEnvelope(object map[string]any) bool {
	model, ok := object["model"].(string)
	if !ok || model == "" {
		return false
	}
	if object["object"] == "response" {
		if _, output := object["output"].([]any); output {
			return true
		}
	}
	if messages, ok := object["messages"].([]any); ok {
		for _, value := range messages {
			message, ok := value.(map[string]any)
			if !ok || !knownMessageRole(lowerString(message["role"])) {
				return false
			}
			if _, content := message["content"]; !content && message["tool_calls"] == nil {
				return false
			}
		}
		return true
	}
	switch object["input"].(type) {
	case string, []any:
		return true
	}
	_, instructions := object["instructions"].(string)
	return instructions
}

func looksMCPToolListEnvelope(object map[string]any) bool {
	if object["jsonrpc"] != "2.0" || object["method"] != nil {
		return false
	}
	if _, id := object["id"]; !id {
		return false
	}
	result, ok := object["result"].(map[string]any)
	if !ok || result["content"] != nil || result["structuredContent"] != nil || result["structured_content"] != nil {
		return false
	}
	tools, ok := result["tools"].([]any)
	if !ok {
		return false
	}
	for _, value := range tools {
		tool, ok := value.(map[string]any)
		if !ok || !namedSchemaDefinition(tool, "inputSchema") {
			return false
		}
	}
	return true
}

func namedSchemaDefinition(object map[string]any, key string) bool {
	name, ok := object["name"].(string)
	return ok && name != "" && isProtocolSchema(object[key])
}

func isProtocolSchema(value any) bool {
	switch value.(type) {
	case map[string]any, bool:
		return true
	default:
		return false
	}
}

func classifySchemaContext(object map[string]any, parent protocolObjectKind, edge string) (protocolObjectKind, bool) {
	switch parent {
	case protocolSchemaEnvelope:
		switch edge {
		case "tools":
			if object["type"] == "function" {
				if function, ok := object["function"].(map[string]any); ok && namedSchemaDefinition(function, "parameters") {
					return protocolToolDefinition, true
				}
				if namedSchemaDefinition(object, "parameters") {
					return protocolFunctionDefinition, true
				}
			}
			if namedSchemaDefinition(object, "input_schema") {
				return protocolAnthropicToolDefinition, true
			}
		case "functions":
			if namedSchemaDefinition(object, "parameters") {
				return protocolFunctionDefinition, true
			}
		case "response_format":
			if object["type"] == "json_schema" {
				if schema, ok := object["json_schema"].(map[string]any); ok && namedSchemaDefinition(schema, "schema") {
					return protocolResponseFormat, true
				}
			}
		case "text", "output_config":
			if format, ok := object["format"].(map[string]any); ok && format["type"] == "json_schema" && isProtocolSchema(format["schema"]) {
				return protocolResponseText, true
			}
		case "output_format":
			if object["type"] == "json_schema" && isProtocolSchema(object["schema"]) {
				return protocolSchemaFormat, true
			}
		}
	case protocolToolDefinition:
		if edge == "function" && namedSchemaDefinition(object, "parameters") {
			return protocolFunctionDefinition, true
		}
	case protocolResponseFormat:
		if edge == "json_schema" && namedSchemaDefinition(object, "schema") {
			return protocolSchemaFormat, true
		}
	case protocolResponseText:
		if edge == "format" && object["type"] == "json_schema" && isProtocolSchema(object["schema"]) {
			return protocolSchemaFormat, true
		}
	case protocolMCPToolListEnvelope:
		if edge == "result" {
			return protocolMCPToolList, true
		}
	case protocolMCPToolList:
		if edge == "tools" && namedSchemaDefinition(object, "inputSchema") {
			return protocolMCPToolDefinition, true
		}
	}
	return protocolBusiness, false
}

// A declared schema is protocol metadata, including its property names,
// references, enum values, constraints, and examples. Rewriting any of those
// can change which arguments a provider generates or accepts.
func protocolSchemaField(kind protocolObjectKind, object map[string]any, key string) bool {
	if !isProtocolSchema(object[key]) {
		return false
	}
	switch kind {
	case protocolAnthropicToolDefinition:
		return key == "input_schema"
	case protocolMCPToolDefinition:
		return key == "inputSchema" || key == "outputSchema"
	case protocolFunctionDefinition:
		return key == "parameters"
	case protocolSchemaFormat:
		return key == "schema"
	default:
		return false
	}
}

// Schema metadata is immutable, not unbounded: it consumes the same depth and
// node budget as data inspected by the policy walker.
func validateProtocolSchema(value any, budget *transformBudget, depth int) error {
	if err := budget.visit(depth); err != nil {
		return err
	}
	switch value := value.(type) {
	case map[string]any:
		for _, child := range value {
			if err := validateProtocolSchema(child, budget, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range value {
			if err := validateProtocolSchema(child, budget, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func collectProtocolSchemaOccupied(value any, out map[string]struct{}, depth int) {
	if depth > maxPolicyDepth {
		return
	}
	switch value := value.(type) {
	case string:
		out[value] = struct{}{}
	case json.Number:
		out[value.String()] = struct{}{}
	case map[string]any:
		for _, child := range value {
			collectProtocolSchemaOccupied(child, out, depth+1)
		}
	case []any:
		for _, child := range value {
			collectProtocolSchemaOccupied(child, out, depth+1)
		}
	}
}

func lowerString(value any) string {
	text, _ := value.(string)
	return strings.ToLower(text)
}

func knownMessageRole(role string) bool {
	switch role {
	case "system", "developer", "user", "assistant", "tool":
		return true
	default:
		return false
	}
}

func looksAgentEnvelope(object map[string]any) bool {
	if _, ok := object["choices"].([]any); ok {
		return true
	}
	switch lowerString(object["object"]) {
	case "response", "chat.completion", "chat.completion.chunk":
		return true
	}
	if strings.HasPrefix(lowerString(object["type"]), "response.") {
		return true
	}
	if _, ok := object["model"].(string); ok {
		for _, key := range []string{"messages", "input", "instructions", "tools", "tool_choice"} {
			if _, exists := object[key]; exists {
				return true
			}
		}
	}
	if messages, ok := object["messages"].([]any); ok {
		for _, value := range messages {
			message, ok := value.(map[string]any)
			if ok && knownMessageRole(lowerString(message["role"])) && message["content"] != nil {
				return true
			}
		}
	}
	if _, input := object["input"]; input {
		if _, reasoning := object["reasoning"]; reasoning {
			return true
		}
	}
	return false
}

func protocolRoutingField(kind protocolObjectKind, object map[string]any, key string) bool {
	switch kind {
	case protocolEnvelope, protocolSchemaEnvelope:
		switch key {
		case "model", "id", "object", "type", "status", "stop_reason", "stop_sequence", "tool_choice",
			"index", "created", "sequence_number", "output_index", "content_index", "summary_index":
			return true
		}
	case protocolMessage:
		if key == "role" {
			return true
		}
		if lowerString(object["role"]) == "tool" && (key == "name" || key == "tool_call_id" || key == "call_id") {
			return true
		}
		if key == "cache_control" {
			return true
		}
	case protocolToolCall:
		switch key {
		case "type", "id", "call_id", "name", "index":
			return true
		}
	case protocolFunction:
		return key == "name" || key == "type"
	case protocolFunctionOutput:
		switch key {
		case "type", "id", "call_id", "name":
			return true
		}
	case protocolToolUse:
		switch key {
		case "type", "id", "name":
			return true
		}
	case protocolToolResult:
		return key == "type" || key == "tool_use_id"
	case protocolContentBlock:
		return key == "type" || key == "cache_control"
	case protocolImage:
		return key == "type"
	case protocolReasoning:
		return key == "type" || key == "id" || key == "encrypted_content"
	case protocolToolDefinition, protocolAnthropicToolDefinition, protocolMCPToolDefinition, protocolFunctionDefinition, protocolSchemaFormat:
		return key == "name" || key == "type" || key == "strict"
	case protocolResponseFormat:
		return key == "type"
	case protocolMCPEnvelope, protocolMCPToolListEnvelope:
		return key == "jsonrpc" || key == "id" || key == "method"
	case protocolMCPParams:
		return key == "name" || key == "_meta"
	}
	return false
}

func opaqueProtocolField(kind protocolObjectKind, object map[string]any, key string, value any) bool {
	if kind == protocolReasoning && key == "encrypted_content" {
		return true
	}
	if kind != protocolImage {
		return false
	}
	switch strings.ToLower(key) {
	case "source", "image_url", "input_image", "b64_json", "file_id", "result", "data", "image", "url":
		return true
	}
	text, ok := value.(string)
	return ok && isImageDataURL(text)
}

func embeddedCandidateInspectionText(text string, candidate embeddedJSONCandidate) string {
	if candidate.start < 0 || candidate.end < candidate.start || candidate.end > len(text) {
		return text
	}
	value := text[candidate.start:candidate.end]
	if candidate.encoding != embeddedJSONShellDouble {
		return value
	}
	if decoded, ok := decodeShellDouble(value); ok {
		return decoded
	}
	return strings.ReplaceAll(value, `\"`, `"`)
}

func marshalEmbeddedCandidate(candidate embeddedJSONCandidate, value any) (string, error) {
	encoded, err := marshalEmbeddedValue(value)
	if err != nil {
		return "", err
	}
	if candidate.encoding == embeddedJSONShellDouble {
		encoded = encodeShellDouble(encoded)
	}
	return encoded, nil
}

func marshalEmbeddedValue(value any) (string, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	return strings.TrimSuffix(out.String(), "\n"), nil
}
