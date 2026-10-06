package redact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func schemaPolicyValue(t *testing.T, value any, path ...any) any {
	t.Helper()
	for _, part := range path {
		switch part := part.(type) {
		case string:
			object, ok := value.(map[string]any)
			if !ok {
				t.Fatalf("expected object at %v, got %T", path, value)
			}
			value = object[part]
		case int:
			array, ok := value.([]any)
			if !ok || part < 0 || part >= len(array) {
				t.Fatalf("expected array item at %v, got %#v", path, value)
			}
			value = array[part]
		default:
			t.Fatalf("unsupported test path component %T", part)
		}
	}
	return value
}

func schemaPolicyRedactor(t *testing.T) *Redactor {
	t.Helper()
	detector, err := detectors.NewRegexDetector(nil, []detectors.CustomPattern{{
		Name: "schema_test_marker", Pattern: "DETECTOR-SENTINEL", Action: "pseudonymize", Generator: "alias",
	}})
	if err != nil {
		t.Fatal(err)
	}
	return New(NewStore(), 0, RedactorOptions{FieldRules: []FieldRule{
		aliasKeyRule("passwords", "password"),
		{Name: "customer_numbers", Keys: []string{"customer_number"}, Action: string(ActionPseudonymize), Generator: "number", Priority: 100},
	}}, detector)
}

func TestProtocolSchemasPreserveProviderContracts(t *testing.T) {
	const schema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"password":{"type":"string","description":"DETECTOR-SENTINEL","minLength":1},"customer_number":{"type":"integer","minimum":0},"nested":{"type":"array","items":{"$ref":"#/$defs/account"}}},"$defs":{"account":{"type":"object","properties":{"password":{"anyOf":[{"type":"string"},{"type":"null"}]},"customer_number":{"type":"number"}},"required":["password"]}},"required":["password","customer_number"],"additionalProperties":false}`
	const record = `,"metadata":{"password":"CUSTOMER-ALPHA","customer_number":123,"note":"DETECTOR-SENTINEL"}`
	tests := []struct {
		name    string
		fixture string
		paths   [][]any
	}{
		{"chat", `{"model":"example-model","messages":[{"role":"user","content":"hello"}],"tools":[{"type":"function","function":{"name":"lookup","description":"DETECTOR-SENTINEL","strict":true,"parameters":` + schema + `}}]` + record + `}`, [][]any{{"tools", 0, "function", "parameters"}}},
		{"chat-legacy", `{"model":"example-model","messages":[{"role":"user","content":"hello"}],"functions":[{"name":"lookup","parameters":` + schema + `}]` + record + `}`, [][]any{{"functions", 0, "parameters"}}},
		{"responses", `{"model":"example-model","input":"hello","tools":[{"type":"function","name":"lookup","parameters":` + schema + `,"strict":true}]` + record + `}`, [][]any{{"tools", 0, "parameters"}}},
		{"responses-echoed-definition", `{"object":"response","id":"resp_example","model":"example-model","output":[],"tools":[{"type":"function","name":"lookup","parameters":` + schema + `,"strict":true}]` + record + `}`, [][]any{{"tools", 0, "parameters"}}},
		{"anthropic", `{"model":"example-model","max_tokens":100,"messages":[{"role":"user","content":"hello"}],"tools":[{"name":"lookup","input_schema":` + schema + `}]` + record + `}`, [][]any{{"tools", 0, "input_schema"}}},
		{"chat-response-schema", `{"model":"example-model","messages":[{"role":"user","content":"hello"}],"response_format":{"type":"json_schema","json_schema":{"name":"answer","strict":true,"schema":` + schema + `}}` + record + `}`, [][]any{{"response_format", "json_schema", "schema"}}},
		{"responses-output-schema", `{"model":"example-model","input":[{"role":"user","content":"hello"}],"text":{"format":{"type":"json_schema","name":"answer","strict":true,"schema":` + schema + `}}` + record + `}`, [][]any{{"text", "format", "schema"}}},
		{"anthropic-output-schema", `{"model":"example-model","messages":[{"role":"user","content":"hello"}],"output_config":{"format":{"type":"json_schema","schema":` + schema + `}}` + record + `}`, [][]any{{"output_config", "format", "schema"}}},
		{"anthropic-legacy-output-schema", `{"model":"example-model","messages":[{"role":"user","content":"hello"}],"output_format":{"type":"json_schema","schema":` + schema + `}` + record + `}`, [][]any{{"output_format", "schema"}}},
		{"mcp-tools-list", `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"lookup","inputSchema":` + schema + `,"outputSchema":` + schema + `}]}` + record + `}`, [][]any{{"result", "tools", 0, "inputSchema"}, {"result", "tools", 0, "outputSchema"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := schemaPolicyRedactor(t)
			fixture := []byte(tc.fixture)
			result, err := r.Transform(fixture, tc.name, false, "allow")
			if err != nil {
				t.Fatalf("valid provider schema rejected: %v", err)
			}
			root := decodePolicyJSON(t, result.Body)
			for _, path := range tc.paths {
				if got := schemaPolicyValue(t, root, path...); !reflect.DeepEqual(got, decodePolicyJSON(t, []byte(schema))) {
					t.Fatalf("schema contract changed at %v: %#v", path, got)
				}
			}
			metadata := schemaPolicyValue(t, root, "metadata").(map[string]any)
			if metadata["password"] == "CUSTOMER-ALPHA" || metadata["customer_number"] == json.Number("123") || metadata["note"] == "DETECTOR-SENTINEL" {
				t.Fatalf("business field or detector policy bypassed: %#v", metadata)
			}
			if tc.name == "chat" && schemaPolicyValue(t, root, "tools", 0, "function", "description") == "DETECTOR-SENTINEL" {
				t.Fatal("tool prose outside schema bypassed detector")
			}
			assertPolicyJSONEqual(t, r.RestoreResponseForSession(result.Body, "application/json", tc.name), fixture)
		})
	}
}

func TestProtocolSchemasDoNotExemptActualArguments(t *testing.T) {
	const schema = `{"type":"object","properties":{"password":{"type":"string"},"customer_number":{"type":"integer"}},"additionalProperties":false}`
	const arguments = `{"password":"CUSTOMER-ALPHA","customer_number":123,"note":"DETECTOR-SENTINEL"}`
	encodedArguments, err := json.Marshal(arguments)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		fixture string
		path    []any
	}{
		{"chat", `{"model":"example-model","messages":[{"role":"assistant","tool_calls":[{"type":"function","id":"call_example","function":{"name":"lookup","arguments":` + string(encodedArguments) + `}}]}],"tools":[{"type":"function","function":{"name":"lookup","parameters":` + schema + `}}]}`, []any{"messages", 0, "tool_calls", 0, "function", "arguments"}},
		{"responses", `{"model":"example-model","input":[{"type":"function_call","name":"lookup","call_id":"call_example","arguments":` + string(encodedArguments) + `}],"tools":[{"type":"function","name":"lookup","parameters":` + schema + `}]}`, []any{"input", 0, "arguments"}},
		{"anthropic", `{"model":"example-model","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"call_example","name":"lookup","input":` + arguments + `}]}],"tools":[{"name":"lookup","input_schema":` + schema + `}]}`, []any{"messages", 0, "content", 0, "input"}},
		{"mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup","arguments":` + arguments + `}}`, []any{"params", "arguments"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := schemaPolicyRedactor(t)
			result, err := r.Transform([]byte(tc.fixture), tc.name, false, "allow")
			if err != nil {
				t.Fatal(err)
			}
			value := schemaPolicyValue(t, decodePolicyJSON(t, result.Body), tc.path...)
			if text, ok := value.(string); ok {
				value = decodePolicyJSON(t, []byte(text))
			}
			args := value.(map[string]any)
			if args["password"] == "CUSTOMER-ALPHA" || args["customer_number"] == json.Number("123") || args["note"] == "DETECTOR-SENTINEL" {
				t.Fatalf("tool arguments bypassed policy: %#v", args)
			}
			restored := r.RestoreResponseForSession(result.Body, "application/json", tc.name)
			value = schemaPolicyValue(t, decodePolicyJSON(t, restored), tc.path...)
			if text, ok := value.(string); ok {
				value = decodePolicyJSON(t, []byte(text))
			}
			if !reflect.DeepEqual(value, decodePolicyJSON(t, []byte(arguments))) {
				t.Fatalf("arguments did not round trip: %#v", value)
			}
		})
	}
}

func TestSchemaLikeBusinessObjectsRemainProtected(t *testing.T) {
	const definition = `{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{"password":{"type":"CUSTOMER-ALPHA"}}}}}`
	const envelope = `{"model":"example-model","messages":[{"role":"user","content":"hello"}],"tools":[` + definition + `]}`
	encodedEnvelope, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]string{
		"reserved-business-keys": `{"schema":{"password":"CUSTOMER-ALPHA"},"parameters":{"password":"CUSTOMER-ALPHA"},"type":{"password":"CUSTOMER-ALPHA"},"tools":[` + definition + `]}`,
		"model-and-tools-only":   `{"model":"inventory","tools":[` + definition + `]}`,
		"nested-envelope":        `{"record":` + envelope + `}`,
		"serialized-envelope":    `{"messages":[{"role":"tool","content":` + string(encodedEnvelope) + `}]}`,
		"argument-envelope":      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup","arguments":` + envelope + `}}`,
		"mcp-business-result":    `{"jsonrpc":"2.0","id":1,"result":{"content":[],"tools":[{"name":"lookup","inputSchema":{"password":"CUSTOMER-ALPHA"}}]}}`,
		"schema-outside-slot":    `{"model":"example-model","input":"hello","schema":{"password":"CUSTOMER-ALPHA"},"tools":[{"type":"function","name":"lookup","parameters":{"type":"object"},"schema":{"password":"CUSTOMER-ALPHA"}}]}`,
	}
	for name, fixture := range tests {
		t.Run(name, func(t *testing.T) {
			r := structuredPolicyRedactor(aliasKeyRule("passwords", "password"))
			result, err := r.Transform([]byte(fixture), name, false, "allow")
			if err != nil {
				t.Fatal(err)
			}
			if result.Transformed == 0 || bytes.Contains(result.Body, []byte("CUSTOMER-ALPHA")) {
				t.Fatalf("schema-looking business data bypassed policies: %s", result.Body)
			}
		})
	}
}

func TestSchemaNamesAreNotGlobalFieldPolicyExemptions(t *testing.T) {
	fixture := []byte(`{"schema":"CUSTOMER-ALPHA","tools":"CUSTOMER-ALPHA","type":"CUSTOMER-ALPHA","parameters":"CUSTOMER-ALPHA"}`)
	r := structuredPolicyRedactor(aliasKeyRule("business", "schema", "tools", "type", "parameters"))
	result, err := r.Transform(fixture, "schema-names", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	if result.Transformed != 4 || bytes.Contains(result.Body, []byte("CUSTOMER-ALPHA")) {
		t.Fatalf("business keys bypassed field policies: %s", result.Body)
	}
	assertPolicyJSONEqual(t, r.RestoreResponseForSession(result.Body, "application/json", "schema-names"), fixture)

	numeric := structuredPolicyRedactor(FieldRule{
		Name: "numbers", Keys: []string{"customer_number"}, Action: string(ActionPseudonymize), Generator: "number", Priority: 100,
	})
	// Schema-looking data outside a protocol schema slot does not suppress
	// the usual selected-value type validation.
	if _, err := numeric.Transform([]byte(`{"schema":{"properties":{"customer_number":{"type":"integer"}}}}`), "schema-names", false, "allow"); !errors.Is(err, ErrUnsafeRequest) {
		t.Fatalf("business numeric policy no longer fails closed: %v", err)
	}
}

func TestSchemaMetadataPreservationDoesNotRelaxInspectionLimits(t *testing.T) {
	deep := any(map[string]any{"type": "string"})
	for i := 0; i <= maxPolicyDepth; i++ {
		deep = map[string]any{"type": "object", "additionalProperties": deep}
	}
	wide := make([]any, maxPolicyNodes)
	for i := range wide {
		wide[i] = "literal"
	}
	for name, schema := range map[string]any{
		"depth": deep,
		"nodes": map[string]any{"type": "string", "enum": wide},
	} {
		t.Run(name, func(t *testing.T) {
			fixture, err := json.Marshal(map[string]any{
				"model": "example-model", "input": "hello",
				"tools": []any{map[string]any{"type": "function", "name": "lookup", "parameters": schema}},
			})
			if err != nil {
				t.Fatal(err)
			}
			r := structuredPolicyRedactor(aliasKeyRule("passwords", "password"))
			if _, err := r.Transform(fixture, name, false, "allow"); !errors.Is(err, ErrUnsafeRequest) {
				t.Fatalf("over-budget schema accepted: %v", err)
			}
		})
	}
}

func TestSchemaLiteralsAvoidAliasCollisionsAndRestoration(t *testing.T) {
	r := structuredPolicyRedactor(FieldRule{
		Name: "number", Keys: []string{"customer_number"}, Action: string(ActionPseudonymize), Generator: "number", Priority: 100,
	})
	candidate, err := generateReplacement(r.store.key[:], "number", "7", 0)
	if err != nil {
		t.Fatal(err)
	}
	fixture := []byte(fmt.Sprintf(`{"model":"example-model","input":"hello","tools":[{"type":"function","name":"lookup","parameters":{"type":"object","properties":{"customer_number":{"type":"number","enum":[%s]}}}}],"record":{"customer_number":7}}`, candidate))
	result, err := r.Transform(fixture, "schema-collision", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	root := decodePolicyJSON(t, result.Body)
	fake := schemaPolicyValue(t, root, "record", "customer_number").(json.Number)
	if fake.String() == candidate {
		t.Fatal("generated argument alias collides with immutable schema enum")
	}
	assertPolicyJSONEqual(t, r.RestoreResponseForSession(result.Body, "application/json", "schema-collision"), fixture)

	// A provider may return a schema literal that happens to equal an existing
	// session alias; only the actual data value must be restored.
	response := []byte(fmt.Sprintf(`{"model":"example-model","input":"hello","text":{"format":{"type":"json_schema","name":"answer","schema":{"type":"number","const":%s}}},"record":{"customer_number":%s}}`, fake, fake))
	want := []byte(fmt.Sprintf(`{"model":"example-model","input":"hello","text":{"format":{"type":"json_schema","name":"answer","schema":{"type":"number","const":%s}}},"record":{"customer_number":7}}`, fake))
	assertPolicyJSONEqual(t, r.RestoreResponseForSession(response, "application/json", "schema-collision"), want)
}
