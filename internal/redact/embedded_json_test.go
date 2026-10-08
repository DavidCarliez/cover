package redact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func structuredPolicyRedactor(rules ...FieldRule) *Redactor {
	return New(NewStore(), 0, RedactorOptions{FieldRules: rules})
}

func aliasKeyRule(name string, keys ...string) FieldRule {
	return FieldRule{
		Name: name, Keys: keys, Category: name, Action: string(ActionPseudonymize),
		Generator: "alias", Priority: 100,
	}
}

func decodePolicyJSON(t *testing.T, data []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func assertPolicyJSONEqual(t *testing.T, got, want []byte) {
	t.Helper()
	if !reflect.DeepEqual(decodePolicyJSON(t, got), decodePolicyJSON(t, want)) {
		t.Fatalf("JSON mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestStructuredKeyPoliciesCoverToolResultEnvelopes(t *testing.T) {
	tests := map[string]string{
		"responses": `{"input":[{"type":"function_call_output","call_id":"call_example","output":"{\"password\":\"CUSTOMER-ALPHA\"}"}]}`,
		"chat":      `{"messages":[{"role":"tool","tool_call_id":"call_example","content":"` + "```json\\n{\\\"password\\\":\\\"CUSTOMER-ALPHA\\\"}\\n```" + `"}]}`,
		"anthropic": `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"tool_example","content":"Result:\n{\"password\":\"CUSTOMER-ALPHA\"}"}]}]}`,
		"mcp":       `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"password\":\"CUSTOMER-ALPHA\"}"}],"structuredContent":{"password":"CUSTOMER-ALPHA"}}}`,
	}
	for name, fixture := range tests {
		t.Run(name, func(t *testing.T) {
			r := structuredPolicyRedactor(aliasKeyRule("passwords", "password"))
			result, err := r.Transform([]byte(fixture), name, false, "allow")
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(result.Body, []byte("CUSTOMER-ALPHA")) {
				t.Fatalf("selected value leaked: %s", result.Body)
			}
			restored := r.RestoreResponseForSession(result.Body, "application/json", name)
			assertPolicyJSONEqual(t, restored, []byte(fixture))
		})
	}
}

func TestStructuredParentPoliciesCoverArraysAndBusinessReservedNames(t *testing.T) {
	r := structuredPolicyRedactor(
		FieldRule{Name: "credentials", Keys: []string{"credentials"}, Action: string(ActionPseudonymize), Generator: "alias", Priority: 100},
		FieldRule{Name: "business_fields", Keys: []string{"id", "type", "role", "name", "encrypted_content", "image_url"}, Action: string(ActionPseudonymize), Generator: "alias", Priority: 90},
	)
	fixture := []byte(`{"credentials":{"short":"x","items":["CUSTOMER-ALPHA",{"role":"tool","name":"CUSTOMER-ALPHA","content":"CUSTOMER-ALPHA"}]},"record":{"id":"CUSTOMER-ALPHA","type":"CUSTOMER-ALPHA","role":"CUSTOMER-ALPHA","name":"CUSTOMER-ALPHA","encrypted_content":"CUSTOMER-ALPHA","image_url":"https://example.com/CUSTOMER-ALPHA.png"}}`)
	result, err := r.Transform(fixture, "business", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	if result.Transformed != 11 || bytes.Contains(result.Body, []byte("CUSTOMER-ALPHA")) || bytes.Contains(result.Body, []byte(`"short":"x"`)) {
		t.Fatalf("nested business values were not all protected: %+v %s", result, result.Body)
	}
	assertPolicyJSONEqual(t, r.RestoreResponseForSession(result.Body, "application/json", "business"), fixture)
}

func TestProtocolRoutingAndOpaqueFieldsRemainUntouchedOnlyInProtocolContext(t *testing.T) {
	r := structuredPolicyRedactor(aliasKeyRule("reserved", "id", "type", "role", "name", "encrypted_content"))
	fixture := []byte(`{"model":"example-model","messages":[{"role":"tool","name":"example_tool","tool_call_id":"call_example","content":"{\"id\":\"CUSTOMER-ALPHA\",\"type\":\"CUSTOMER-ALPHA\",\"role\":\"CUSTOMER-ALPHA\",\"name\":\"CUSTOMER-ALPHA\",\"encrypted_content\":\"CUSTOMER-ALPHA\"}"}],"reasoning":{"type":"reasoning","encrypted_content":"CUSTOMER-ALPHA"},"input":[{"type":"input_image","image_url":"data:image/png;base64,CUSTOMER-ALPHA"}]}`)
	result, err := r.Transform(fixture, "protocol", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	root := decodePolicyJSON(t, result.Body).(map[string]any)
	message := root["messages"].([]any)[0].(map[string]any)
	if message["role"] != "tool" || message["name"] != "example_tool" {
		t.Fatalf("routing fields changed: %#v", message)
	}
	if strings.Contains(message["content"].(string), "CUSTOMER-ALPHA") {
		t.Fatalf("business JSON inside tool content bypassed policy: %q", message["content"])
	}
	if root["reasoning"].(map[string]any)["encrypted_content"] != "CUSTOMER-ALPHA" {
		t.Fatal("protocol encrypted content changed")
	}
	if root["input"].([]any)[0].(map[string]any)["image_url"] != "data:image/png;base64,CUSTOMER-ALPHA" {
		t.Fatal("protocol image payload changed")
	}
	restoredRoot := decodePolicyJSON(t, r.RestoreResponseForSession(result.Body, "application/json", "protocol")).(map[string]any)
	originalRoot := decodePolicyJSON(t, fixture).(map[string]any)
	restoredMessage := restoredRoot["messages"].([]any)[0].(map[string]any)
	originalMessage := originalRoot["messages"].([]any)[0].(map[string]any)
	assertPolicyJSONEqual(t, []byte(restoredMessage["content"].(string)), []byte(originalMessage["content"].(string)))
	// Serialized business JSON can be re-encoded without changing its meaning.
	restoredMessage["content"] = originalMessage["content"]
	if !reflect.DeepEqual(restoredRoot, originalRoot) {
		t.Fatal("restoration changed protocol metadata or content types")
	}
}

func TestMCPStructuredContentTreatsReservedNamesAsBusinessData(t *testing.T) {
	r := structuredPolicyRedactor(aliasKeyRule("reserved", "id", "type", "role", "name", "encrypted_content"))
	fixture := []byte(`{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"id":"CUSTOMER-ALPHA","type":"CUSTOMER-ALPHA","role":"CUSTOMER-ALPHA","name":"CUSTOMER-ALPHA","encrypted_content":"CUSTOMER-ALPHA"}}}`)
	result, err := r.Transform(fixture, "mcp-structured", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	root := decodePolicyJSON(t, result.Body).(map[string]any)
	if root["id"].(json.Number).String() != "1" {
		t.Fatalf("MCP routing id changed: %s", result.Body)
	}
	structured := root["result"].(map[string]any)["structuredContent"].(map[string]any)
	for _, key := range []string{"id", "type", "role", "name", "encrypted_content"} {
		if structured[key] == "CUSTOMER-ALPHA" {
			t.Fatalf("structuredContent.%s bypassed policy: %s", key, result.Body)
		}
	}
	assertPolicyJSONEqual(t, r.RestoreResponseForSession(result.Body, "application/json", "mcp-structured"), fixture)
}

func TestNumericFieldPolicyPreservesJSONTypesAndExactRestoration(t *testing.T) {
	rule := FieldRule{
		Name: "numbers", Keys: []string{"integer", "fraction", "exponent", "negative"},
		Action: string(ActionPseudonymize), Generator: "number", Priority: 100,
	}
	r := structuredPolicyRedactor(rule)
	fixture := []byte(`{"integer":123,"fraction":12.50,"exponent":1.25e+3,"negative":-42}`)
	result, err := r.Transform(fixture, "numbers", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	root := decodePolicyJSON(t, result.Body).(map[string]any)
	for _, key := range rule.Keys {
		number, ok := root[key].(json.Number)
		if !ok || strings.ContainsAny(number.String(), ".eE") {
			t.Fatalf("%s is not a canonical JSON-number fake: %#v", key, root[key])
		}
	}
	assertPolicyJSONEqual(t, r.RestoreResponseForSession(result.Body, "application/json", "numbers"), fixture)
}

func TestNumericCollisionAndTokenBoundaryRestoration(t *testing.T) {
	r := structuredPolicyRedactor(FieldRule{
		Name: "number", Keys: []string{"selected"}, Action: string(ActionPseudonymize), Generator: "number", Priority: 100,
	})
	candidate, err := generateReplacement(r.store.key[:], "number", "7", 0)
	if err != nil {
		t.Fatal(err)
	}
	fixture := []byte(fmt.Sprintf(`{"selected":7,"control":%s}`, candidate))
	result, err := r.Transform(fixture, "collision", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	root := decodePolicyJSON(t, result.Body).(map[string]any)
	fake := root["selected"].(json.Number).String()
	if fake == candidate || root["control"].(json.Number).String() != candidate {
		t.Fatalf("numeric collision was not avoided: %s", result.Body)
	}
	if restoredScalar := string(r.RestoreResponseForSession([]byte(fake), "application/json", "collision")); restoredScalar != "7" {
		t.Fatalf("top-level numeric restoration=%q", restoredScalar)
	}

	larger := "9" + fake + "9"
	response := []byte(fmt.Sprintf(`{"selected":%s,"larger":%s}`, fake, larger))
	restored := r.RestoreResponseForSession(response, "application/json", "collision")
	restoredRoot := decodePolicyJSON(t, restored).(map[string]any)
	if restoredRoot["selected"].(json.Number).String() != "7" || restoredRoot["larger"].(json.Number).String() != larger {
		t.Fatalf("numeric token boundary restoration failed: %s", restored)
	}
}

func TestNumericFakeRestoresInsideCurlJSONCommand(t *testing.T) {
	r := structuredPolicyRedactor(FieldRule{
		Name: "customer_number", Keys: []string{"customer_number"}, Action: string(ActionPseudonymize), Generator: "number", Priority: 100,
	})
	result, err := r.Transform([]byte(`{"customer_number":1.25e+3}`), "curl-number", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	fake := decodePolicyJSON(t, result.Body).(map[string]any)["customer_number"].(json.Number).String()
	command := "curl -sS https://example.com/items --data '{\"customer_number\":" + fake + "}'"
	response, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	restored := r.RestoreResponseForSession(response, "application/json", "curl-number")
	var output map[string]string
	if err := json.Unmarshal(restored, &output); err != nil {
		t.Fatal(err)
	}
	want := "curl -sS https://example.com/items --data '{\"customer_number\":1.25e+3}'"
	if output["command"] != want {
		t.Fatalf("restored command=%q, want %q", output["command"], want)
	}
}

func TestSelectedNonStringPoliciesFailClosedOrBlockExplicitly(t *testing.T) {
	for _, tc := range []struct{ action, generator string }{
		{string(ActionPlaceholder), ""},
		{string(ActionMask), ""},
		{string(ActionRedact), ""},
		{string(ActionPseudonymize), "alias"},
	} {
		r := structuredPolicyRedactor(FieldRule{Name: "number", Keys: []string{"value"}, Action: tc.action, Generator: tc.generator})
		if _, err := r.Transform([]byte(`{"value":7}`), "invalid-number", false, "allow"); !errors.Is(err, ErrUnsafeRequest) {
			t.Fatalf("action=%s generator=%s error=%v", tc.action, tc.generator, err)
		}
	}

	blocked := structuredPolicyRedactor(FieldRule{Name: "block", Keys: []string{"value"}, Action: string(ActionBlock)})
	result, err := blocked.Transform([]byte(`{"value":true}`), "blocked-bool", false, "allow")
	if err != nil || !result.Blocked || !bytes.Equal(result.Body, []byte(`{"value":true}`)) {
		t.Fatalf("boolean block result=%+v error=%v", result, err)
	}
	invalidBool := structuredPolicyRedactor(FieldRule{Name: "bool", Keys: []string{"value"}, Action: string(ActionPseudonymize), Generator: "alias"})
	if _, err := invalidBool.Transform([]byte(`{"value":true}`), "invalid-bool", false, "allow"); !errors.Is(err, ErrUnsafeRequest) {
		t.Fatalf("boolean pseudonymization error=%v", err)
	}

	nullPolicy := structuredPolicyRedactor(aliasKeyRule("null", "value"))
	nullResult, err := nullPolicy.Transform([]byte(`{"value":null}`), "null", false, "allow")
	if err != nil || !bytes.Equal(nullResult.Body, []byte(`{"value":null}`)) {
		t.Fatalf("null changed: %s error=%v", nullResult.Body, err)
	}
}

func TestMalformedRecognizedEmbeddedJSONFailsClosedWithoutRejectingSource(t *testing.T) {
	r := structuredPolicyRedactor(aliasKeyRule("password", "password"))
	// A selected scalar in malformed JSON is protected as a plain-text
	// assignment; a selected container or unterminated string needs the
	// parser, so the request is rejected.
	scalars := []string{
		`{"password":"CUSTOMER-ALPHA"`,
		"```json\n{\"password\":\"CUSTOMER-ALPHA\"",
		"Command output:\n{\"password\":\"CUSTOMER-ALPHA\"",
		"curl https://example.com --data '{\"password\":\"CUSTOMER-ALPHA\"'",
		"{\"a\":1}\n{\"password\":\"CUSTOMER-ALPHA\"}\n",
		`{"password":"CUSTOMER-ALPHA",}`,
	}
	for i, text := range scalars {
		body, _ := json.Marshal(map[string]string{"content": text})
		result, err := r.Transform(body, fmt.Sprintf("scalar-%d", i), false, "allow")
		if err != nil || bytes.Contains(result.Body, []byte("CUSTOMER-ALPHA")) {
			t.Fatalf("scalar fixture %d: %v %s", i, err, result.Body)
		}
	}
	containers := []string{
		`{"password":{"value":"CUSTOMER-ALPHA"}`,
		`{"password":["CUSTOMER-ALPHA"`,
		`{"password":"CUSTOMER-ALPHA`,
		// The plain-text net cannot pair these with their key.
		"{\"password\":\n  \"CUSTOMER-ALPHA\",, }",
		"{\"password\"\n  : \"CUSTOMER-ALPHA\",, }",
		`{"pass\u0077ord": "CUSTOMER-ALPHA",, }`,
	}
	for i, text := range containers {
		body, _ := json.Marshal(map[string]string{"content": text})
		if _, err := r.Transform(body, fmt.Sprintf("container-%d", i), false, "allow"); !errors.Is(err, ErrUnsafeRequest) {
			t.Fatalf("container fixture %d error=%v", i, err)
		}
	}

	sources := []string{
		"package example\nvar record = map[string]string{\"password\": \"CUSTOMER-ALPHA\"",
		"[]byte(`{\"password\":\"CUSTOMER-ALPHA\"`)",
		"const result = {\"password\":\"CUSTOMER-ALPHA\"",
		"const result =\n{\"password\":\"CUSTOMER-ALPHA\"",
	}
	// Source code is not rejected as malformed JSON, but a selected value
	// written as an assignment in it is still protected.
	for i, source := range sources {
		body, _ := json.Marshal(map[string]string{"content": source})
		result, err := r.Transform(body, fmt.Sprintf("source-%d", i), false, "allow")
		if err != nil || bytes.Contains(result.Body, []byte("CUSTOMER-ALPHA")) {
			t.Fatalf("ordinary source %d was rejected or leaked: %v %s", i, err, result.Body)
		}
	}
}

func TestSelectedJSONNamesUseJSONEscapes(t *testing.T) {
	for _, tc := range []struct{ name, encoded string }{
		{"account/name", `"account\/name"`},
		{"account\U0001D11E", `"account\uD834\uDD1E"`},
	} {
		r := structuredPolicyRedactor(aliasKeyRule("selected", tc.name))
		valid := `{` + tc.encoded + `:"sample-value"}`
		body, _ := json.Marshal(map[string]string{"content": valid})
		result := mustTransform(t, r, "s", body)
		if strings.Contains(string(result.Body), "sample-value") {
			t.Fatal("decoded selected name was not protected")
		}
		body, _ = json.Marshal(map[string]string{"content": strings.TrimSuffix(valid, "}")})
		if _, err := r.Transform(body, "s", false, "allow"); !errors.Is(err, ErrUnsafeRequest) {
			t.Fatalf("incomplete selected JSON error=%v", err)
		}
	}
}

func TestNestedJSONEncodingFencesAndResultPrefixes(t *testing.T) {
	r := structuredPolicyRedactor(aliasKeyRule("password", "password"))
	inner := `{"password":"CUSTOMER-ALPHA"}`
	encoded, err := json.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []string{
		string(encoded),
		"```json\n" + inner + "\n```",
		"Command result:\n" + inner,
	}
	for i, text := range fixtures {
		body, _ := json.Marshal(map[string]string{"content": text})
		result, err := r.Transform(body, fmt.Sprintf("nested-%d", i), false, "allow")
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(result.Body, []byte("CUSTOMER-ALPHA")) {
			t.Fatalf("fixture %d leaked selected value: %s", i, result.Body)
		}
		assertPolicyJSONEqual(t, r.RestoreResponseForSession(result.Body, "application/json", fmt.Sprintf("nested-%d", i)), body)
	}
}

func TestFieldAllowPrecedenceSuppressesInheritedAndDetectorWork(t *testing.T) {
	r := structuredPolicyRedactor(
		FieldRule{Name: "allow_public", Keys: []string{"public"}, Action: string(ActionAllow), Priority: 200},
		FieldRule{Name: "protect_payload", Keys: []string{"payload"}, Action: string(ActionPseudonymize), Generator: "alias", Priority: 100},
	)
	fixture := []byte(`{"payload":{"public":"CUSTOMER-ALPHA","private":"CUSTOMER-ALPHA"}}`)
	result, err := r.Transform(fixture, "allow", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	root := decodePolicyJSON(t, result.Body).(map[string]any)["payload"].(map[string]any)
	if root["public"] != "CUSTOMER-ALPHA" || root["private"] == "CUSTOMER-ALPHA" {
		t.Fatalf("allow precedence failed: %s", result.Body)
	}
}

func TestEmbeddedJSONDepthIsBoundedAndNoPolicyIsBytePreserving(t *testing.T) {
	text := `{"password":"CUSTOMER-ALPHA"}`
	for range maxEmbeddedJSONDepth + 2 {
		encoded, err := json.Marshal(text)
		if err != nil {
			t.Fatal(err)
		}
		text = string(encoded)
	}
	body, _ := json.Marshal(map[string]string{"content": text})
	protected := structuredPolicyRedactor(aliasKeyRule("password", "password"))
	if _, err := protected.Transform(body, "bounded", false, "allow"); !errors.Is(err, ErrUnsafeRequest) {
		t.Fatalf("deep embedded JSON error=%v", err)
	}
	unconfigured := structuredPolicyRedactor()
	result, err := unconfigured.Transform(body, "unchanged", false, "allow")
	if err != nil || !bytes.Equal(result.Body, body) {
		t.Fatalf("no-policy request changed: %v %s", err, result.Body)
	}
}

func TestQueryAndFormRestorationReencodesReservedCharacters(t *testing.T) {
	original := "CUSTOMER-ALPHA&A/B?="
	r := structuredPolicyRedactor(
		FieldRule{Name: "query", QueryParams: []string{"token"}, Action: string(ActionPseudonymize), Generator: "alias", Priority: 100},
		FieldRule{Name: "form", FormFields: []string{"secret"}, Action: string(ActionPseudonymize), Generator: "alias", Priority: 100},
	)
	fixtures := []struct {
		name  string
		value string
		check func(*testing.T, string)
	}{
		{
			name:  "query",
			value: "https://example.com/items?token=CUSTOMER-ALPHA%26A%2FB%3F%3D&public=ok",
			check: func(t *testing.T, value string) {
				parsed, err := url.Parse(value)
				if err != nil {
					t.Fatal(err)
				}
				if parsed.Query().Get("token") != original || parsed.Query().Get("public") != "ok" {
					t.Fatalf("restored query=%q", value)
				}
			},
		},
		{
			name:  "form",
			value: "secret=CUSTOMER-ALPHA%26A%2FB%3F%3D&public=ok",
			check: func(t *testing.T, value string) {
				parsed, err := url.ParseQuery(value)
				if err != nil {
					t.Fatal(err)
				}
				if parsed.Get("secret") != original || parsed.Get("public") != "ok" {
					t.Fatalf("restored form=%q", value)
				}
			},
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"content": fixture.value})
			result, err := r.Transform(body, fixture.name, false, "allow")
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(result.Body, []byte("CUSTOMER-ALPHA")) {
				t.Fatalf("selected HTTP value leaked: %s", result.Body)
			}
			restored := r.RestoreResponseForSession(result.Body, "application/json", fixture.name)
			var output map[string]string
			if err := json.Unmarshal(restored, &output); err != nil {
				t.Fatal(err)
			}
			fixture.check(t, output["content"])
		})
	}
}

func TestProtocolShapedBusinessJSONCannotBypassFieldPolicies(t *testing.T) {
	r := structuredPolicyRedactor(aliasKeyRule("business", "id", "type", "role", "name", "data", "encrypted_content"))
	for _, business := range []string{
		`{"type":"image","id":"private-id","data":"private-data","encrypted_content":"private-state"}`,
		`{"type":"tool_result","role":"tool","name":"private-name","id":"private-id","content":"public"}`,
		`{"type":"reasoning","encrypted_content":"private-state"}`,
	} {
		body, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "tool", "content": business}}})
		result, err := r.Transform(body, "protocol-shaped-business", false, "allow")
		if err != nil {
			t.Fatal(err)
		}
		protected := decodePolicyJSON(t, result.Body).(map[string]any)["messages"].([]any)[0].(map[string]any)
		if protected["role"] != "tool" {
			t.Fatal("the actual provider role changed")
		}
		originalFields := decodePolicyJSON(t, []byte(business)).(map[string]any)
		protectedFields := decodePolicyJSON(t, []byte(protected["content"].(string))).(map[string]any)
		for key, original := range originalFields {
			if key != "content" && protectedFields[key] == original {
				t.Fatalf("business field %s bypassed protection: %s", key, result.Body)
			}
		}
		restored := decodePolicyJSON(t, r.RestoreResponseForSession(result.Body, "application/json", "protocol-shaped-business")).(map[string]any)
		content := restored["messages"].([]any)[0].(map[string]any)["content"].(string)
		assertPolicyJSONEqual(t, []byte(content), []byte(business))
	}
}
