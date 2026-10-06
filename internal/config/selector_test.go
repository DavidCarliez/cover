package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStructuredSelectorRejectsAmbiguousRules(t *testing.T) {
	for name, body := range map[string]string{
		"mixed JSON and HTTP":         "keys: [password]\n    headers: [Authorization]",
		"mixed HTTP kinds":            "cookies: [session]\n    query_params: [ticket]",
		"pattern mixed with selector": "form_fields: [secret]\n    pattern: value",
		"capture mixed with selector": "headers: [Authorization]\n    capture_group: value",
		"empty selector":              "query_params: [' ']",
		"control character selector":  "headers: [\"Bad\\nHeader\"]",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			data := "rules:\n  protected:\n    " + body + "\n    action: redact\n"
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("ambiguous or malformed selector policy was accepted")
			}
		})
	}
}
