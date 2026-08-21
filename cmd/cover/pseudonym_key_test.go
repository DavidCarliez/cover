package main

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/DavidCarliez/cover/internal/config"
	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func keyedAlias(t *testing.T, keyPath string) string {
	t.Helper()
	cfg := config.Default()
	cfg.Pseudonymization.KeyFile = keyPath
	cfg.Rules = map[string]detectors.CustomPattern{
		"customer": {Pattern: `nike`, Action: "pseudonymize", Generator: "alias"},
	}
	r, cleanup, err := buildRedactor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	result, err := r.Transform([]byte(`{"text":"nike"}`), "session", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]string
	if err := json.Unmarshal(result.Body, &body); err != nil {
		t.Fatal(err)
	}
	if body["text"] == "nike" {
		t.Fatal("customer value was not pseudonymized")
	}
	return body["text"]
}

func TestBuildRedactorPersistsStableInstallationScopedPseudonyms(t *testing.T) {
	dir := t.TempDir()
	keyA := filepath.Join(dir, "a", "pseudonym.key")
	keyB := filepath.Join(dir, "b", "pseudonym.key")
	a1 := keyedAlias(t, keyA)
	a2 := keyedAlias(t, keyA)
	b := keyedAlias(t, keyB)
	if a1 != a2 {
		t.Fatalf("pseudonym changed across redactor restarts: %q != %q", a1, a2)
	}
	if a1 == b {
		t.Fatalf("separate installations produced a linkable pseudonym: %q", a1)
	}
}
