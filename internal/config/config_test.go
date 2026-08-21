package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func withHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]struct{}, len(a))
	for _, s := range a {
		seen[s] = struct{}{}
	}
	for _, s := range b {
		if _, ok := seen[s]; !ok {
			return false
		}
	}
	return true
}

func TestDefault(t *testing.T) {
	home := t.TempDir()
	withHome(t, home)

	cfg := Default()

	if cfg.Listen != defaultListen {
		t.Errorf("Listen = %q, want %q", cfg.Listen, defaultListen)
	}
	if cfg.Upstream != "" {
		t.Errorf("Upstream = %q, want empty", cfg.Upstream)
	}
	if cfg.Mappings.SessionHeader != "X-Cover-Session" {
		t.Errorf("Mappings.SessionHeader = %q, want X-Cover-Session", cfg.Mappings.SessionHeader)
	}

	if cfg.UpstreamTimeouts.ConnectTimeoutMS != 10000 {
		t.Errorf("UpstreamTimeouts.ConnectTimeoutMS = %d, want 10000", cfg.UpstreamTimeouts.ConnectTimeoutMS)
	}
	if cfg.UpstreamTimeouts.ResponseHeaderTimeoutMS != 120000 {
		t.Errorf("UpstreamTimeouts.ResponseHeaderTimeoutMS = %d, want 120000", cfg.UpstreamTimeouts.ResponseHeaderTimeoutMS)
	}

	wantLog := filepath.Join(home, ".local", "share", dirName, logName)
	if cfg.LogFile != wantLog {
		t.Errorf("LogFile = %q, want %q", cfg.LogFile, wantLog)
	}

	if !cfg.Cache.Enabled {
		t.Error("Cache.Enabled = false, want true")
	}
	if cfg.Cache.MaxEntries != 10000 {
		t.Errorf("Cache.MaxEntries = %d, want 10000", cfg.Cache.MaxEntries)
	}

	if !cfg.Detectors.Regex.Enabled {
		t.Error("Detectors.Regex.Enabled = false, want true")
	}
	if !sameStringSet(cfg.Detectors.Regex.BuiltinCategories, detectors.BuiltinCategories()) {
		t.Errorf("BuiltinCategories mismatch: got %v", cfg.Detectors.Regex.BuiltinCategories)
	}
	if len(cfg.Detectors.Regex.CustomPatterns) != 0 {
		t.Errorf("CustomPatterns = %+v, want empty", cfg.Detectors.Regex.CustomPatterns)
	}

	llm := cfg.Detectors.LLMFallback
	if llm.Enabled {
		t.Error("LLMFallback.Enabled = true, want false")
	}
	if llm.Port != 8418 {
		t.Errorf("LLMFallback.Port = %d, want 8418", llm.Port)
	}
	if llm.MinTextLen != 8 || llm.MaxTextLen != 2000 {
		t.Errorf("LLMFallback text len bounds = (%d, %d), want (8, 2000)", llm.MinTextLen, llm.MaxTextLen)
	}
	if llm.RequestTimeoutMS != 3000 || llm.OverallTimeoutMS != 4000 {
		t.Errorf("LLMFallback timeouts = (%d, %d), want (3000, 4000)", llm.RequestTimeoutMS, llm.OverallTimeoutMS)
	}
	if llm.Concurrency != 4 {
		t.Errorf("LLMFallback.Concurrency = %d, want 4", llm.Concurrency)
	}
	if llm.BatchSize != 8 {
		t.Errorf("LLMFallback.BatchSize = %d, want 8", llm.BatchSize)
	}
	if llm.LlamacppRelease != "latest" {
		t.Errorf("LLMFallback.LlamacppRelease = %q, want latest", llm.LlamacppRelease)
	}
}

func TestPath(t *testing.T) {
	home := t.TempDir()
	withHome(t, home)

	got, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	want := filepath.Join(home, ".config", dirName, fileName)
	if got != want {
		t.Errorf("Path() = %q, want %q", got, want)
	}
}

func TestStateDir(t *testing.T) {
	home := t.TempDir()
	withHome(t, home)

	got, err := StateDir()
	if err != nil {
		t.Fatalf("StateDir: %v", err)
	}
	want := filepath.Join(home, ".local", "share", dirName)
	if got != want {
		t.Errorf("StateDir() = %q, want %q", got, want)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", fileName)

	original := Default()
	original.Upstream = "https://api.example.com"
	original.Detectors.Regex.BuiltinCategories = []string{"email", "jwt"}
	original.Detectors.Regex.CustomPatterns = []detectors.CustomPattern{
		{Name: "internal_proj", Pattern: `PROJ-[0-9]{4,6}`},
	}
	original.Detectors.LLMFallback.Enabled = true
	original.Detectors.LLMFallback.Port = 9000

	if err := Save(path, original); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat saved config: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("config file mode = %o, want 0600", info.Mode().Perm())
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(loaded, original) {
		t.Errorf("loaded config differs from original:\n got  %+v\n want %+v", loaded, original)
	}
}

func TestLoadPartialYAMLMergesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, fileName)

	const yaml = `upstream: "https://api.anthropic.com"
detectors:
  regex:
    enabled: false
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Listen != defaultListen {
		t.Errorf("Listen = %q, want default %q", cfg.Listen, defaultListen)
	}
	if cfg.Upstream != "https://api.anthropic.com" {
		t.Errorf("Upstream = %q, want https://api.anthropic.com", cfg.Upstream)
	}
	if cfg.Detectors.Regex.Enabled {
		t.Error("Detectors.Regex.Enabled = true, want false from YAML")
	}
	if !sameStringSet(cfg.Detectors.Regex.BuiltinCategories, detectors.BuiltinCategories()) {
		t.Error("BuiltinCategories should fall back to defaults when omitted")
	}
	if cfg.Detectors.LLMFallback.Port != 8418 {
		t.Errorf("LLMFallback.Port = %d, want default 8418", cfg.Detectors.LLMFallback.Port)
	}
	if cfg.UpstreamTimeouts.ConnectTimeoutMS != 10000 {
		t.Errorf("UpstreamTimeouts.ConnectTimeoutMS = %d, want default 10000", cfg.UpstreamTimeouts.ConnectTimeoutMS)
	}
	if cfg.UpstreamTimeouts.ResponseHeaderTimeoutMS != 120000 {
		t.Errorf("UpstreamTimeouts.ResponseHeaderTimeoutMS = %d, want default 120000", cfg.UpstreamTimeouts.ResponseHeaderTimeoutMS)
	}
}

func TestLoadErrors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
		if err == nil {
			t.Fatal("expected error for missing file")
		}
		if !strings.Contains(err.Error(), "reading config") {
			t.Errorf("error = %v, want reading config prefix", err)
		}
	})

	t.Run("invalid yaml", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), fileName)
		if err := os.WriteFile(path, []byte("listen: ["), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		_, err := Load(path)
		if err == nil {
			t.Fatal("expected error for invalid yaml")
		}
		if !strings.Contains(err.Error(), "parsing config") {
			t.Errorf("error = %v, want parsing config prefix", err)
		}
	})

	t.Run("unknown field", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), fileName)
		if err := os.WriteFile(path, []byte("unknown_security_setting: true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("expected unknown field to stop startup")
		}
	})

	t.Run("invalid rule regex", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), fileName)
		yaml := "rules:\n  broken:\n    pattern: '[unterminated'\n    action: redact\n"
		if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("expected invalid regex to stop startup")
		}
	})

	t.Run("invalid action", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), fileName)
		yaml := "rules:\n  broken:\n    pattern: secret\n    action: silently_ignore\n"
		if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("expected invalid action to stop startup")
		}
	})
}

func TestLoadDeclarativeRule(t *testing.T) {
	path := filepath.Join(t.TempDir(), fileName)
	yaml := `rules:
  password:
    pattern: '(?i)password=(?P<value>[^ ]+)'
    category: credential
    action: pseudonymize
    generator: password
    priority: 50
    enabled: true
    case_sensitive: false
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	rule := cfg.Rules["password"]
	if rule.Name != "password" || rule.Category != "credential" || rule.Action != "pseudonymize" || rule.Generator != "password" || rule.Priority != 50 {
		t.Fatalf("unexpected rule: %+v", rule)
	}
}

func TestExampleConfigsValidate(t *testing.T) {
	for _, name := range []string{"config.example.yaml", "codex-router.example.yaml"} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(filepath.Join("..", "..", "configs", name)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, fileName)

	if Exists(path) {
		t.Error("Exists = true for missing file")
	}

	if err := os.WriteFile(path, []byte("listen: 127.0.0.1:1\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if !Exists(path) {
		t.Error("Exists = false for existing file")
	}
}
