package install

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseChoices(t *testing.T) {
	tests := []struct {
		in   string
		want []int
	}{
		{"1", []int{1}},
		{"1,2", []int{1, 2}},
		{"1, 2, 3", []int{1, 2, 3}},
		{"1/2", []int{1, 2}},
		{"1,1,2", []int{1, 2}},
		{"", nil},
		{"  ", nil},
	}
	for _, tt := range tests {
		got := parseChoices(tt.in)
		if len(got) != len(tt.want) {
			t.Fatalf("parseChoices(%q) = %v, want %v", tt.in, got, tt.want)
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Fatalf("parseChoices(%q) = %v, want %v", tt.in, got, tt.want)
			}
		}
	}
}

func TestNormalizeUpstream(t *testing.T) {
	got, err := normalizeUpstream("openai")
	if err != nil || got != "https://api.openai.com" {
		t.Fatalf("openai: got %q, err %v", got, err)
	}
	got, err = normalizeUpstream("anthropic")
	if err != nil || got != "https://api.anthropic.com" {
		t.Fatalf("anthropic: got %q, err %v", got, err)
	}
	got, err = normalizeUpstream("https://api.example.com")
	if err != nil || got != "https://api.example.com" {
		t.Fatalf("custom: got %q, err %v", got, err)
	}
}

func TestResolveUpstreamSingleAgent(t *testing.T) {
	up, err := resolveUpstream([]Agent{AgentClaude}, "", strings.NewReader(""))
	if err != nil || up != "https://api.anthropic.com" {
		t.Fatalf("claude: got %q, err %v", up, err)
	}
	up, err = resolveUpstream([]Agent{AgentOpenAI}, "", strings.NewReader(""))
	if err != nil || up != "https://api.openai.com" {
		t.Fatalf("openai: got %q, err %v", up, err)
	}
	up, err = resolveUpstream([]Agent{AgentCursor}, "", strings.NewReader(""))
	if err != nil || up != "https://api.openai.com" {
		t.Fatalf("cursor: got %q, err %v", up, err)
	}
}

func TestAgentsFromLabels(t *testing.T) {
	agents, err := agentsFromLabels([]string{labelClaude, labelOpenAI})
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 2 || agents[0] != AgentClaude || agents[1] != AgentOpenAI {
		t.Fatalf("unexpected agents: %v", agents)
	}
	_, err = agentsFromLabels(nil)
	if err == nil {
		t.Fatal("expected error for empty selection")
	}
}

func TestMergeClaudeSettings(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(claudeDir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"alwaysThinkingEnabled":true}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := mergeJSONEnv(path, map[string]string{"ANTHROPIC_BASE_URL": "http://127.0.0.1:8317"}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	var env map[string]string
	if err := json.Unmarshal(settings["env"], &env); err != nil {
		t.Fatal(err)
	}
	if env["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:8317" {
		t.Fatalf("unexpected env: %v", env)
	}
	if _, ok := settings["alwaysThinkingEnabled"]; !ok {
		t.Fatalf("lost alwaysThinkingEnabled: %s", data)
	}
}

func TestConfigureAgentSettingsClaude(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := configureAgentSettings(io.Discard, "127.0.0.1:8317", []Agent{AgentClaude}); err != nil {
		t.Fatal(err)
	}
	path, err := claudeSettingsPath()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ANTHROPIC_BASE_URL") {
		t.Fatalf("missing ANTHROPIC_BASE_URL: %s", data)
	}
}

func TestWriteShellProfileBlock(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SHELL", "/bin/zsh")

	if _, err := writeShellProfile("127.0.0.1:8317", []Agent{AgentOpenAI, AgentClaude}); err != nil {
		t.Fatal(err)
	}
	if _, err := writeShellProfile("127.0.0.1:8317", []Agent{AgentOpenAI, AgentClaude, AgentCursor}); err != nil {
		t.Fatal(err)
	}

	profile, _, err := shellProfilePath()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, profileBegin) || !strings.Contains(content, profileEnd) {
		t.Fatalf("missing markers: %s", content)
	}
	if strings.Count(content, profileBegin) != 1 {
		t.Fatalf("expected one block, got:\n%s", content)
	}
	if !strings.Contains(content, `OPENAI_BASE_URL='http://127.0.0.1:8317/v1'`) {
		t.Fatalf("missing OPENAI_BASE_URL: %s", content)
	}
	if !strings.Contains(content, `ANTHROPIC_BASE_URL='http://127.0.0.1:8317'`) {
		t.Fatalf("missing ANTHROPIC_BASE_URL: %s", content)
	}
}

func TestMergeClaudeSettingsKeepsOtherEnvValuesAndBacksUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	original := `{"env":{"MAX_THINKING_TOKENS":1024,"FLAG":true,"ANTHROPIC_BASE_URL":"https://router.example"}}` + "\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	previous, err := mergeJSONEnv(path, map[string]string{"ANTHROPIC_BASE_URL": "http://127.0.0.1:8317"})
	if err != nil {
		t.Fatal(err)
	}
	if previous["ANTHROPIC_BASE_URL"] != "https://router.example" {
		t.Fatalf("previous=%v", previous)
	}
	data, _ := os.ReadFile(path)
	var settings struct{ Env map[string]any }
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	if settings.Env["MAX_THINKING_TOKENS"] != float64(1024) || settings.Env["FLAG"] != true || settings.Env["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:8317" {
		t.Fatalf("env not merged safely: %s", data)
	}
	if backup, _ := os.ReadFile(path + settingsBackupSuffix); string(backup) != original {
		t.Fatalf("backup=%q", backup)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("permissions changed to %v", info.Mode().Perm())
	}
}

func TestShellProfileQuotesValuesAndSupportsFish(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("SHELL", "/usr/bin/fish")
	path, err := writeShellProfile("127.0.0.1:8317", []Agent{AgentClaude})
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(home, ".config", "fish", "conf.d", "cover.fish") {
		t.Fatalf("fish profile path=%s", path)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "set -gx ANTHROPIC_BASE_URL 'http://127.0.0.1:8317'") {
		t.Fatalf("fish profile=%s", data)
	}
	if got, want := shellQuote(`$(touch x)'`), `'$(touch x)'\'''`; got != want {
		t.Fatalf("shellQuote=%s, want %s", got, want)
	}
}

func TestInstallKeepsConfiguredUpstream(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")
	cfgPath := filepath.Join(home, ".config", "cover", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("# my router\nupstream: https://router.example/v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Run(Options{Agents: []Agent{AgentClaude}, SkipStart: true, NoProfile: true, Writer: &out}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(data), "upstream: https://router.example/v1") || !strings.Contains(string(data), "# my router") {
		t.Fatalf("installer replaced the configured upstream or comments: %s", data)
	}
	if strings.Contains(out.String(), "Updated ") {
		t.Fatalf("reported a profile update with --no-profile: %s", out.String())
	}
	if err := Run(Options{Agents: []Agent{AgentClaude}, Upstream: "openai", SkipStart: true, NoProfile: true, Writer: &out}); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(cfgPath)
	if !strings.Contains(string(data), "upstream: https://api.openai.com") || !strings.Contains(string(data), "# my router") {
		t.Fatalf("explicit upstream was not applied with comments kept: %s", data)
	}
}
