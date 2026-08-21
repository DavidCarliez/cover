package codexconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSelectedCoverProvider(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	body := `model_provider = "cover" # active provider

[model_providers.cover]
name = "Cover # local"
base_url = "http://127.0.0.1:8317"
wire_api = "responses"

[features]
enable_request_compression = false
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ModelProvider != "cover" || cfg.SelectedBaseURL() != "http://127.0.0.1:8317" || !cfg.CompressionDisabled {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestLoadBuiltInOpenAIBaseURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("openai_base_url = 'http://localhost:8317'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SelectedBaseURL() != "http://localhost:8317" {
		t.Fatalf("base URL=%q", cfg.SelectedBaseURL())
	}
}
