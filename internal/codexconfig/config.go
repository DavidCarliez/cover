// Package codexconfig reads the small subset of user-level Codex configuration
// needed to verify that model traffic is routed through Cover.
package codexconfig

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	ModelProvider       string
	OpenAIBaseURL       string
	ProviderBaseURLs    map[string]string
	CompressionDisabled bool
}

func Path() (string, error) {
	if root := os.Getenv("CODEX_HOME"); root != "" {
		return filepath.Join(root, "config.toml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving Codex config path: %w", err)
	}
	return filepath.Join(home, ".codex", "config.toml"), nil
}

func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	result := Config{ProviderBaseURLs: map[string]string{}}
	table := ""
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(stripComment(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			table = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		key, raw, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value, ok := scalar(strings.TrimSpace(raw))
		if !ok {
			continue
		}
		switch {
		case table == "" && key == "model_provider":
			result.ModelProvider = value
		case table == "" && key == "openai_base_url":
			result.OpenAIBaseURL = value
		case table == "features" && key == "enable_request_compression":
			result.CompressionDisabled = value == "false"
		case strings.HasPrefix(table, "model_providers.") && key == "base_url":
			provider := strings.Trim(strings.TrimPrefix(table, "model_providers."), `"'`)
			if provider != "" {
				result.ProviderBaseURLs[provider] = value
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return Config{}, fmt.Errorf("reading Codex config: %w", err)
	}
	return result, nil
}

func (c Config) SelectedBaseURL() string {
	provider := c.ModelProvider
	if provider == "" || provider == "openai" {
		if c.OpenAIBaseURL != "" {
			return c.OpenAIBaseURL
		}
		if provider == "" {
			provider = "openai"
		}
	}
	return c.ProviderBaseURLs[provider]
}

func stripComment(line string) string {
	var quote rune
	escaped := false
	for i, r := range line {
		if escaped {
			escaped = false
			continue
		}
		if quote == '"' && r == '\\' {
			escaped = true
			continue
		}
		if r == '"' || r == '\'' {
			if quote == 0 {
				quote = r
			} else if quote == r {
				quote = 0
			}
			continue
		}
		if r == '#' && quote == 0 {
			return line[:i]
		}
	}
	return line
}

func scalar(raw string) (string, bool) {
	if raw == "true" || raw == "false" {
		return raw, true
	}
	if len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'' {
		return raw[1 : len(raw)-1], true
	}
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		value, err := strconv.Unquote(raw)
		return value, err == nil
	}
	return "", false
}
