// Package config handles loading, saving, and defaulting llm-guard's
// configuration file (~/.config/llmguard/config.yaml).
package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"llmguard/internal/redact"
	"llmguard/internal/redact/detectors"
)

// Config is the top-level configuration loaded from config.yaml.
type Config struct {
	Listen           string                             `yaml:"listen"`
	Upstream         string                             `yaml:"upstream"`
	LogFile          string                             `yaml:"log_file"`
	UpstreamTimeouts UpstreamTimeoutsConfig             `yaml:"upstream_timeouts"`
	Cache            CacheConfig                        `yaml:"cache"`
	Detectors        DetectorsConfig                    `yaml:"detectors"`
	Rules            map[string]detectors.CustomPattern `yaml:"rules"`
	Mappings         MappingsConfig                     `yaml:"mappings"`
	Media            MediaConfig                        `yaml:"media"`
}

type MappingsConfig struct {
	SessionHeader        string `yaml:"session_header"`
	MaxSessions          int    `yaml:"max_sessions"`
	MaxEntriesPerSession int    `yaml:"max_entries_per_session"`
	SessionTTLMinutes    int    `yaml:"session_ttl_minutes"`
}

type MediaConfig struct {
	Images string `yaml:"images"`
}

// UpstreamTimeoutsConfig bounds how long the proxy waits on the upstream LLM
// API. ResponseHeaderTimeout applies only until the first response byte;
// streaming bodies are not capped by Client.Timeout so long SSE streams can
// run indefinitely.
type UpstreamTimeoutsConfig struct {
	ConnectTimeoutMS        int `yaml:"connect_timeout_ms"`
	ResponseHeaderTimeoutMS int `yaml:"response_header_timeout_ms"`
}

// CacheConfig configures the in-memory redaction result cache.
type CacheConfig struct {
	Enabled    bool `yaml:"enabled"`
	MaxEntries int  `yaml:"max_entries"`
}

// DetectorsConfig groups settings for each detector type.
type DetectorsConfig struct {
	Regex       RegexConfig       `yaml:"regex"`
	LLMFallback LLMFallbackConfig `yaml:"llm_fallback"`
}

// RegexConfig configures the built-in regex detector.
type RegexConfig struct {
	Enabled           bool                      `yaml:"enabled"`
	BuiltinCategories []string                  `yaml:"builtin_categories"`
	CustomPatterns    []detectors.CustomPattern `yaml:"custom_patterns"`
}

// LLMFallbackConfig configures the optional local-LLM semantic detector. When
// enabled, llm-guard spawns a local `llama-server` subprocess (downloaded via
// `llmguard models pull`) and uses it as an additional detector for sensitive
// content that regex patterns miss. Startup and request-time detector failures
// are fatal/fail-closed while this detector is enabled.
type LLMFallbackConfig struct {
	Enabled bool `yaml:"enabled"`

	// ServerPath is the path to the llama-server binary, set by
	// `llmguard models pull`.
	ServerPath string `yaml:"server_path"`
	// ModelPath is the path to the GGUF model file, set by
	// `llmguard models pull`.
	ModelPath string `yaml:"model_path"`
	// Port is the local port llama-server listens on.
	Port int `yaml:"port"`

	// MinTextLen is the minimum string length (in bytes) considered for the
	// LLM pass; shorter strings are skipped.
	MinTextLen int `yaml:"min_text_len"`
	// MaxTextLen is the maximum string length (in bytes) considered for the
	// LLM pass; longer strings are skipped to bound latency.
	MaxTextLen int `yaml:"max_text_len"`

	// RequestTimeoutMS bounds a single call to llama-server's /completion
	// endpoint.
	RequestTimeoutMS int `yaml:"request_timeout_ms"`
	// OverallTimeoutMS bounds the total time spent across all LLM detector
	// calls for a single proxied request.
	OverallTimeoutMS int `yaml:"overall_timeout_ms"`

	// SkipIfRegexMatched skips the LLM pass for a string when regex
	// detectors already found matches in that string.
	SkipIfRegexMatched bool `yaml:"skip_if_regex_matched"`

	// Concurrency is the maximum number of parallel LLM detector calls per
	// proxied request when batching is not used.
	Concurrency int `yaml:"concurrency"`

	// BatchSize is the number of strings sent in a single LLM /completion
	// call when batching is supported. Set to 1 to disable batching.
	BatchSize int `yaml:"batch_size"`

	// LlamacppRelease is the ggml-org/llama.cpp release tag `models pull`
	// downloads from, or "latest".
	LlamacppRelease string `yaml:"llamacpp_release"`
}

const (
	dirName       = "llmguard"
	fileName      = "config.yaml"
	logName       = "redactions.log"
	defaultListen = "127.0.0.1:8317"
)

// Default returns a Config populated with sensible defaults. Upstream is
// left blank and must be set by the user (via `llmguard init` or by editing
// the config file).
func Default() *Config {
	return &Config{
		Listen:   defaultListen,
		Upstream: "",
		LogFile:  defaultLogPath(),
		UpstreamTimeouts: UpstreamTimeoutsConfig{
			ConnectTimeoutMS:        10000,
			ResponseHeaderTimeoutMS: 120000,
		},
		Cache: CacheConfig{
			Enabled:    true,
			MaxEntries: 10000,
		},
		Rules: map[string]detectors.CustomPattern{},
		Mappings: MappingsConfig{
			SessionHeader:        "X-LLMGuard-Session",
			MaxSessions:          128,
			MaxEntriesPerSession: 10000,
			SessionTTLMinutes:    60,
		},
		Media: MediaConfig{Images: "allow"},
		Detectors: DetectorsConfig{
			Regex: RegexConfig{
				Enabled:           true,
				BuiltinCategories: detectors.BuiltinCategories(),
				CustomPatterns:    []detectors.CustomPattern{},
			},
			LLMFallback: LLMFallbackConfig{
				Enabled:            false,
				Port:               8418,
				MinTextLen:         8,
				MaxTextLen:         2000,
				RequestTimeoutMS:   3000,
				OverallTimeoutMS:   4000,
				SkipIfRegexMatched: false,
				Concurrency:        4,
				BatchSize:          8,
				LlamacppRelease:    "latest",
			},
		},
	}
}

// Path returns the default config file path: ~/.config/llmguard/config.yaml.
func Path() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, ".config", dirName, fileName), nil
}

// StateDir returns the directory used for llm-guard's persistent local
// state (logs, downloaded llama-server binaries, GGUF models):
// ~/.local/share/llmguard.
func StateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, ".local", "share", dirName), nil
}

func defaultLogPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", logName)
	}
	return filepath.Join(home, ".local", "share", dirName, logName)
}

// Load reads and parses the config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	cfg := Default()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config %s: %w", path, err)
	}
	return cfg, nil
}

// Validate rejects an invalid security policy instead of silently weakening it.
func (c *Config) Validate() error {
	if c.Mappings.MaxSessions <= 0 || c.Mappings.MaxEntriesPerSession <= 0 || c.Mappings.SessionTTLMinutes <= 0 {
		return fmt.Errorf("mapping limits and TTL must be positive")
	}
	switch c.Media.Images {
	case "allow", "warn", "block":
	default:
		return fmt.Errorf("media.images must be allow, warn, or block")
	}
	rules := make([]detectors.CustomPattern, 0, len(c.Rules)+len(c.Detectors.Regex.CustomPatterns))
	for _, rule := range c.Detectors.Regex.CustomPatterns {
		if rule.Action != "" {
			if err := redact.ValidateAction(rule.Action, rule.Generator); err != nil {
				return fmt.Errorf("custom pattern %q: %w", rule.Name, err)
			}
		}
		rules = append(rules, rule)
	}
	for name, rule := range c.Rules {
		rule.Name = name
		if rule.Category == "" {
			rule.Category = name
		}
		if rule.Action == "" {
			return fmt.Errorf("rule %q has no action", name)
		}
		if err := redact.ValidateAction(rule.Action, rule.Generator); err != nil {
			return fmt.Errorf("rule %q: %w", name, err)
		}
		c.Rules[name] = rule
		rules = append(rules, rule)
	}
	if _, err := detectors.NewRegexDetector(c.Detectors.Regex.BuiltinCategories, rules); err != nil {
		return err
	}
	return nil
}

// Save writes cfg to path as YAML, creating parent directories as needed.
func Save(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing config %s: %w", path, err)
	}
	return nil
}

// Exists reports whether a file exists at path.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
