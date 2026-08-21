// Command cover runs a local HTTP proxy that redacts secrets and other
// sensitive data from requests before forwarding them to a remote LLM API,
// restoring the original values in the response.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/DavidCarliez/cover/internal/config"
	"github.com/DavidCarliez/cover/internal/daemon"
	"github.com/DavidCarliez/cover/internal/install"
	"github.com/DavidCarliez/cover/internal/llamacpp"
	"github.com/DavidCarliez/cover/internal/proxy"
	"github.com/DavidCarliez/cover/internal/redact"
	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

// Local LLM fallback model: a small instruction-tuned GGUF model used by
// `cover models pull`.
const (
	modelFileName = "qwen2.5-0.5b-instruct-q4_k_m.gguf"
	modelURL      = "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf"
)

func main() {
	root := &cobra.Command{
		Use:   "cover",
		Short: "Local secrets-redacting proxy for LLM API traffic",
		Long: "Cover runs a local proxy that any agent can point its API base URL at.\n" +
			"It redacts secrets, API keys, and other sensitive data from requests before\n" +
			"forwarding them to the real LLM provider, and restores the original values\n" +
			"in the response.",
	}

	root.AddCommand(installCmd(), envCmd(), initCmd(), startCmd(), stopCmd(), restartCmd(), statusCmd(), testCmd(), inspectCmd(), modelsCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func installCmd() *cobra.Command {
	var (
		agents    []string
		upstream  string
		skipStart bool
		noProfile bool
	)
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Configure Cover for your agents, start the proxy, and set up shell exports",
		Long: "Interactive setup that writes config, starts the proxy in the background,\n" +
			"adds BASE_URL exports to your shell profile, and prints a ready summary.\n\n" +
			"Usually invoked by scripts/install.sh after building the binary.",
		RunE: func(cmd *cobra.Command, args []string) error {
			var parsed []install.Agent
			for _, a := range agents {
				switch strings.ToLower(strings.TrimSpace(a)) {
				case "openai":
					parsed = append(parsed, install.AgentOpenAI)
				case "claude":
					parsed = append(parsed, install.AgentClaude)
				case "cursor":
					parsed = append(parsed, install.AgentCursor)
				default:
					return fmt.Errorf("unknown agent %q (use openai, claude, or cursor)", a)
				}
			}
			return install.Run(install.Options{
				Agents:    parsed,
				Upstream:  upstream,
				SkipStart: skipStart,
				NoProfile: noProfile,
			})
		},
	}
	cmd.Flags().StringSliceVar(&agents, "agents", nil, "agents to configure: openai, claude, cursor")
	cmd.Flags().StringVar(&upstream, "upstream", "", "upstream API: openai, anthropic, or full URL")
	cmd.Flags().BoolVar(&skipStart, "skip-start", false, "configure only; do not start the proxy")
	cmd.Flags().BoolVar(&noProfile, "no-profile", false, "do not write exports to the shell profile")
	return cmd
}

func envCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "env",
		Short: "Print shell exports for configured agents (eval in your shell)",
		RunE: func(cmd *cobra.Command, args []string) error {
			agents, err := install.LoadSavedAgents()
			if err != nil {
				return err
			}
			if len(agents) == 0 {
				return fmt.Errorf("no saved agent config — run `cover install` first")
			}
			cfg, err := loadOrDefaultConfig()
			if err != nil {
				return err
			}
			for _, line := range install.EnvExports(cfg.Listen, agents) {
				fmt.Println(line)
			}
			return nil
		},
	}
}

func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create the Cover config file",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := config.Path()
			if err != nil {
				return err
			}
			if config.Exists(path) {
				fmt.Printf("Config already exists at %s (edit it directly to make changes)\n", path)
				return nil
			}

			cfg := config.Default()

			fmt.Println("Which LLM API should Cover proxy to?")
			fmt.Println("  1) OpenAI    (https://api.openai.com)")
			fmt.Println("  2) Anthropic (https://api.anthropic.com)")
			fmt.Println("  3) Custom URL")
			fmt.Print("Choice [1-3]: ")

			reader := bufio.NewReader(os.Stdin)
			choice, _ := reader.ReadString('\n')
			switch strings.TrimSpace(choice) {
			case "1":
				cfg.Upstream = "https://api.openai.com"
			case "2":
				cfg.Upstream = "https://api.anthropic.com"
			default:
				fmt.Print("Enter upstream base URL (scheme + host, e.g. https://api.example.com): ")
				u, _ := reader.ReadString('\n')
				cfg.Upstream = strings.TrimSpace(u)
			}

			if cfg.Upstream == "" {
				return fmt.Errorf("no upstream URL provided")
			}

			if err := config.Save(path, cfg); err != nil {
				return err
			}

			fmt.Printf("\nWrote config to %s\n", path)
			fmt.Printf("Proxy will listen on %s and forward to %s\n\n", cfg.Listen, cfg.Upstream)
			fmt.Println("Point your agent at the proxy by setting its API base URL, e.g.:")
			fmt.Printf("  export OPENAI_BASE_URL=http://%s/v1\n", cfg.Listen)
			fmt.Printf("  export ANTHROPIC_BASE_URL=http://%s\n", cfg.Listen)
			fmt.Println("\nThen run: cover start")
			return nil
		},
	}
}

func startCmd() *cobra.Command {
	var detach bool
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the proxy (foreground by default)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if detach {
				return startDetached()
			}
			return runForeground()
		},
	}
	cmd.Flags().BoolVar(&detach, "detach", false, "run in the background")
	return cmd
}

func stopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop a running proxy",
		RunE: func(cmd *cobra.Command, args []string) error {
			pidPath, err := daemon.PidFilePath()
			if err != nil {
				return err
			}
			if err := daemon.StopOrFind(pidPath, listenAddrFromConfig()); err != nil {
				return err
			}
			printStopped(os.Stdout)
			return nil
		},
	}
}

func restartCmd() *cobra.Command {
	var detach bool
	cmd := &cobra.Command{
		Use:   "restart",
		Short: "Stop the proxy if running and start it again",
		RunE: func(cmd *cobra.Command, args []string) error {
			pidPath, err := daemon.PidFilePath()
			if err != nil {
				return err
			}
			if err := daemon.StopOrFindAndWait(pidPath, listenAddrFromConfig(), 5*time.Second); err != nil {
				return err
			}
			if detach {
				return startDetached()
			}
			return runForeground()
		},
	}
	cmd.Flags().BoolVar(&detach, "detach", true, "run in the background")
	return cmd
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether the proxy is running",
		RunE: func(cmd *cobra.Command, args []string) error {
			pidPath, err := daemon.PidFilePath()
			if err != nil {
				return err
			}

			cfg, err := loadOrDefaultConfig()
			if err != nil {
				return err
			}

			pid, running := runningPID(pidPath, cfg.Listen)
			info := statusDisplay{
				Running:  running,
				Listen:   cfg.Listen,
				Upstream: cfg.Upstream,
				LogFile:  cfg.LogFile,
				PID:      pid,
			}
			if running {
				stateDir, err := config.StateDir()
				if err == nil {
					info.DaemonLog = filepath.Join(stateDir, "daemon.log")
				}
			}
			printStatus(os.Stdout, info)
			return nil
		},
	}
}

func runningPID(pidPath, listenAddr string) (int, bool) {
	if pid, err := daemon.Read(pidPath); err == nil && daemon.IsRunning(pid) {
		return pid, true
	}
	if pid, err := daemon.FindListenerPID(listenAddr); err == nil && daemon.IsRunning(pid) {
		return pid, true
	}
	_ = daemon.Remove(pidPath)
	return 0, false
}

func testCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Run a sample payload through the redactor (no network calls)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrDefaultConfig()
			if err != nil {
				return err
			}

			redactor, cleanup, err := buildRedactor(cfg)
			if err != nil {
				return err
			}
			defer cleanup()

			sample := `{
  "messages": [
    {"role": "user", "content": "Here is my AWS key AKIAIOSFODNN7EXAMPLE, my GitHub token ghp_1234567890abcdefghijklmnopqrstuvwxyz12, my email alice@example.com, SSN 123-45-6789, card 4111 1111 1111 1111, and phone (555) 123-4567. Please review this code."}
  ]
}`

			redactedBody, categories := redactor.Redact([]byte(sample))

			fmt.Println("Original request body:")
			fmt.Println(sample)

			fmt.Println("\nRedacted body (this is what the remote LLM sees):")
			fmt.Println(string(redactedBody))

			fmt.Printf("\nDetected categories: %v\n", categories)

			restored := redactor.Restore(redactedBody)
			fmt.Println("\nRestored body (this is what would be returned to the agent if echoed back):")
			fmt.Println(string(restored))

			return nil
		},
	}
}

func inspectCmd() *cobra.Command {
	var session string
	cmd := &cobra.Command{
		Use:   "inspect request.json",
		Short: "Show the protected request that would be sent upstream without forwarding it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrDefaultConfig()
			if err != nil {
				return err
			}
			if err := cfg.Validate(); err != nil {
				return err
			}
			body, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("reading request file: %w", err)
			}
			r, cleanup, err := buildRedactor(cfg)
			if err != nil {
				return err
			}
			defer cleanup()
			result, err := r.Transform(body, session, false, cfg.Media.Images)
			if err != nil {
				return err
			}
			var transformed any
			if len(result.Body) > 0 {
				if err := json.Unmarshal(result.Body, &transformed); err != nil {
					return fmt.Errorf("encoding inspection result")
				}
			}
			output := struct {
				Categories  []string             `json:"categories"`
				Matches     []redact.MatchReport `json:"matches"`
				Transformed int                  `json:"transformed"`
				Blocked     bool                 `json:"blocked"`
				Warnings    []string             `json:"warnings,omitempty"`
				Request     any                  `json:"transformed_request"`
			}{result.Categories, result.Matches, result.Transformed, result.Blocked, result.Warnings, transformed}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(output)
		},
	}
	cmd.Flags().StringVar(&session, "session", "inspect", "local mapping session identifier")
	return cmd
}

func modelsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "models",
		Short: "Manage the local LLM fallback model",
	}
	cmd.AddCommand(modelsPullCmd(), modelsStatusCmd())
	return cmd
}

func modelsPullCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Download the llama-server binary and GGUF model used by the LLM fallback detector",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, _, ok := llamacpp.AssetPattern(); !ok {
				fmt.Printf("No prebuilt llama-server binary is available for %s/%s.\n", runtime.GOOS, runtime.GOARCH)
				fmt.Println("LLM fallback will remain unavailable; regex-based redaction is unaffected.")
				return nil
			}

			cfgPath, err := config.Path()
			if err != nil {
				return err
			}
			cfg, err := loadOrDefaultConfig()
			if err != nil {
				return err
			}
			stateDir, err := config.StateDir()
			if err != nil {
				return err
			}

			fmt.Printf("Fetching llama.cpp release metadata (%s)...\n", cfg.Detectors.LLMFallback.LlamacppRelease)
			rel, err := llamacpp.FetchRelease(cfg.Detectors.LLMFallback.LlamacppRelease)
			if err != nil {
				return err
			}

			assetName, assetURL, ok := rel.FindAsset()
			if !ok {
				return fmt.Errorf("release %s has no prebuilt llama-server for %s/%s", rel.Tag, runtime.GOOS, runtime.GOARCH)
			}

			binDir := filepath.Join(stateDir, "bin")
			serverPath := filepath.Join(binDir, "llama-"+rel.Tag, llamacpp.ServerBinaryName(runtime.GOOS))
			if force || !fileExists(serverPath) {
				fmt.Printf("Downloading %s...\n", assetName)
				serverPath, err = rel.DownloadServerBinary(assetURL, binDir)
				if err != nil {
					return fmt.Errorf("downloading llama-server: %w", err)
				}
			} else {
				fmt.Printf("llama-server already present at %s (use --force to re-download)\n", serverPath)
			}

			modelPath := filepath.Join(stateDir, "models", modelFileName)
			if force || !fileExists(modelPath) {
				fmt.Printf("Downloading %s (~490MB)...\n", modelFileName)
				if err := llamacpp.DownloadModel(modelURL, modelPath, force); err != nil {
					return fmt.Errorf("downloading model: %w", err)
				}
			} else {
				fmt.Printf("model already present at %s (use --force to re-download)\n", modelPath)
			}

			cfg.Detectors.LLMFallback.ServerPath = serverPath
			cfg.Detectors.LLMFallback.ModelPath = modelPath

			if !cfg.Detectors.LLMFallback.Enabled {
				fmt.Print("\nEnable the local LLM fallback now? [y/N]: ")
				reader := bufio.NewReader(os.Stdin)
				resp, _ := reader.ReadString('\n')
				if strings.EqualFold(strings.TrimSpace(resp), "y") {
					cfg.Detectors.LLMFallback.Enabled = true
				}
			}

			if err := config.Save(cfgPath, cfg); err != nil {
				return err
			}

			fmt.Printf("\nServer binary: %s\n", serverPath)
			fmt.Printf("Model file:    %s\n", modelPath)
			if cfg.Detectors.LLMFallback.Enabled {
				fmt.Println("\nLLM fallback enabled. Restart Cover (`cover restart`) to apply.")
			} else {
				fmt.Printf("\nTo enable the LLM fallback later, set `detectors.llm_fallback.enabled: true` in %s\n", cfgPath)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "re-download even if the binary/model are already present")
	return cmd
}

func modelsStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the status of the local LLM fallback model",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrDefaultConfig()
			if err != nil {
				return err
			}
			lf := cfg.Detectors.LLMFallback

			fmt.Printf("enabled:     %v\n", lf.Enabled)

			if pattern, ext, ok := llamacpp.AssetPattern(); ok {
				fmt.Printf("platform:    %s/%s supported (llama-<tag>-bin-%s%s)\n", runtime.GOOS, runtime.GOARCH, pattern, ext)
			} else {
				fmt.Printf("platform:    %s/%s has no prebuilt llama-server; LLM fallback unavailable\n", runtime.GOOS, runtime.GOARCH)
			}

			printPath := func(label, path string) {
				switch {
				case path == "":
					fmt.Printf("%s (not set — run `cover models pull`)\n", label)
				case fileExists(path):
					fmt.Printf("%s %s (present)\n", label, path)
				default:
					fmt.Printf("%s %s (missing — run `cover models pull`)\n", label, path)
				}
			}
			printPath("server_path:", lf.ServerPath)
			printPath("model_path: ", lf.ModelPath)
			return nil
		},
	}
}

// runForeground loads the config, starts the HTTP proxy server, and blocks
// until it receives SIGINT/SIGTERM.
func runForeground() error {
	cfgPath, err := config.Path()
	if err != nil {
		return err
	}
	if !config.Exists(cfgPath) {
		return fmt.Errorf("no config found at %s — run `cover init` first", cfgPath)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if cfg.Upstream == "" {
		return fmt.Errorf("upstream not set in %s — edit the config or re-run `cover init`", cfgPath)
	}

	redactor, cleanupRedactor, err := buildRedactor(cfg)
	if err != nil {
		return err
	}
	defer cleanupRedactor()

	logger, closeLog, err := openLogger(cfg.LogFile)
	if err != nil {
		return err
	}
	defer closeLog()

	p, err := proxy.New(cfg.Upstream, redactor, logger, proxy.Options{
		ConnectTimeout:        time.Duration(cfg.UpstreamTimeouts.ConnectTimeoutMS) * time.Millisecond,
		ResponseHeaderTimeout: time.Duration(cfg.UpstreamTimeouts.ResponseHeaderTimeoutMS) * time.Millisecond,
		SessionHeader:         cfg.Mappings.SessionHeader,
		MediaImages:           cfg.Media.Images,
	})
	if err != nil {
		return err
	}

	pidPath, err := daemon.PidFilePath()
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Listen, err)
	}

	if err := daemon.Write(pidPath, os.Getpid()); err != nil {
		_ = ln.Close()
		return err
	}
	defer daemon.Remove(pidPath)

	srv := &http.Server{Handler: p}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	showStopBanner := false
	go func() {
		<-sigCh
		showStopBanner = true
		srv.Close()
	}()

	if os.Getenv("COVER_NO_BANNER") == "" {
		printStarted(os.Stdout, startDisplay{
			Listen:   cfg.Listen,
			Upstream: cfg.Upstream,
			LogFile:  cfg.LogFile,
			PID:      os.Getpid(),
		})
	}

	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	if showStopBanner {
		printStopped(os.Stdout)
	}
	return nil
}

// startDetached re-executes the current binary with `start` (foreground) as
// a detached background process and records its pid.
func startDetached() error {
	cfgPath, err := config.Path()
	if err != nil {
		return err
	}
	if !config.Exists(cfgPath) {
		return fmt.Errorf("no config found at %s — run `cover init` first", cfgPath)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	pidPath, err := daemon.PidFilePath()
	if err != nil {
		return err
	}
	if pid, err := daemon.Read(pidPath); err == nil && daemon.IsRunning(pid) {
		return fmt.Errorf("Cover is already running (pid %d)", pid)
	}
	if daemon.AddrInUse(cfg.Listen) {
		if pid, err := daemon.FindListenerPID(cfg.Listen); err == nil {
			return fmt.Errorf("Cover is already running on %s (pid %d); use `cover stop`", cfg.Listen, pid)
		}
		return fmt.Errorf("port %s is already in use", cfg.Listen)
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(pidPath), 0o755); err != nil {
		return fmt.Errorf("creating state directory: %w", err)
	}

	logPath := filepath.Join(filepath.Dir(pidPath), "daemon.log")
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("opening daemon log %s: %w", logPath, err)
	}
	defer logFile.Close()

	cmd := exec.Command(exe, "start")
	cmd.Env = append(os.Environ(), "COVER_NO_BANNER=1")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = detachSysProcAttr()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting background process: %w", err)
	}

	if err := daemon.WaitForListen(cfg.Listen, 5*time.Second); err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("Cover failed to start (see %s): %w", logPath, err)
	}

	pid := cmd.Process.Pid
	if recorded, err := daemon.Read(pidPath); err == nil {
		pid = recorded
	}

	printStarted(os.Stdout, startDisplay{
		Listen:   cfg.Listen,
		Upstream: cfg.Upstream,
		LogFile:  cfg.LogFile,
		PID:      pid,
		Detached: true,
		LogPath:  logPath,
	})
	return nil
}

func listenAddrFromConfig() string {
	cfg, err := loadOrDefaultConfig()
	if err != nil {
		return config.Default().Listen
	}
	return cfg.Listen
}

func loadOrDefaultConfig() (*config.Config, error) {
	cfgPath, err := config.Path()
	if err != nil {
		return nil, err
	}
	if config.Exists(cfgPath) {
		return config.Load(cfgPath)
	}
	return config.Default(), nil
}

// buildRedactor assembles a Redactor from cfg. The returned cleanup func
// must be called when the redactor is no longer needed; it stops the local
// LLM fallback subprocess (if one was started).
func buildRedactor(cfg *config.Config) (*redact.Redactor, func(), error) {
	if err := cfg.Validate(); err != nil {
		return nil, func() {}, err
	}
	store := redact.NewStoreWithOptions(redact.StoreOptions{
		MaxSessions:          cfg.Mappings.MaxSessions,
		MaxEntriesPerSession: cfg.Mappings.MaxEntriesPerSession,
		SessionTTL:           time.Duration(cfg.Mappings.SessionTTLMinutes) * time.Minute,
	})
	cleanup := func() {}

	var dets []detectors.Detector
	var fieldRules []redact.FieldRule
	if cfg.Detectors.Regex.Enabled || len(cfg.Rules) > 0 {
		var categories []string
		var custom []detectors.CustomPattern
		if cfg.Detectors.Regex.Enabled {
			categories = cfg.Detectors.Regex.BuiltinCategories
			custom = append(custom, cfg.Detectors.Regex.CustomPatterns...)
			for _, rule := range cfg.Detectors.Regex.CustomPatterns {
				if fieldRule, ok := makeFieldRule(rule); ok {
					fieldRules = append(fieldRules, fieldRule)
				}
			}
		}
		names := make([]string, 0, len(cfg.Rules))
		for name := range cfg.Rules {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			rule := cfg.Rules[name]
			rule.Name = name
			custom = append(custom, rule)
			if fieldRule, ok := makeFieldRule(rule); ok {
				fieldRules = append(fieldRules, fieldRule)
			}
		}
		rd, err := detectors.NewRegexDetector(categories, custom)
		if err != nil {
			return nil, cleanup, fmt.Errorf("configuring regex detector: %w", err)
		}
		dets = append(dets, rd)
	}

	var llmBudget time.Duration
	opts := redact.RedactorOptions{
		SkipLLMIfRegexMatched: cfg.Detectors.LLMFallback.SkipIfRegexMatched,
		LLMConcurrency:        cfg.Detectors.LLMFallback.Concurrency,
		LLMBatchSize:          cfg.Detectors.LLMFallback.BatchSize,
		FieldRules:            fieldRules,
	}
	if cfg.Cache.Enabled {
		opts.Cache = redact.NewDetectionCache(cfg.Cache.MaxEntries)
	}

	if cfg.Detectors.LLMFallback.Enabled {
		if det, llmCleanup, ok := startLLMFallback(cfg.Detectors.LLMFallback); ok {
			dets = append(dets, det)
			llmBudget = time.Duration(cfg.Detectors.LLMFallback.OverallTimeoutMS) * time.Millisecond
			cleanup = llmCleanup
		} else {
			return nil, cleanup, fmt.Errorf("enabled local LLM detector is unavailable; refusing to start with a weaker policy")
		}
	}

	return redact.New(store, llmBudget, opts, dets...), cleanup, nil
}

func makeFieldRule(rule detectors.CustomPattern) (redact.FieldRule, bool) {
	if len(rule.Keys) == 0 || (rule.Enabled != nil && !*rule.Enabled) {
		return redact.FieldRule{}, false
	}
	action := rule.Action
	if action == "" {
		action = string(redact.ActionPlaceholder)
	}
	category := rule.Category
	if category == "" {
		category = rule.Name
	}
	caseSensitive := false
	if rule.CaseSensitive != nil {
		caseSensitive = *rule.CaseSensitive
	}
	return redact.FieldRule{
		Name:          rule.Name,
		Keys:          append([]string(nil), rule.Keys...),
		Category:      category,
		Action:        action,
		Generator:     rule.Generator,
		Priority:      rule.Priority,
		CaseSensitive: caseSensitive,
	}, true
}

// startLLMFallback attempts to start the local llama-server subprocess and
// build an LLM fallback detector from lf. On any failure it prints a
// warning to stderr and returns ok=false so the proxy continues with
// regex-only detection — the LLM fallback is strictly best-effort.
func startLLMFallback(lf config.LLMFallbackConfig) (*llamacpp.Detector, func(), bool) {
	warn := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "Cover: "+format+"; continuing with regex-only detection.\n", args...)
	}

	if lf.ServerPath == "" || lf.ModelPath == "" {
		warn("LLM fallback is enabled but server_path/model_path are not set (run `cover models pull`)")
		return nil, nil, false
	}
	if !fileExists(lf.ServerPath) {
		warn("LLM fallback server binary not found at %s (run `cover models pull`)", lf.ServerPath)
		return nil, nil, false
	}
	if !fileExists(lf.ModelPath) {
		warn("LLM fallback model not found at %s (run `cover models pull`)", lf.ModelPath)
		return nil, nil, false
	}

	stateDir, err := config.StateDir()
	if err != nil {
		warn("resolving state directory: %v", err)
		return nil, nil, false
	}
	logPath := filepath.Join(stateDir, "llama-server.log")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		warn("creating state directory %s: %v", stateDir, err)
		return nil, nil, false
	}
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		warn("opening llama-server log %s: %v", logPath, err)
		return nil, nil, false
	}

	srv, err := llamacpp.StartServer(lf.ServerPath, lf.ModelPath, lf.Port, logFile)
	if err != nil {
		logFile.Close()
		warn("failed to start local LLM fallback server: %v", err)
		return nil, nil, false
	}

	det := llamacpp.NewDetector(srv, lf.MinTextLen, lf.MaxTextLen, time.Duration(lf.RequestTimeoutMS)*time.Millisecond)
	cleanup := func() {
		srv.Stop()
		logFile.Close()
	}
	return det, cleanup, true
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func openLogger(path string) (*log.Logger, func(), error) {
	if path == "" {
		return nil, func() {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, nil, fmt.Errorf("creating log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("opening log file %s: %w", path, err)
	}
	logger := log.New(f, "", log.LstdFlags|log.LUTC)
	return logger, func() { f.Close() }, nil
}
