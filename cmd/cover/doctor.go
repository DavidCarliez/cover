package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/DavidCarliez/cover/internal/codexconfig"
	"github.com/DavidCarliez/cover/internal/config"
	"github.com/DavidCarliez/cover/internal/daemon"
	"github.com/DavidCarliez/cover/internal/redact"
	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type doctorReport struct {
	Checks   []doctorCheck `json:"checks"`
	Passed   int           `json:"passed"`
	Warnings int           `json:"warnings"`
	Skipped  int           `json:"skipped"`
	Failed   int           `json:"failed"`
}

func (r *doctorReport) add(name, status, detail string) {
	r.Checks = append(r.Checks, doctorCheck{Name: name, Status: status, Detail: detail})
	switch status {
	case "pass":
		r.Passed++
	case "warn":
		r.Warnings++
	case "skip":
		r.Skipped++
	case "fail":
		r.Failed++
	}
}

func doctorCmd() *cobra.Command {
	var (
		asJSON  bool
		timeout time.Duration
	)
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Verify Cover, its privacy controls, and Codex routing",
		RunE: func(cmd *cobra.Command, args []string) error {
			report := runDoctor(cmd.Context(), timeout)
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(report); err != nil {
					return err
				}
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "Cover doctor")
				for _, check := range report.Checks {
					fmt.Fprintf(cmd.OutOrStdout(), "  %-4s  %-22s %s\n", strings.ToUpper(check.Status), check.Name, check.Detail)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "\n%d passed, %d warnings, %d skipped, %d failed\n", report.Passed, report.Warnings, report.Skipped, report.Failed)
			}
			if report.Failed > 0 {
				return fmt.Errorf("doctor found %d failed check(s)", report.Failed)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
	cmd.Flags().DurationVar(&timeout, "timeout", 2*time.Second, "timeout for the local live check")
	return cmd
}

func runDoctor(ctx context.Context, timeout time.Duration) doctorReport {
	var report doctorReport
	cfgPath, err := config.Path()
	if err != nil {
		report.add("configuration", "fail", "could not resolve the Cover configuration path")
		return report
	}
	if !config.Exists(cfgPath) {
		report.add("configuration", "fail", "configuration is missing; run `cover init`")
		return report
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		report.add("configuration", "fail", "configuration is invalid")
		return report
	}
	report.add("configuration", "pass", "configuration loads and security policy validates")
	if isLoopbackListen(cfg.Listen) {
		report.add("listener policy", "pass", "listener is restricted to the local machine")
	} else {
		report.add("listener policy", "warn", "remote listening is enabled; enforce separate firewall and authentication controls")
	}
	report.add("memory limits", "pass", fmt.Sprintf("request=%d MiB response=%d MiB SSE-event=%d MiB",
		cfg.Limits.RequestBytes>>20, cfg.Limits.ResponseBytes>>20, cfg.Limits.SSEEventBytes>>20))

	key, err := config.LoadOrCreatePseudonymKey(cfg.Pseudonymization.KeyFile)
	if err != nil {
		report.add("pseudonym key", "fail", "persistent HMAC key is missing or unsafe")
	} else {
		report.add("pseudonym key", "pass", "persistent installation key loaded successfully")
		checkRedactionEngine(&report, key)
	}

	if strings.TrimSpace(cfg.Upstream) == "" {
		report.add("upstream routing", "fail", "upstream is not configured")
	} else if upstreamLoopsToCover(cfg.Upstream, cfg.Listen) {
		report.add("upstream routing", "fail", "upstream points back to Cover and would create a loop")
	} else {
		report.add("upstream routing", "pass", "upstream is distinct from the Cover listener")
	}

	pidPath, err := daemon.PidFilePath()
	running := false
	if err == nil {
		_, running = runningPID(pidPath, cfg.Listen)
	}
	if running {
		report.add("proxy process", "pass", "Cover is running")
		checkLiveProxy(ctx, &report, cfg.Listen, timeout)
	} else {
		report.add("proxy process", "fail", "Cover is not running; run `cover start --detach`")
		report.add("live fail-closed", "skip", "proxy is not running")
	}

	if info, err := os.Lstat(cfg.LogFile); err != nil {
		report.add("activity log", "warn", "audit log is unavailable; monitor will work after Cover writes it")
	} else if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		report.add("activity log", "fail", "audit log is not a private regular file")
	} else {
		report.add("activity log", "pass", "private metadata-only audit log is available to monitor")
	}

	checkCodex(&report, cfg.Listen)
	checkEnvironment(&report, cfg.Listen)
	return report
}

func checkRedactionEngine(report *doctorReport, key [config.PseudonymKeySize]byte) {
	detector, err := detectors.NewRegexDetector([]string{"email"}, nil)
	if err != nil {
		report.add("redaction round trip", "fail", "could not initialize the synthetic detector")
		return
	}
	r := redact.New(redact.NewStoreWithOptions(redact.StoreOptions{PseudonymKey: key}), 0, redact.RedactorOptions{}, detector)
	original := []byte(`{"input":"cover-doctor@example.com"}`)
	result, err := r.Transform(original, "doctor", false, "allow")
	if err != nil || result.Transformed != 1 || bytes.Contains(result.Body, []byte("cover-doctor@example.com")) {
		report.add("redaction round trip", "fail", "synthetic value was not safely transformed")
		return
	}
	restored := r.RestoreResponseForSession(result.Body, "application/json", "doctor")
	if !bytes.Contains(restored, []byte("cover-doctor@example.com")) {
		report.add("redaction round trip", "fail", "synthetic value was not restored locally")
		return
	}
	report.add("redaction round trip", "pass", "synthetic value is transformed and restored locally")
}

func checkLiveProxy(ctx context.Context, report *doctorReport, listen string, timeout time.Duration) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+listen+"/__cover_doctor__", strings.NewReader(`{"input":`))
	if err != nil {
		report.add("live fail-closed", "fail", "could not construct the local probe")
		return
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil}}
	response, err := client.Do(request)
	if err != nil {
		report.add("live fail-closed", "fail", "local proxy did not answer the probe")
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnprocessableEntity {
		report.add("live fail-closed", "fail", fmt.Sprintf("unsafe probe returned HTTP %d instead of 422", response.StatusCode))
		return
	}
	report.add("live fail-closed", "pass", "unsafe input is rejected locally with HTTP 422")
}

func checkCodex(report *doctorReport, listen string) {
	path, err := codexconfig.Path()
	if err != nil {
		report.add("Codex routing", "warn", "could not resolve the user-level Codex config path")
		return
	}
	cfg, err := codexconfig.Load(path)
	if os.IsNotExist(err) {
		report.add("Codex routing", "skip", "no user-level Codex config found")
		return
	}
	if err != nil {
		report.add("Codex routing", "fail", "user-level Codex config could not be read")
		return
	}
	expected := "http://" + listen
	if normalizeBaseURL(cfg.SelectedBaseURL()) != normalizeBaseURL(expected) {
		report.add("Codex routing", "fail", "selected Codex provider does not point to Cover")
	} else {
		report.add("Codex routing", "pass", "selected user-level provider points to Cover")
	}
	if cfg.CompressionDisabled {
		report.add("Codex compression", "pass", "request compression is disabled for inspection")
	} else {
		report.add("Codex compression", "fail", "set features.enable_request_compression = false")
	}
}

func checkEnvironment(report *doctorReport, listen string) {
	expected := normalizeBaseURL("http://" + listen)
	checked := false
	for _, name := range []string{"OPENAI_BASE_URL", "ANTHROPIC_BASE_URL"} {
		value := os.Getenv(name)
		if value == "" {
			continue
		}
		checked = true
		normalized := normalizeBaseURL(value)
		if normalized != expected && normalized != expected+"/v1" {
			report.add("environment routing", "warn", name+" does not point to Cover and may bypass it")
			return
		}
	}
	if checked {
		report.add("environment routing", "pass", "configured API base environment variables point to Cover")
	} else {
		report.add("environment routing", "skip", "no API base environment variables are set in this shell")
	}
}

func normalizeBaseURL(value string) string {
	return strings.TrimRight(strings.TrimSpace(value), "/")
}

func upstreamLoopsToCover(upstream, listen string) bool {
	u, err := url.Parse(upstream)
	return err == nil && strings.EqualFold(u.Host, listen)
}

func isLoopbackListen(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
