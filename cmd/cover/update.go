package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/DavidCarliez/cover/internal/config"
	"github.com/DavidCarliez/cover/internal/daemon"
	updater "github.com/DavidCarliez/cover/internal/update"
	"github.com/spf13/cobra"
)

func updateCmd() *cobra.Command {
	var tag string
	var rollback bool
	cmd := &cobra.Command{Use: "update", Short: "Install a checksum-verified release, with automatic rollback", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if runtime.GOOS == "windows" {
			return fmt.Errorf("self-update requires Linux or macOS; on Windows, stop Cover and use the release installer")
		}
		if rollback && tag != "" {
			return fmt.Errorf("--rollback cannot be combined with --version")
		}
		path, err := os.Executable()
		if err != nil {
			return err
		}
		path, err = filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		cfg, err := loadOrDefaultConfig()
		if err != nil {
			return err
		}
		pidPath, err := daemon.PidFilePath()
		if err != nil {
			return err
		}
		_, running := runningPID(pidPath, cfg.Listen)
		var candidate []byte
		if rollback {
			candidate, err = os.ReadFile(path + ".previous")
		} else {
			client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if req.URL.Scheme != "https" {
					return fmt.Errorf("release redirect must use HTTPS")
				}
				if len(via) >= 10 {
					return fmt.Errorf("too many release redirects")
				}
				return nil
			}}
			const base = "https://github.com/DavidCarliez/cover/releases"
			if tag == "" {
				tag, err = updater.Latest(cmd.Context(), client, base)
				if err != nil {
					return err
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Downloading and verifying %s...\n", tag)
			candidate, err = updater.Fetch(cmd.Context(), client, base, tag, runtime.GOOS, runtime.GOARCH)
		}
		if err != nil {
			return err
		}
		run := func(binary string, args ...string) error {
			ctx, cancel := context.WithTimeout(context.Background(), shutdownWait()+30*time.Second)
			defer cancel()
			proc := exec.CommandContext(ctx, binary, args...)
			if err := proc.Run(); err != nil {
				return fmt.Errorf("cover %s failed; run cover doctor for details: %w", args[0], err)
			}
			return nil
		}
		err = updater.Install(path, candidate, updater.Hooks{
			Validate: func(staged string) error {
				ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
				defer cancel()
				out, err := exec.CommandContext(ctx, staged, "version", "--json").Output()
				if err != nil {
					return err
				}
				var info struct {
					Version string `json:"version"`
				}
				if json.Unmarshal(out, &info) != nil || info.Version == "" {
					return fmt.Errorf("invalid candidate version response")
				}
				if !rollback && info.Version != tag && "v"+info.Version != tag {
					return fmt.Errorf("candidate version does not match release tag")
				}
				cfgPath, pathErr := config.Path()
				if pathErr != nil {
					return pathErr
				}
				if config.Exists(cfgPath) {
					return checkUpdateHealth(cmd.Context(), staged, false)
				}
				return nil
			},
			Stop: func() error {
				if !running {
					return nil
				}
				return daemon.StopOrFindAndWait(pidPath, cfg.Listen, shutdownWait())
			},
			StartAndCheck: func() error {
				if !running {
					return nil
				}
				if err := run(path, "start", "--detach"); err != nil {
					return err
				}
				return checkUpdateHealth(context.Background(), path, true)
			},
		})
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Cover updated. Configuration preserved; previous binary saved for cover update --rollback.")
		return nil
	}}
	cmd.Flags().StringVar(&tag, "version", "", "release tag to install (default: latest)")
	cmd.Flags().BoolVar(&rollback, "rollback", false, "restore the previous installed binary")
	return cmd
}

func checkUpdateHealth(ctx context.Context, binary string, requireRunning bool) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	data, _ := exec.CommandContext(ctx, binary, "doctor", "--json").Output()
	var report doctorReport
	if json.Unmarshal(data, &report) != nil || len(report.Checks) == 0 {
		return fmt.Errorf("Cover health check did not complete")
	}
	for _, check := range report.Checks {
		// A client intentionally routed elsewhere must not block a Cover update.
		if strings.HasPrefix(check.Name, "Codex ") || check.Name == "environment routing" {
			continue
		}
		if !requireRunning && (check.Name == "proxy process" || check.Name == "live fail-closed") {
			continue
		}
		if check.Status == "fail" {
			return fmt.Errorf("Cover health check failed: %s", check.Name)
		}
	}
	return nil
}
