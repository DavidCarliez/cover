package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/DavidCarliez/cover/internal/activity"
	"github.com/DavidCarliez/cover/internal/config"
)

var errContentMonitorOnce = errors.New("content monitor completed one event")

func monitorCmd() *cobra.Command {
	var (
		lines       int
		follow      bool
		asJSON      bool
		showContent bool
		once        bool
		interval    time.Duration
	)
	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Watch safe request metadata, with explicit opt-in live content viewing",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrDefaultConfig()
			if err != nil {
				return err
			}
			if once && !showContent {
				return fmt.Errorf("--once requires --show-content")
			}
			if showContent {
				if !follow {
					return fmt.Errorf("--show-content is live-only and requires --follow=true")
				}
				key, err := config.LoadOrCreatePseudonymKey(cfg.Pseudonymization.KeyFile)
				if err != nil {
					return fmt.Errorf("loading live monitor key: %w", err)
				}
				baseURL, err := liveMonitorBaseURL(cfg.Listen)
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: sensitive live view enabled; originals and replacements are displayed locally, not saved. --json also includes outbound request bodies.")
				ready := func() {
					if !asJSON {
						fmt.Fprintln(cmd.ErrOrStderr(), "Waiting for new requests (historical content is never persisted)...")
					}
				}
				err = activity.WatchContent(cmd.Context(), baseURL, activity.ContentToken(key), ready, func(event activity.ContentEvent) error {
					if err := writeContentEvent(cmd.OutOrStdout(), event, asJSON); err != nil {
						return err
					}
					if once {
						return errContentMonitorOnce
					}
					return nil
				})
				if errors.Is(err, errContentMonitorOnce) {
					return nil
				}
				return err
			}
			if !asJSON {
				fmt.Fprintln(cmd.OutOrStdout(), "Cover activity (metadata only; prompt and response content is never shown)")
				fmt.Fprintln(cmd.OutOrStdout(), "TIME      CODE  REDACT      SENT  RETURNED  LATENCY  CATEGORIES            ERROR")
			}
			return activity.Run(cmd.Context(), cmd.OutOrStdout(), cfg.LogFile, activity.Options{
				Lines: lines, Follow: follow, JSON: asJSON, Interval: interval,
			})
		},
	}
	cmd.Flags().IntVarP(&lines, "lines", "n", 20, "number of recent safe events to show")
	cmd.Flags().BoolVarP(&follow, "follow", "f", true, "continue watching for new events")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit newline-delimited JSON events")
	cmd.Flags().BoolVar(&showContent, "show-content", false, "show one original -> replacement pair per line live; add --json for full events (sensitive)")
	cmd.Flags().BoolVar(&once, "once", false, "with --show-content, exit after the next request")
	cmd.Flags().DurationVar(&interval, "interval", 250*time.Millisecond, "log polling interval")
	return cmd
}

func liveMonitorBaseURL(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("invalid Cover listener: %w", err)
	}
	switch {
	case host == "" || host == "0.0.0.0":
		host = "127.0.0.1"
	case host == "::":
		host = "::1"
	case strings.EqualFold(host, "localhost"):
	case net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback():
	default:
		return "", fmt.Errorf("--show-content requires a loopback or all-interface listener")
	}
	return "http://" + net.JoinHostPort(host, port), nil
}

func writeContentEvent(w interface{ Write([]byte) (int, error) }, event activity.ContentEvent, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(w).Encode(event)
	}
	for _, caught := range event.Caught {
		if _, err := fmt.Fprintf(w, "%s -> %s\n", strconv.Quote(caught.Original), strconv.Quote(caught.Replacement)); err != nil {
			return err
		}
	}
	return nil
}
