package main

import (
	"bytes"
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
				fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: sensitive live view enabled; matched originals and transformed request bodies will be displayed locally but not saved.")
				ready := func() {
					if !asJSON {
						fmt.Fprintln(cmd.OutOrStdout(), "Waiting for new requests (historical content is never persisted)...")
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
	cmd.Flags().BoolVar(&showContent, "show-content", false, "show matched originals and exact transformed request bodies live (sensitive)")
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
	if _, err := fmt.Fprintf(w, "\n[%s] transformed=%d blocked=%t\n", event.Time.Local().Format("15:04:05"), event.Transformed, event.Blocked); err != nil {
		return err
	}
	if len(event.Caught) == 0 {
		if _, err := fmt.Fprintln(w, "Caught: none"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(w, "Caught:"); err != nil {
			return err
		}
		for _, caught := range event.Caught {
			if _, err := fmt.Fprintf(w, "  [%s/%s] %s -> %s\n", caught.Category, caught.Action, strconv.Quote(caught.Original), strconv.Quote(caught.Replacement)); err != nil {
				return err
			}
		}
	}
	if event.Blocked {
		_, err := fmt.Fprintln(w, "Sent to LLM: nothing (blocked locally)")
		return err
	}
	if len(event.Sent) == 0 {
		_, err := fmt.Fprintln(w, "Sent to LLM: empty request body")
		return err
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, event.Sent, "", "  "); err != nil {
		pretty.Write(event.Sent)
	}
	_, err := fmt.Fprintf(w, "Sent to LLM:\n%s\n", pretty.Bytes())
	return err
}
