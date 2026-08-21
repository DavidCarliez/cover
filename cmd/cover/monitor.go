package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/DavidCarliez/cover/internal/activity"
)

func monitorCmd() *cobra.Command {
	var (
		lines    int
		follow   bool
		asJSON   bool
		interval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Watch privacy-safe request metadata without displaying prompt content",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadOrDefaultConfig()
			if err != nil {
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
	cmd.Flags().DurationVar(&interval, "interval", 250*time.Millisecond, "log polling interval")
	return cmd
}
