// Package activity reads Cover's allowlisted metadata-only audit events.
package activity

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const maxInitialTailBytes = int64(1 << 20)

type Event struct {
	Time          time.Time `json:"time"`
	Status        int       `json:"status,omitempty"`
	Transformed   int       `json:"transformed,omitempty"`
	SentBytes     *int      `json:"sent_bytes,omitempty"`
	ReturnedBytes *int      `json:"returned_bytes,omitempty"`
	DurationMS    *int64    `json:"duration_ms,omitempty"`
	Categories    []string  `json:"categories,omitempty"`
	Error         string    `json:"error,omitempty"`
}

type Options struct {
	Lines    int
	Follow   bool
	JSON     bool
	Interval time.Duration
}

func Parse(line string) (Event, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return Event{}, false
	}
	if len(fields) >= 4 && fields[2] == "upstream" && fields[3] == "error" {
		// A detailed request event follows this diagnostic line. Suppress it so
		// monitor presents one row per request and never exposes rate-limit or
		// request-id header values recorded after the status.
		return Event{}, false
	}
	stamp, err := time.ParseInLocation("2006/01/02 15:04:05", fields[0]+" "+fields[1], time.UTC)
	if err != nil {
		return Event{}, false
	}
	event := Event{Time: stamp}
	seen := false
	for _, field := range fields[2:] {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch key {
		case "status":
			event.Status, ok = safeInt(value)
			seen = seen || ok
		case "transformed":
			event.Transformed, ok = safeInt(value)
			seen = seen || ok
		case "sent_bytes":
			if n, valid := safeInt(value); valid {
				event.SentBytes = &n
			}
		case "returned_bytes":
			if n, valid := safeInt(value); valid {
				event.ReturnedBytes = &n
			}
		case "duration_ms":
			if n, valid := safeInt(value); valid {
				duration := int64(n)
				event.DurationMS = &duration
			}
		case "categories":
			for _, category := range strings.Split(value, ",") {
				if safeLabel(category) {
					event.Categories = append(event.Categories, category)
				}
			}
		case "error":
			if safeLabel(value) {
				event.Error = value
				seen = true
			}
		}
	}
	return event, seen
}

func safeInt(value string) (int, bool) {
	n, err := strconv.Atoi(value)
	return n, err == nil && n >= 0
}

func safeLabel(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' || r == ':' {
			continue
		}
		return false
	}
	return true
}

func Run(ctx context.Context, w io.Writer, path string, opts Options) error {
	if opts.Lines < 0 {
		return fmt.Errorf("lines must not be negative")
	}
	if opts.Interval <= 0 {
		opts.Interval = 250 * time.Millisecond
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("checking audit log: %w", err)
	}
	offset := info.Size()
	if opts.Lines > 0 {
		start := offset - maxInitialTailBytes
		if start < 0 {
			start = 0
		}
		events, err := readEvents(f, start, offset, start > 0)
		if err != nil {
			return err
		}
		if len(events) > opts.Lines {
			events = events[len(events)-opts.Lines:]
		}
		for _, event := range events {
			if err := writeEvent(w, event, opts.JSON); err != nil {
				return err
			}
		}
	}
	if !opts.Follow {
		return nil
	}

	ticker := time.NewTicker(opts.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			pathInfo, err := os.Stat(path)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return fmt.Errorf("checking audit log: %w", err)
			}
			openInfo, err := f.Stat()
			if err != nil {
				return fmt.Errorf("checking open audit log: %w", err)
			}
			if !os.SameFile(pathInfo, openInfo) {
				_ = f.Close()
				f, err = os.Open(path)
				if err != nil {
					return fmt.Errorf("reopening audit log: %w", err)
				}
				offset = 0
			} else if pathInfo.Size() < offset {
				offset = 0
			}
			if pathInfo.Size() <= offset {
				continue
			}
			events, err := readEvents(f, offset, pathInfo.Size(), false)
			if err != nil {
				return err
			}
			offset = pathInfo.Size()
			for _, event := range events {
				if err := writeEvent(w, event, opts.JSON); err != nil {
					return err
				}
			}
		}
	}
}

func readEvents(f *os.File, start, end int64, discardFirst bool) ([]Event, error) {
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seeking audit log: %w", err)
	}
	scanner := bufio.NewScanner(io.LimitReader(f, end-start))
	scanner.Buffer(make([]byte, 4096), 128<<10)
	if discardFirst && scanner.Scan() {
		// The bounded tail may begin in the middle of an older line.
	}
	var events []Event
	for scanner.Scan() {
		if event, ok := Parse(scanner.Text()); ok {
			events = append(events, event)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading audit log: %w", err)
	}
	return events, nil
}

func writeEvent(w io.Writer, event Event, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(w).Encode(event)
	}
	categories := "-"
	if len(event.Categories) > 0 {
		categories = strings.Join(event.Categories, ",")
	}
	errorText := "-"
	if event.Error != "" {
		errorText = event.Error
	}
	sent := "-"
	if event.SentBytes != nil {
		sent = strconv.Itoa(*event.SentBytes)
	}
	returned := "-"
	if event.ReturnedBytes != nil {
		returned = strconv.Itoa(*event.ReturnedBytes)
	}
	duration := "-"
	if event.DurationMS != nil {
		duration = strconv.FormatInt(*event.DurationMS, 10) + "ms"
	}
	_, err := fmt.Fprintf(w, "%s  %3d  %5d  %8s  %8s  %8s  %-20s  %s\n",
		event.Time.Format("15:04:05"), event.Status, event.Transformed, sent,
		returned, duration, categories, errorText)
	return err
}
