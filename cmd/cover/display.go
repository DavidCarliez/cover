package main

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

type startDisplay struct {
	Listen   string
	Upstream string
	LogFile  string
	PID      int
	Detached bool
	LogPath  string // daemon log when Detached
}

func printStarted(w io.Writer, info startDisplay) {
	const (
		reset  = "\033[0m"
		bold   = "\033[1m"
		green  = "\033[32m"
		cyan   = "\033[36m"
		yellow = "\033[33m"
		dim    = "\033[2m"
	)

	useColor := isTerminalWriter(w)
	c := func(code, s string) string {
		if !useColor {
			return s
		}
		return code + s + reset
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, c(bold+green, "  ┌─────────────────────────────────────────────────────┐"))
	fmt.Fprintln(w, c(bold+green, "  │                                                     │"))
	fmt.Fprintln(w, c(bold+green, "  │   ✓  Cover is protecting you                        │"))
	fmt.Fprintln(w, c(bold+green, "  │                                                     │"))
	fmt.Fprintln(w, c(bold+green, "  └─────────────────────────────────────────────────────┘"))
	fmt.Fprintln(w)

	fmt.Fprintln(w, c(green, "  The cruel upstream LLM servers shall not have your secrets."))
	fmt.Fprintln(w, c(dim, "  API keys, tokens, emails, and other sensitive bits in your"))
	fmt.Fprintln(w, c(dim, "  prompts are stripped and replaced with placeholders before"))
	fmt.Fprintln(w, c(dim, "  they ever leave your machine — then restored on the way back."))
	fmt.Fprintln(w)
	fmt.Fprintln(w, c(bold, "  Standing guard over:"))
	fmt.Fprintln(w, "    • API keys and auth tokens")
	fmt.Fprintln(w, "    • Passwords and private keys")
	fmt.Fprintln(w, "    • Emails, SSNs, and other PII")
	fmt.Fprintln(w, "    • Internal codenames and customer data")
	fmt.Fprintln(w)

	if info.PID > 0 {
		fmt.Fprintf(w, "  %s %s\n", c(dim, "Status:"), c(green, fmt.Sprintf("running (pid %d)", info.PID)))
	}
	fmt.Fprintf(w, "  %s %s\n", c(dim, "Proxy:"), c(cyan, "http://"+info.Listen))
	fmt.Fprintf(w, "  %s %s\n", c(dim, "Upstream:"), safeUpstreamDisplay(info.Upstream))
	fmt.Fprintf(w, "  %s %s\n", c(dim, "Redaction log:"), info.LogFile)
	fmt.Fprintln(w)

	if info.Detached {
		fmt.Fprintf(w, "  %s %s\n", c(dim, "Daemon log:"), info.LogPath)
		fmt.Fprintln(w)
		fmt.Fprintln(w, c(dim, "  Running in the background. To stand down:"))
		fmt.Fprintf(w, "    %s\n", c(yellow, "cover stop"))
	} else {
		fmt.Fprintln(w, c(dim, "  Press Ctrl+C to stop — and face the cruel servers unguarded again."))
	}
	fmt.Fprintln(w)
}

type statusDisplay struct {
	Running   bool
	Listen    string
	Upstream  string
	LogFile   string
	PID       int
	DaemonLog string
}

func printStatus(w io.Writer, info statusDisplay) {
	const (
		reset  = "\033[0m"
		bold   = "\033[1m"
		green  = "\033[32m"
		cyan   = "\033[36m"
		yellow = "\033[33m"
		dim    = "\033[2m"
	)

	useColor := isTerminalWriter(w)
	c := func(code, s string) string {
		if !useColor {
			return s
		}
		return code + s + reset
	}

	fmt.Fprintln(w)
	if info.Running {
		fmt.Fprintln(w, c(bold+green, "  ┌─────────────────────────────────────────────────────┐"))
		fmt.Fprintln(w, c(bold+green, "  │                                                     │"))
		fmt.Fprintln(w, c(bold+green, "  │   ✓  Cover is protecting you                        │"))
		fmt.Fprintln(w, c(bold+green, "  │                                                     │"))
		fmt.Fprintln(w, c(bold+green, "  └─────────────────────────────────────────────────────┘"))
	} else {
		fmt.Fprintln(w, c(bold+yellow, "  ┌─────────────────────────────────────────────────────┐"))
		fmt.Fprintln(w, c(bold+yellow, "  │                                                     │"))
		fmt.Fprintln(w, c(bold+yellow, "  │   ○  Cover is not running                           │"))
		fmt.Fprintln(w, c(bold+yellow, "  │                                                     │"))
		fmt.Fprintln(w, c(bold+yellow, "  └─────────────────────────────────────────────────────┘"))
	}
	fmt.Fprintln(w)

	if info.Running {
		fmt.Fprintf(w, "  %s %s\n", c(dim, "Status:"), c(green, fmt.Sprintf("running (pid %d)", info.PID)))
		fmt.Fprintf(w, "  %s %s\n", c(dim, "Proxy:"), c(cyan, "http://"+info.Listen))
		fmt.Fprintf(w, "  %s %s\n", c(dim, "Upstream:"), safeUpstreamDisplay(info.Upstream))
		fmt.Fprintf(w, "  %s %s\n", c(dim, "Redaction log:"), info.LogFile)
		if info.DaemonLog != "" {
			fmt.Fprintf(w, "  %s %s\n", c(dim, "Daemon log:"), info.DaemonLog)
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, c(dim, "  Commands: cover stop · cover restart"))
	} else {
		fmt.Fprintln(w, c(dim, "  The cruel upstream LLM servers are unchallenged."))
		fmt.Fprintln(w, c(dim, "  Your secrets have no local guardian right now."))
		fmt.Fprintln(w)
		fmt.Fprintln(w, c(dim, "  To stand up the proxy:"))
		fmt.Fprintf(w, "    %s\n", c(yellow, "cover start --detach"))
	}
	fmt.Fprintln(w)
}

func safeUpstreamDisplay(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "<configured>"
	}
	origin := u.Scheme + "://" + u.Host
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return strings.TrimSuffix(origin, "/") + "/<redacted>"
	}
	return origin
}

func printStopped(w io.Writer) {
	const (
		reset  = "\033[0m"
		bold   = "\033[1m"
		red    = "\033[31m"
		yellow = "\033[33m"
		dim    = "\033[2m"
	)

	useColor := isTerminalWriter(w)
	c := func(code, s string) string {
		if !useColor {
			return s
		}
		return code + s + reset
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, c(bold+red, "  ┌─────────────────────────────────────────────────────┐"))
	fmt.Fprintln(w, c(bold+red, "  │                                                     │"))
	fmt.Fprintln(w, c(bold+red, "  │   ✗  Cover is stopped                               │"))
	fmt.Fprintln(w, c(bold+red, "  │                                                     │"))
	fmt.Fprintln(w, c(bold+red, "  └─────────────────────────────────────────────────────┘"))
	fmt.Fprintln(w)

	fmt.Fprintln(w, c(yellow, "  You are on your own now."))
	fmt.Fprintln(w, c(dim, "  The cruel upstream LLM servers have you unguarded —"))
	fmt.Fprintln(w, c(dim, "  every API key, token, email, and secret in your prompts"))
	fmt.Fprintln(w, c(dim, "  sails straight to them, redaction-free."))
	fmt.Fprintln(w)
	fmt.Fprintln(w, c(bold, "  Be careful with:"))
	fmt.Fprintln(w, "    • API keys and auth tokens")
	fmt.Fprintln(w, "    • Passwords and private keys")
	fmt.Fprintln(w, "    • Emails, SSNs, and other PII")
	fmt.Fprintln(w, "    • Internal codenames and customer data")
	fmt.Fprintln(w)
	fmt.Fprintln(w, c(dim, "  To shield yourself again:"))
	fmt.Fprintf(w, "    %s\n", c(yellow, "cover start --detach"))
	fmt.Fprintln(w)
}

func isTerminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
