package install

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	terminal "github.com/AlecAivazis/survey/v2/terminal"
)

const (
	labelOpenAI      = "OpenAI / Codex CLI"
	labelClaude      = "Claude Code"
	labelCursor      = "Cursor IDE"
	labelUpOpenAI    = "OpenAI (api.openai.com)"
	labelUpAnthropic = "Anthropic (api.anthropic.com)"
)

var labelToAgent = map[string]Agent{
	labelOpenAI: AgentOpenAI,
	labelClaude: AgentClaude,
	labelCursor: AgentCursor,
}

func chooseAgents(explicitReader io.Reader) ([]Agent, error) {
	if explicitReader != nil {
		return promptAgentsText(explicitReader, os.Stdout)
	}
	tty, err := openTerminalIO()
	if err != nil {
		return nil, fmt.Errorf("interactive install requires a terminal (use --agents openai,claude,cursor): %w", err)
	}
	defer tty.in.Close()
	return promptAgentsSurvey(tty)
}

func promptAgentsSurvey(tty terminalIO) ([]Agent, error) {
	var selected []string
	prompt := &survey.MultiSelect{
		Message: "Which AI agents do you use?",
		Options: []string{labelOpenAI, labelClaude, labelCursor},
		Help:    "↑/↓ move · space to select · enter to confirm",
	}
	if err := survey.AskOne(prompt, &selected, survey.WithStdio(tty, tty, os.Stderr)); err != nil {
		if err == terminal.InterruptErr {
			return nil, fmt.Errorf("install cancelled")
		}
		return nil, err
	}
	return agentsFromLabels(selected)
}

func promptAgentsText(r io.Reader, w io.Writer) ([]Agent, error) {
	reader := bufio.NewReader(r)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Which AI agents do you use?")
	fmt.Fprintln(w, "  1) OpenAI / Codex CLI")
	fmt.Fprintln(w, "  2) Claude Code")
	fmt.Fprintln(w, "  3) Cursor IDE")
	fmt.Fprint(w, "Enter numbers separated by commas (e.g. 1,2): ")

	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("reading agent choice: %w", err)
	}

	choices := parseChoices(line)
	if len(choices) == 0 {
		return nil, fmt.Errorf("select at least one agent (1, 2, or 3)")
	}

	var agents []Agent
	for _, c := range choices {
		switch c {
		case 1:
			agents = append(agents, AgentOpenAI)
		case 2:
			agents = append(agents, AgentClaude)
		case 3:
			agents = append(agents, AgentCursor)
		default:
			return nil, fmt.Errorf("invalid choice %d (use 1, 2, or 3)", c)
		}
	}
	return agents, nil
}

func agentsFromLabels(labels []string) ([]Agent, error) {
	if len(labels) == 0 {
		return nil, fmt.Errorf("select at least one agent")
	}
	var agents []Agent
	seen := make(map[Agent]bool)
	for _, label := range labels {
		agent, ok := labelToAgent[label]
		if !ok {
			return nil, fmt.Errorf("unknown agent %q", label)
		}
		if !seen[agent] {
			seen[agent] = true
			agents = append(agents, agent)
		}
	}
	return agents, nil
}

func promptUpstream(explicitReader io.Reader) (string, error) {
	if explicitReader != nil {
		return promptUpstreamText(explicitReader, os.Stdout)
	}
	tty, err := openTerminalIO()
	if err != nil {
		return "", err
	}
	defer tty.in.Close()
	return promptUpstreamSurvey(tty)
}

func promptUpstreamSurvey(tty terminalIO) (string, error) {
	var choice string
	prompt := &survey.Select{
		Message: "Cover proxies to one upstream — which should it use?",
		Options: []string{labelUpOpenAI, labelUpAnthropic},
		Help:    "↑/↓ move · enter to select",
	}
	if err := survey.AskOne(prompt, &choice, survey.WithStdio(tty, tty, os.Stderr)); err != nil {
		if err == terminal.InterruptErr {
			return "", fmt.Errorf("install cancelled")
		}
		return "", err
	}
	switch choice {
	case labelUpOpenAI:
		return "https://api.openai.com", nil
	case labelUpAnthropic:
		return "https://api.anthropic.com", nil
	default:
		return "", fmt.Errorf("invalid upstream choice")
	}
}

func promptUpstreamText(r io.Reader, w io.Writer) (string, error) {
	reader := bufio.NewReader(r)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "You selected agents that use different API providers.")
	fmt.Fprintln(w, "Cover proxies to one upstream at a time — which should it use?")
	fmt.Fprintln(w, "  1) OpenAI    (https://api.openai.com)")
	fmt.Fprintln(w, "  2) Anthropic (https://api.anthropic.com)")
	fmt.Fprint(w, "Choice [1-2]: ")
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading upstream choice: %w", err)
	}
	switch strings.TrimSpace(line) {
	case "1", "":
		return "https://api.openai.com", nil
	case "2":
		return "https://api.anthropic.com", nil
	default:
		return "", fmt.Errorf("invalid upstream choice")
	}
}
