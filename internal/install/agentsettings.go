package install

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/DavidCarliez/cover/internal/atomicfile"
)

// configureAgentSettings writes agent-specific config so clients pick up the
// proxy without relying on shell exports (which install scripts cannot apply
// to the parent shell when executed as ./install.sh).
func configureAgentSettings(out io.Writer, listen string, agents []Agent) error {
	baseHTTP := "http://" + listen
	if containsAgent(agents, AgentClaude) {
		path, err := claudeSettingsPath()
		if err != nil {
			return err
		}
		previous, err := mergeJSONEnv(path, map[string]string{"ANTHROPIC_BASE_URL": baseHTTP})
		if err != nil {
			return fmt.Errorf("claude settings: %w", err)
		}
		if old := previous["ANTHROPIC_BASE_URL"]; old != "" && old != baseHTTP {
			fmt.Fprintf(out, "Note: replaced ANTHROPIC_BASE_URL %s in %s; the previous file is saved as %s.\n", old, path, path+settingsBackupSuffix)
		}
	}
	return nil
}

func claudeSettingsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude", "settings.json"), nil
}

// mergeJSONEnv merges key/value pairs into the "env" object of a JSON settings
// file, preserving all other top-level keys.
const settingsBackupSuffix = ".cover-backup"

// mergeJSONEnv sets env entries in a JSON settings file and returns the
// string values they replaced. Other settings and env values of any type are
// kept. Before Cover first changes a file, the original is saved beside it.
func mergeJSONEnv(path string, env map[string]string) (map[string]string, error) {
	settings := make(map[string]json.RawMessage)
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &settings); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	existing := map[string]json.RawMessage{}
	if raw, ok := settings["env"]; ok {
		if err := json.Unmarshal(raw, &existing); err != nil {
			return nil, fmt.Errorf("parsing env in %s: %w", path, err)
		}
	}
	previous := map[string]string{}
	changed := false
	for k, v := range env {
		var old string
		if raw, ok := existing[k]; ok && json.Unmarshal(raw, &old) == nil {
			previous[k] = old
			if old == v {
				continue
			}
		}
		encoded, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		existing[k], changed = encoded, true
	}
	if !changed {
		return previous, nil
	}
	envRaw, err := json.Marshal(existing)
	if err != nil {
		return nil, err
	}
	settings["env"] = envRaw
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return nil, err
	}
	out = append(out, '\n')
	if data != nil {
		backup := path + settingsBackupSuffix
		if _, err := os.Stat(backup); os.IsNotExist(err) {
			if err := atomicfile.Write(backup, data, 0o600); err != nil {
				return nil, err
			}
		}
	}
	return previous, atomicfile.Write(path, out, 0o644)
}
