package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
)

type buildRecord struct {
	PID                     int
	Version, Commit, Digest string
}

func executableDigest() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func RecordBuild(pidPath string, pid int, version, commit string) error {
	digest, err := executableDigest()
	if err != nil {
		return err
	}
	data, err := json.Marshal(buildRecord{pid, version, commit, digest})
	if err != nil {
		return err
	}
	return os.WriteFile(pidPath+".build.json", data, 0600)
}

func CompareBuild(pidPath string, pid int) string {
	data, err := os.ReadFile(pidPath + ".build.json")
	var record buildRecord
	if err != nil || json.Unmarshal(data, &record) != nil || record.PID != pid {
		return "Running build unknown; restart Cover to load the installed binary."
	}
	digest, err := executableDigest()
	if err != nil {
		return "Could not compare the installed and running builds."
	}
	if digest != record.Digest {
		return "Running build differs from the installed binary; run cover restart."
	}
	return "Running build matches the installed binary."
}
