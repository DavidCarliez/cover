package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const PseudonymKeySize = 32

var errPseudonymKeyIncomplete = errors.New("pseudonym key file is incomplete")

// LoadOrCreatePseudonymKey loads the local HMAC key or creates it with
// owner-only permissions. The key is stored separately from config.yaml so
// sharing a policy file does not also share its pseudonym namespace.
func LoadOrCreatePseudonymKey(path string) ([PseudonymKeySize]byte, error) {
	var key [PseudonymKeySize]byte
	if strings.TrimSpace(path) == "" {
		return key, fmt.Errorf("pseudonym key path must not be empty")
	}
	if loaded, err := loadPseudonymKey(path); err == nil {
		return loaded, nil
	} else if errors.Is(err, errPseudonymKeyIncomplete) {
		return waitForPseudonymKey(path)
	} else if !os.IsNotExist(err) {
		return key, fmt.Errorf("reading pseudonym key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return key, fmt.Errorf("creating pseudonym key directory: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return key, fmt.Errorf("generating pseudonym key: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(key[:]) + "\n"
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if os.IsExist(err) {
		return waitForPseudonymKey(path)
	}
	if err != nil {
		return key, fmt.Errorf("creating pseudonym key: %w", err)
	}
	if _, err := io.WriteString(f, encoded); err != nil {
		_ = f.Close()
		return key, fmt.Errorf("writing pseudonym key: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return key, fmt.Errorf("syncing pseudonym key: %w", err)
	}
	if err := f.Close(); err != nil {
		return key, fmt.Errorf("closing pseudonym key: %w", err)
	}
	return key, nil
}

func waitForPseudonymKey(path string) ([PseudonymKeySize]byte, error) {
	var key [PseudonymKeySize]byte
	for attempt := 0; attempt < 100; attempt++ {
		loaded, err := loadPseudonymKey(path)
		if err == nil {
			return loaded, nil
		}
		if !errors.Is(err, errPseudonymKeyIncomplete) && !os.IsNotExist(err) {
			return key, fmt.Errorf("reading concurrently created pseudonym key: %w", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return key, fmt.Errorf("reading concurrently created pseudonym key: timed out")
}

func loadPseudonymKey(path string) ([PseudonymKeySize]byte, error) {
	var key [PseudonymKeySize]byte
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return key, err
	}
	if !linkInfo.Mode().IsRegular() {
		return key, fmt.Errorf("pseudonym key must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return key, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return key, fmt.Errorf("checking pseudonym key: %w", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return key, fmt.Errorf("pseudonym key must not be accessible by group or other users, got mode %04o", info.Mode().Perm())
	}
	if info.Size() < int64(base64.StdEncoding.EncodedLen(PseudonymKeySize)) {
		return key, errPseudonymKeyIncomplete
	}
	data, err := io.ReadAll(io.LimitReader(f, 129))
	if err != nil {
		return key, fmt.Errorf("reading pseudonym key contents: %w", err)
	}
	if len(data) > 128 {
		return key, fmt.Errorf("pseudonym key file is unexpectedly large")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(decoded) != PseudonymKeySize {
		return key, fmt.Errorf("pseudonym key must be a base64-encoded %d-byte key", PseudonymKeySize)
	}
	copy(key[:], decoded)
	return key, nil
}
