package config

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestLoadOrCreatePseudonymKeyIsStableAndInstallationScoped(t *testing.T) {
	dir := t.TempDir()
	pathA := filepath.Join(dir, "a", "pseudonym.key")
	pathB := filepath.Join(dir, "b", "pseudonym.key")

	first, err := LoadOrCreatePseudonymKey(pathA)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreatePseudonymKey(pathA)
	if err != nil {
		t.Fatal(err)
	}
	other, err := LoadOrCreatePseudonymKey(pathB)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("same key file did not produce a stable key")
	}
	if first == other {
		t.Fatal("separate key files unexpectedly produced the same key")
	}
	if first == ([PseudonymKeySize]byte{}) {
		t.Fatal("generated an all-zero key")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(pathA)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("key permissions=%04o, want 0600", info.Mode().Perm())
		}
	}
}

func TestLoadOrCreatePseudonymKeyConcurrentCallersAgree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pseudonym.key")
	const callers = 16
	keys := make([][PseudonymKeySize]byte, callers)
	errs := make([]error, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range keys {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			keys[i], errs[i] = LoadOrCreatePseudonymKey(path)
		}(i)
	}
	close(start)
	wg.Wait()
	for i := range keys {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if keys[i] != keys[0] {
			t.Fatalf("caller %d received a different key", i)
		}
	}
}

func TestLoadOrCreatePseudonymKeyRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	malformed := filepath.Join(dir, "malformed.key")
	if err := os.WriteFile(malformed, []byte("not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreatePseudonymKey(malformed); err == nil {
		t.Fatal("malformed key was accepted")
	}

	symlink := filepath.Join(dir, "symlink.key")
	if err := os.Symlink(malformed, symlink); err == nil {
		if _, err := LoadOrCreatePseudonymKey(symlink); err == nil {
			t.Fatal("symlinked key file was accepted")
		}
	}

	if runtime.GOOS != "windows" {
		permissive := filepath.Join(dir, "permissive.key")
		if err := os.WriteFile(permissive, []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreatePseudonymKey(permissive); err == nil {
			t.Fatal("group/world-readable key was accepted")
		}
	}
}
