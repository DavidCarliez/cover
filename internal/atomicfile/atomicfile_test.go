package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteKeepsSymlinkAndPermissions(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dotfiles", "zshrc")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, ".zshrc")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	if err := Write(link, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced by a regular file")
	}
	data, _ := os.ReadFile(target)
	info, _ := os.Stat(target)
	if string(data) != "new" || info.Mode().Perm() != 0o640 {
		t.Fatalf("target=%q mode=%v", data, info.Mode().Perm())
	}
	if entries, _ := os.ReadDir(filepath.Dir(target)); len(entries) != 1 {
		t.Fatalf("temporary files remain: %v", entries)
	}
}

func TestWriteCreatesWithPermission(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new", "config.yaml")
	if err := Write(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info.Mode().Perm(), err)
	}
}
