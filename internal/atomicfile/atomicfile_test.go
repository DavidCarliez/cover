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

func TestWriteKeepsDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	// A dotfiles manager may link a profile before its target exists.
	target := filepath.Join(dir, "dotfiles", "fish", "cover.fish")
	link := filepath.Join(dir, "cover.fish")
	if err := os.Symlink(filepath.Join("dotfiles", "fish", "cover.fish"), link); err != nil {
		t.Skip("symlinks unavailable")
	}
	if err := Write(link, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("dangling symlink was replaced by a regular file")
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "new" {
		t.Fatalf("target=%q err=%v", data, err)
	}

	loop := filepath.Join(dir, "loop")
	if err := os.Symlink("loop", loop); err != nil {
		t.Fatal(err)
	}
	if err := Write(loop, []byte("x"), 0o600); err == nil {
		t.Fatal("symlink loop was replaced")
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

func TestWriteResolvesParentLinksBeforeRelativeTargets(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "existing"}[existing], func(t *testing.T) {
			root := t.TempDir()
			shell := filepath.Join(root, "dotfiles", "shell")
			shared := filepath.Join(root, "dotfiles", "shared")
			for _, dir := range []string{shell, shared} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			target := filepath.Join(shared, "profile")
			if existing {
				if err := os.WriteFile(target, []byte("old"), 0o640); err != nil {
					t.Fatal(err)
				}
			}
			parent := filepath.Join(root, "profiles")
			if err := os.Symlink(shell, parent); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			link := filepath.Join(shell, "profile")
			if err := os.Symlink(filepath.Join("..", "shared", "profile"), link); err != nil {
				t.Fatal(err)
			}
			if err := Write(filepath.Join(parent, "profile"), []byte("updated"), 0o600); err != nil {
				t.Fatal(err)
			}
			if data, err := os.ReadFile(target); err != nil || string(data) != "updated" {
				t.Fatalf("intended target=%q err=%v", data, err)
			}
			if _, err := os.Lstat(filepath.Join(root, "shared")); !os.IsNotExist(err) {
				t.Fatalf("unexpected sibling path: %v", err)
			}
			if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("link was replaced: %v", err)
			}
		})
	}
}
