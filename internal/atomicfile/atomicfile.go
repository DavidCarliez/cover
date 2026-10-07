// Package atomicfile replaces files so readers never observe a partial write.
package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
)

// Write replaces path with data. A symlinked path keeps its link and replaces
// the target, even one that does not exist yet. An existing file keeps its
// permissions; a new file gets perm.
func Write(path string, data []byte, perm os.FileMode) error {
	path, err := resolveLinks(path)
	if err != nil {
		return err
	}
	if info, err := os.Stat(path); err == nil {
		perm = info.Mode().Perm()
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// resolveLinks follows symlinks at path, including a last link whose target
// is missing, which filepath.EvalSymlinks cannot resolve.
func resolveLinks(path string) (string, error) {
	for range 40 {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			return path, nil
		}
		target, err := os.Readlink(path)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		path = target
	}
	return "", errors.New("too many levels of symbolic links")
}
