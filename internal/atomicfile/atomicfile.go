// Package atomicfile replaces files so readers never observe a partial write.
package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// resolveLinks follows existing path components before interpreting "..".
// Missing suffixes are allowed so Write can create a dangling link's target.
func resolveLinks(path string) (string, error) {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if !filepath.IsAbs(path) {
		volume := filepath.VolumeName(path)
		base, err := filepath.Abs(volume + ".")
		if err != nil {
			return "", err
		}
		path = path[len(volume):]
		if len(path) > 0 && os.IsPathSeparator(path[0]) {
			path = filepath.VolumeName(base) + path
		} else {
			path = base + string(filepath.Separator) + path
		}
	}
	volume := filepath.VolumeName(path)
	resolved := volume + string(filepath.Separator)
	remaining := filepath.ToSlash(path[len(volume):])
	links := 0
	for remaining != "" {
		part, rest, _ := strings.Cut(remaining, "/")
		remaining = rest
		switch part {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, part)
		info, err := os.Lstat(next)
		if err != nil {
			if !os.IsNotExist(err) {
				return "", err
			}
			resolved = next
			continue
		}
		if info.Mode()&os.ModeSymlink == 0 {
			resolved = next
			continue
		}
		links++
		if links > 40 {
			return "", errors.New("too many levels of symbolic links")
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(target) {
			volume = filepath.VolumeName(target)
			resolved = volume + string(filepath.Separator)
			target = target[len(volume):]
		}
		// Do not Join here: the target may itself cross a symlink before "..".
		remaining = filepath.ToSlash(target) + "/" + remaining
	}
	return resolved, nil
}
