// Package update downloads verified release binaries and installs them with
// rollback. It never modifies configuration or client routing.
package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const maxBinary = 128 << 20

var tagPattern = regexp.MustCompile(`^v[0-9][0-9A-Za-z._-]*$`)

func get(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("release download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("release download returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("release asset exceeds size limit")
	}
	return body, nil
}

func Latest(ctx context.Context, client *http.Client, base string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/latest", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("latest release lookup returned HTTP %d", resp.StatusCode)
	}
	tag := filepath.Base(resp.Request.URL.Path)
	if !tagPattern.MatchString(tag) {
		return "", fmt.Errorf("no published release found")
	}
	return tag, nil
}

func Fetch(ctx context.Context, client *http.Client, base, tag, goos, arch string) ([]byte, error) {
	if !tagPattern.MatchString(tag) {
		return nil, fmt.Errorf("invalid release tag")
	}
	ext := ".tar.gz"
	binary := "cover"
	if goos == "windows" {
		ext = ".zip"
		binary = "cover.exe"
	}
	asset := "cover_" + strings.TrimPrefix(tag, "v") + "_" + goos + "_" + arch + ext
	root := base + "/download/" + tag + "/"
	checks, err := get(ctx, client, root+"checksums.txt", 1<<20)
	if err != nil {
		return nil, err
	}
	expected := ""
	for _, line := range strings.Split(string(checks), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == asset {
			if expected != "" {
				return nil, fmt.Errorf("duplicate checksum entry")
			}
			expected = strings.ToLower(fields[0])
		}
	}
	if decoded, err := hex.DecodeString(expected); err != nil || len(decoded) != sha256.Size {
		return nil, fmt.Errorf("release checksum is missing or invalid")
	}
	archive, err := get(ctx, client, root+asset, maxBinary)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(archive)
	if hex.EncodeToString(sum[:]) != expected {
		return nil, fmt.Errorf("checksum verification failed; nothing installed")
	}
	return extract(archive, binary, ext)
}

func extract(archive []byte, name, ext string) ([]byte, error) {
	var result []byte
	read := func(r io.Reader) error {
		if result != nil {
			return fmt.Errorf("duplicate binary in archive")
		}
		data, err := io.ReadAll(io.LimitReader(r, maxBinary+1))
		if err != nil {
			return err
		}
		if len(data) == 0 || len(data) > maxBinary {
			return fmt.Errorf("invalid binary size")
		}
		result = data
		return nil
	}
	if ext == ".zip" {
		zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if f.Name == name {
				if !f.Mode().IsRegular() {
					return nil, fmt.Errorf("binary is not a regular file")
				}
				r, err := f.Open()
				if err != nil {
					return nil, err
				}
				err = read(r)
				r.Close()
				if err != nil {
					return nil, err
				}
			}
		}
	} else {
		gz, err := gzip.NewReader(bytes.NewReader(archive))
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		tr := tar.NewReader(io.LimitReader(gz, 2*maxBinary))
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			if h.Name == name {
				if h.Typeflag != tar.TypeReg {
					return nil, fmt.Errorf("binary is not a regular file")
				}
				if err = read(tr); err != nil {
					return nil, err
				}
			}
		}
	}
	if result == nil {
		return nil, fmt.Errorf("archive does not contain %s", name)
	}
	return result, nil
}

type Hooks struct {
	Validate      func(string) error
	Stop          func() error
	StartAndCheck func() error
}

func stage(path string, data []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".cover-update-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(name)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return "", err
	}
	if err = f.Chmod(0755); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

// Install saves the current binary at path.previous before replacing it.
// Hooks run for both the candidate and, if necessary, the restored binary.
func Install(path string, candidate []byte, h Hooks) error {
	lock, err := os.OpenFile(path+".update.lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("cannot acquire update lock (another update may be running): %w", err)
	}
	lock.Close()
	defer os.Remove(path + ".update.lock")
	staged, err := stage(path, candidate)
	if err != nil {
		return err
	}
	defer os.Remove(staged)
	if err = h.Validate(staged); err != nil {
		return fmt.Errorf("candidate validation failed: %w", err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	backup, err := stage(path, current)
	if err != nil {
		return err
	}
	defer os.Remove(backup)
	if err = h.Stop(); err != nil {
		return fmt.Errorf("could not stop Cover; binary unchanged: %w", err)
	}
	if err = os.Rename(backup, path+".previous"); err != nil {
		return fmt.Errorf("cannot save rollback binary: %w; restart: %v", err, h.StartAndCheck())
	}
	if err = os.Rename(staged, path); err != nil {
		return fmt.Errorf("cannot install binary: %w; restart: %v", err, h.StartAndCheck())
	}
	if healthErr := h.StartAndCheck(); healthErr != nil {
		if err = h.Stop(); err != nil {
			return fmt.Errorf("update health check failed; rollback could not stop daemon: %w", err)
		}
		restored, err := stage(path, current)
		if err != nil {
			return fmt.Errorf("rollback staging failed: %w", err)
		}
		defer os.Remove(restored)
		if err = os.Rename(restored, path); err != nil {
			return fmt.Errorf("rollback failed: %w", err)
		}
		if err = h.StartAndCheck(); err != nil {
			return fmt.Errorf("previous binary restored but health check failed: %w", err)
		}
		return fmt.Errorf("update health check failed; previous binary restored: %w", healthErr)
	}
	return nil
}
