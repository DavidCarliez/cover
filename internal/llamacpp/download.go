package llamacpp

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const releaseAPIBase = "https://api.github.com/repos/ggml-org/llama.cpp/releases"

// Release describes a ggml-org/llama.cpp GitHub release.
type Release struct {
	Tag    string
	Assets map[string]string // asset name -> browser_download_url
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

// FetchRelease fetches release metadata for the given tag, or the latest
// release if tag is "" or "latest".
func FetchRelease(tag string) (*Release, error) {
	url := releaseAPIBase + "/latest"
	if tag != "" && tag != "latest" {
		url = releaseAPIBase + "/tags/" + tag
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Cover")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching release metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching release metadata: %s returned %s", url, resp.Status)
	}

	var gr ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return nil, fmt.Errorf("parsing release metadata: %w", err)
	}

	r := &Release{Tag: gr.TagName, Assets: make(map[string]string, len(gr.Assets))}
	for _, a := range gr.Assets {
		r.Assets[a.Name] = a.BrowserDownloadURL
	}
	return r, nil
}

// FindAsset returns the name and download URL of the prebuilt llama-server
// archive in r matching the current platform, if any.
func (r *Release) FindAsset() (name, url string, ok bool) {
	pattern, ext, ok := AssetPattern()
	if !ok {
		return "", "", false
	}
	name = fmt.Sprintf("llama-%s-bin-%s%s", r.Tag, pattern, ext)
	url, ok = r.Assets[name]
	return name, url, ok
}

// DownloadServerBinary downloads the llama-server release archive at url and
// extracts it into destDir/llama-{tag}/, returning the path to the
// extracted llama-server (or llama-server.exe) binary. The shared libraries
// that ship alongside the binary are extracted into the same directory.
func (r *Release) DownloadServerBinary(url, destDir string) (string, error) {
	tmp, err := downloadToTemp(url)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp)

	extractDir := filepath.Join(destDir, "llama-"+r.Tag)
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		return "", fmt.Errorf("creating %s: %w", extractDir, err)
	}

	if strings.HasSuffix(url, ".zip") {
		if err := extractZip(tmp, destDir); err != nil {
			return "", err
		}
	} else {
		if err := extractTarGz(tmp, destDir); err != nil {
			return "", err
		}
	}

	binName := ServerBinaryName(runtime.GOOS)
	serverPath := filepath.Join(extractDir, binName)
	if _, err := os.Stat(serverPath); err != nil {
		return "", fmt.Errorf("extracted archive did not contain %s: %w", serverPath, err)
	}
	if err := os.Chmod(serverPath, 0o755); err != nil {
		return "", fmt.Errorf("making %s executable: %w", serverPath, err)
	}
	return serverPath, nil
}

// DownloadModel downloads the GGUF model at url to destPath, skipping the
// download if destPath already exists unless force is true. The download is
// streamed to a temporary file and renamed into place on success so a
// partial download never looks like a complete model.
func DownloadModel(url, destPath string, force bool) error {
	if !force {
		if _, err := os.Stat(destPath); err == nil {
			return nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(destPath), err)
	}

	tmpPath := destPath + ".tmp"
	if err := downloadToFile(url, tmpPath); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("finalizing download: %w", err)
	}
	return nil
}

func downloadToTemp(url string) (string, error) {
	f, err := os.CreateTemp("", "llamacpp-server-*")
	if err != nil {
		return "", err
	}
	path := f.Name()
	f.Close()

	if err := downloadToFile(url, path); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

func downloadToFile(url, path string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading %s: server returned %s", url, resp.Status)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("downloading %s: %w", url, err)
	}
	return nil
}

// extractTarGz extracts a gzip-compressed tar archive into destDir,
// preserving the archive's internal directory structure. Entries that would
// escape destDir are rejected.
func extractTarGz(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("opening gzip archive: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading tar archive: %w", err)
		}

		target, err := safeJoin(destDir, hdr.Name)
		if err != nil {
			return err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode)&0o777|0o600)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		case tar.TypeSymlink:
			if err := writeSymlink(destDir, target, hdr.Name, hdr.Linkname); err != nil {
				return err
			}
		default:
			// skip other special entries (hardlinks, devices, etc.)
		}
	}
}

// writeSymlink creates a symlink at target pointing to linkname, after
// verifying linkname is relative and the resulting link stays within
// destDir. llama.cpp's macOS release archives use relative symlinks (e.g.
// libllama-common.0.dylib -> libllama-common.0.0.9660.dylib) so the binary
// can locate its versioned shared libraries.
func writeSymlink(destDir, target, entryName, linkname string) error {
	if filepath.IsAbs(linkname) {
		return fmt.Errorf("archive entry %q has an absolute symlink target %q", entryName, linkname)
	}
	resolved := filepath.Join(filepath.Dir(target), linkname)
	if rel, err := filepath.Rel(destDir, resolved); err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("archive entry %q symlink target %q escapes destination directory", entryName, linkname)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	os.Remove(target)
	if err := os.Symlink(linkname, target); err != nil {
		return fmt.Errorf("creating symlink %s: %w", target, err)
	}
	return nil
}

// extractZip extracts a zip archive into destDir, preserving the archive's
// internal directory structure. Entries that would escape destDir are
// rejected.
func extractZip(archivePath, destDir string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("opening zip archive: %w", err)
	}
	defer zr.Close()

	for _, zf := range zr.File {
		target, err := safeJoin(destDir, zf.Name)
		if err != nil {
			return err
		}

		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}

		in, err := zf.Open()
		if err != nil {
			return err
		}

		if zf.Mode()&os.ModeSymlink != 0 {
			linkTarget, err := io.ReadAll(in)
			in.Close()
			if err != nil {
				return err
			}
			if err := writeSymlink(destDir, target, zf.Name, string(linkTarget)); err != nil {
				return err
			}
			continue
		}

		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			in.Close()
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			in.Close()
			out.Close()
			return err
		}
		in.Close()
		out.Close()
	}
	return nil
}

// safeJoin joins destDir and name, ensuring the result stays within destDir
// (guards against zip-slip / path traversal in archive entries).
func safeJoin(destDir, name string) (string, error) {
	target := filepath.Join(destDir, name)
	rel, err := filepath.Rel(destDir, target)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("archive entry %q escapes destination directory", name)
	}
	return target, nil
}
