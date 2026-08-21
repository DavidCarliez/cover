// Package llamacpp manages an optional local llama-server subprocess
// (downloaded from ggml-org/llama.cpp's GitHub releases) used as a
// best-effort LLM-based fallback detector for sensitive text that regex
// patterns miss. The core Cover proxy and regex detection work on every
// platform Go supports; this package only adds the LLM fallback on
// platforms with a prebuilt llama-server binary, and degrades gracefully
// (regex-only) everywhere else.
package llamacpp

import "runtime"

// platformAsset describes the llama.cpp release asset for one GOOS/GOARCH
// combination: the asset name is "llama-{tag}-bin-{pattern}.{ext}".
type platformAsset struct {
	pattern string
	ext     string
}

// platformAssets maps "GOOS/GOARCH" to the llama.cpp CPU-build release asset
// for that platform. Only CPU builds are used so the result is portable
// without GPU drivers; macOS builds include Metal/Accelerate support.
var platformAssets = map[string]platformAsset{
	"darwin/arm64":  {pattern: "macos-arm64", ext: ".tar.gz"},
	"darwin/amd64":  {pattern: "macos-x64", ext: ".tar.gz"},
	"linux/amd64":   {pattern: "ubuntu-x64", ext: ".tar.gz"},
	"linux/arm64":   {pattern: "ubuntu-arm64", ext: ".tar.gz"},
	"linux/s390x":   {pattern: "ubuntu-s390x", ext: ".tar.gz"},
	"windows/amd64": {pattern: "win-cpu-x64", ext: ".zip"},
	"windows/arm64": {pattern: "win-cpu-arm64", ext: ".zip"},
}

// AssetPattern returns the llama.cpp release asset name pattern and archive
// extension for the current platform (runtime.GOOS/runtime.GOARCH), and
// whether a prebuilt llama-server binary is available at all.
func AssetPattern() (pattern, ext string, ok bool) {
	return assetPatternFor(runtime.GOOS, runtime.GOARCH)
}

func assetPatternFor(goos, goarch string) (pattern, ext string, ok bool) {
	a, ok := platformAssets[goos+"/"+goarch]
	if !ok {
		return "", "", false
	}
	return a.pattern, a.ext, true
}

// ServerBinaryName returns the expected llama-server executable name for
// the given GOOS (".exe" suffix on Windows).
func ServerBinaryName(goos string) string {
	if goos == "windows" {
		return "llama-server.exe"
	}
	return "llama-server"
}
