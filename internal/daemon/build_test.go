package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildStatusDetectsMismatchAndStaleRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cover.pid")
	if err := RecordBuild(path, 123, "test", "abc"); err != nil {
		t.Fatal(err)
	}
	if got := CompareBuild(path, 123); !strings.Contains(got, "matches") {
		t.Fatal(got)
	}
	if got := CompareBuild(path, 456); !strings.Contains(got, "unknown") {
		t.Fatal(got)
	}
	data, _ := json.Marshal(buildRecord{PID: 123, Digest: "different"})
	os.WriteFile(path+".build.json", data, 0600)
	if got := CompareBuild(path, 123); !strings.Contains(got, "differs") {
		t.Fatal(got)
	}
}
