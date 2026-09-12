package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func archiveFixture(t *testing.T, name string, kind byte) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: 3, Typeflag: kind}); err != nil {
		t.Fatal(err)
	}
	if kind == tar.TypeReg {
		tw.Write([]byte("new"))
	}
	tw.Close()
	gz.Close()
	return b.Bytes()
}

func TestFetchVerifiesBeforeExtraction(t *testing.T) {
	for _, mode := range []string{"valid", "mismatch", "missing", "duplicate", "traversal"} {
		t.Run(mode, func(t *testing.T) {
			name := "cover"
			if mode == "traversal" {
				name = "../cover"
			}
			data := archiveFixture(t, name, tar.TypeReg)
			sum := sha256.Sum256(data)
			checks := fmt.Sprintf("%x  cover_1.2.3_linux_amd64.tar.gz\n", sum)
			switch mode {
			case "mismatch":
				checks = strings.Repeat("0", 64) + " cover_1.2.3_linux_amd64.tar.gz"
			case "missing":
				checks = ""
			case "duplicate":
				checks += checks
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "checksums.txt") {
					fmt.Fprint(w, checks)
				} else {
					w.Write(data)
				}
			}))
			defer server.Close()
			got, err := Fetch(context.Background(), server.Client(), server.URL, "v1.2.3", "linux", "amd64")
			if mode == "valid" {
				if err != nil || string(got) != "new" {
					t.Fatalf("%q %v", got, err)
				}
			} else if err == nil {
				t.Fatal("invalid release accepted")
			}
		})
	}
}

func TestInstallTransactionAndRollback(t *testing.T) {
	for _, mode := range []string{"success", "validation", "stop", "health"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cover")
			os.WriteFile(path, []byte("old"), 0755)
			starts := 0
			err := Install(path, []byte("new"), Hooks{
				Validate: func(staged string) error {
					data, _ := os.ReadFile(staged)
					if string(data) != "new" {
						t.Fatal("bad stage")
					}
					if mode == "validation" {
						return fmt.Errorf("invalid")
					}
					return nil
				},
				Stop: func() error {
					if mode == "stop" {
						return fmt.Errorf("busy")
					}
					return nil
				},
				StartAndCheck: func() error {
					starts++
					if mode == "health" && starts == 1 {
						return fmt.Errorf("unhealthy")
					}
					return nil
				},
			})
			got, _ := os.ReadFile(path)
			want := "old"
			if mode == "success" {
				want = "new"
			}
			if string(got) != want {
				t.Fatalf("got %s", got)
			}
			if (err == nil) != (mode == "success") {
				t.Fatalf("error=%v", err)
			}
			if mode == "health" && starts != 2 {
				t.Fatal("old binary not restarted")
			}
			if mode == "success" || mode == "health" {
				backup, _ := os.ReadFile(path + ".previous")
				if string(backup) != "old" {
					t.Fatal("missing rollback copy")
				}
			}
			if _, err := os.Stat(path + ".update.lock"); !os.IsNotExist(err) {
				t.Fatal("lock retained")
			}
		})
	}
}

func TestInstallLockPreventsConcurrentUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cover")
	os.WriteFile(path, []byte("old"), 0755)
	os.WriteFile(path+".update.lock", nil, 0600)
	if err := Install(path, []byte("new"), Hooks{}); err == nil {
		t.Fatal("lock ignored")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "old" {
		t.Fatal("binary changed")
	}
}
