package remote

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRcloneLocal(t *testing.T) {
	if _, err := exec.LookPath("rclone"); err != nil {
		t.Skip("rclone not installed")
	}
	r := Rclone{Base: filepath.Join(t.TempDir(), "remote")}
	if es, err := r.List(false); err != nil || len(es) != 0 {
		t.Fatalf("missing folder: %v %v", es, err)
	}
	if err := r.CheckSHA256(); err != nil {
		t.Fatalf("local remote: %v", err)
	}
	if err := (Rclone{Base: ":memory:x"}).CheckSHA256(); err != ErrNoSHA256 {
		t.Fatalf("memory remote (md5 only): %v", err)
	}

	w, err := r.Create("a.age.partial")
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, "hello")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("hello"))
	if h, err := r.SHA256("a.age.partial"); err != nil || h != hex.EncodeToString(sum[:]) {
		t.Fatalf("SHA256: %q %v", h, err)
	}
	if err := r.Move("a.age.partial", "a.age"); err != nil {
		t.Fatal(err)
	}

	// A move over a file of the same size and time still replaces it.
	dir := r.Base
	os.WriteFile(filepath.Join(dir, "same.age"), []byte("AAAA"), 0o644)
	os.WriteFile(filepath.Join(dir, "same.age.partial"), []byte("BBBB"), 0o644)
	now := time.Now()
	os.Chtimes(filepath.Join(dir, "same.age"), now, now)
	os.Chtimes(filepath.Join(dir, "same.age.partial"), now, now)
	if err := r.Move("same.age.partial", "same.age"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "same.age")); string(b) != "BBBB" {
		t.Fatalf("move skipped: %q", b)
	}
	os.Remove(filepath.Join(dir, "same.age"))

	local := filepath.Join(t.TempDir(), "b")
	os.WriteFile(local, []byte(strings.Repeat("x", 100000)), 0o644)
	var last int64
	if err := r.Upload(local, "b.age", func(done, total int64) { last = done }); err != nil {
		t.Fatal(err)
	}
	_ = last

	es, err := r.List(true)
	if err != nil || len(es) != 2 || es[0].Name != "a.age" || es[0].SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("List: %+v %v", es, err)
	}

	rc, err := r.Open("a.age")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	if err := rc.Close(); err != nil || string(b) != "hello" {
		t.Fatalf("Open: %q %v", b, err)
	}
	// Closing early doesn't hang.
	rc, _ = r.Open("b.age")
	rc.Read(make([]byte, 10))
	rc.Close()

	if err := r.Remove("a.age"); err != nil {
		t.Fatal(err)
	}
	if err := r.Remove("a.age"); err == nil {
		t.Fatal("removing a missing file succeeded")
	}
	if _, err := r.Link("b.age"); err == nil {
		t.Fatal("a local folder made a public link")
	}
}
