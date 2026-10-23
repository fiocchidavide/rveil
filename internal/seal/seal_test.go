package seal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const pass = "test-passphrase"

func TestStreamRoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte("some content "), 100000)
	var out bytes.Buffer
	res, err := Stream(bytes.NewReader(data), pass, &out)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if res.SHA256 != hex.EncodeToString(sum[:]) || res.Size != int64(len(data)) || res.AgeSize != int64(out.Len()) {
		t.Fatalf("bad result %+v", res)
	}
	r, err := NewReader(bytes.NewReader(out.Bytes()), pass)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("round trip: %v", err)
	}
	if sha, n := r.Sum(); sha != res.SHA256 || n != res.Size {
		t.Fatal("Sum mismatch")
	}
	if _, err := NewReader(bytes.NewReader(out.Bytes()), "wrong"); !IsWrongKey(err) {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestVerifierRejectsCorruption(t *testing.T) {
	var out bytes.Buffer
	if _, err := Stream(strings.NewReader("hello"), pass, &out); err != nil {
		t.Fatal(err)
	}
	bad := out.Bytes()
	bad[len(bad)-5] ^= 1
	v := newVerifier(pass, true)
	v.Write(bad)
	if _, _, err := v.finish(); err == nil {
		t.Fatal("corrupted ciphertext verified")
	}
}

func TestRewrap(t *testing.T) {
	data := []byte(strings.Repeat("rekey me ", 5000))
	var a bytes.Buffer
	res, err := Stream(bytes.NewReader(data), pass, &a)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	res2, err := Rewrap(bytes.NewReader(a.Bytes()), pass, "new-pass", res.SHA256, &b)
	if err != nil {
		t.Fatal(err)
	}
	if res2.SHA256 != res.SHA256 || res2.AgeSHA256 == res.AgeSHA256 {
		t.Fatalf("results %+v %+v", res, res2)
	}
	r, err := NewReader(&b, "new-pass")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r)
	if !bytes.Equal(got, data) {
		t.Fatal("rewrapped content differs")
	}
	if _, err := Rewrap(bytes.NewReader(a.Bytes()), pass, "x", "deadbeef", io.Discard); !errors.Is(err, ErrVerify) {
		t.Fatalf("wrong expected hash: %v", err)
	}
}

func TestSealPathExtract(t *testing.T) {
	if _, err := bsdtar(); err != nil {
		t.Skip(err)
	}
	src := t.TempDir()
	dir := filepath.Join(src, "my folder")
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	os.WriteFile(filepath.Join(dir, "sub", "a.txt"), []byte("alpha"), 0o644)
	os.Symlink("sub/a.txt", filepath.Join(dir, "link"))
	// A top-level symlink is followed.
	os.Symlink(dir, filepath.Join(src, "shortcut"))
	s, err := Resolve(filepath.Join(src, "shortcut"))
	if err != nil || s.Name != "my folder" || s.Kind != "dir" {
		t.Fatalf("Resolve: %+v %v", s, err)
	}
	var out bytes.Buffer
	res, err := SealPath(s, pass, &out, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Inspect sees the name and kind.
	r, _ := NewReader(bytes.NewReader(out.Bytes()), pass)
	name, kind, err := Inspect(r)
	if err != nil || name != "my folder" || kind != "dir" {
		t.Fatalf("Inspect: %q %q %v", name, kind, err)
	}

	dest := t.TempDir()
	for i, want := range []string{"my folder", "my folder.unsealed", "my folder.unsealed-2"} {
		r, _ := NewReader(bytes.NewReader(out.Bytes()), pass)
		placed, err := Extract(r, dest, func() error {
			if sha, _ := r.Sum(); sha != res.SHA256 {
				return errors.New("hash mismatch")
			}
			return nil
		})
		r.Close()
		if err != nil || len(placed) != 1 || filepath.Base(placed[0]) != want {
			t.Fatalf("extract %d: %v %v", i, placed, err)
		}
	}
	got, _ := os.ReadFile(filepath.Join(dest, "my folder", "sub", "a.txt"))
	link, _ := os.Readlink(filepath.Join(dest, "my folder", "link"))
	if string(got) != "alpha" || link != "sub/a.txt" {
		t.Fatalf("content %q, link %q", got, link)
	}

	// A failed check leaves nothing behind.
	r, _ = NewReader(bytes.NewReader(out.Bytes()), pass)
	if _, err := Extract(r, dest, func() error { return errors.New("no") }); err == nil {
		t.Fatal("failed check extracted")
	}
	entries, _ := os.ReadDir(dest)
	if len(entries) != 3 {
		t.Fatalf("leftovers: %v", entries)
	}
}
