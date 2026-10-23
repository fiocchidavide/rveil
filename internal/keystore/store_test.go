package keystore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fiocchidavide/rveil/internal/format"
)

func TestFileStore(t *testing.T) {
	s := File{Path: filepath.Join(t.TempDir(), "sub", "keys.json")}
	ks, err := LoadKeys(s)
	if err != nil || len(ks) != 0 {
		t.Fatalf("empty store: %v %v", ks, err)
	}
	if _, err := ks.Current(); err != ErrNoKeys {
		t.Fatalf("Current on empty: %v", err)
	}
	k1, err := New(s, ks)
	if err != nil {
		t.Fatal(err)
	}
	ks, _ = LoadKeys(s)
	k2, err := New(s, ks) // waits out k1's second
	if err != nil {
		t.Fatal(err)
	}
	if k2.Created.Unix() == k1.Created.Unix() {
		t.Fatal("two keys in the same second")
	}
	ks, err = LoadKeys(s)
	if err != nil || len(ks) != 2 {
		t.Fatalf("load: %v %v", ks, err)
	}
	if cur, _ := ks.Current(); cur.ID != k2.ID {
		t.Fatalf("current is %s, want %s", cur.ID, k2.ID)
	}
	id := format.NewArchiveID(k1.ID)
	want, _ := format.Passphrase(k1.Master, id)
	if got, err := ks.Passphrase(id); err != nil || got != want {
		t.Fatalf("Passphrase: %v", err)
	}
	if fi, _ := os.Stat(s.Path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

func TestOpen(t *testing.T) {
	for spec, ok := range map[string]bool{"op:rveil": true, "file:/tmp/k": true, "op:": false, "nope": false, "s3:x": false} {
		if _, err := Open(spec); (err == nil) != ok {
			t.Errorf("Open(%q): %v", spec, err)
		}
	}
}
