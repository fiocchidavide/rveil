package main

// End-to-end tests: the built binary, a key file and a local folder as the
// rclone remote. They need rclone and bsdtar; the stock-recovery and
// open.sh tests also use age (with age-plugin-batchpass), zstd and openssl 3
// when they are installed.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var bin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "rveil-test-")
	if err != nil {
		panic(err)
	}
	bin = filepath.Join(dir, "rveil-"+runtime.GOOS+"-"+runtime.GOARCH)
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		panic(string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type env struct {
	t    *testing.T
	root string
	vars []string
}

func newEnv(t *testing.T) *env {
	for _, tool := range []string{"rclone"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	root := t.TempDir()
	return &env{t: t, root: root, vars: []string{
		"RVEIL_KEYSTORE=file:" + filepath.Join(root, "keys.json"),
		"RVEIL_REMOTE=" + filepath.Join(root, "remote"),
		"RVEIL_STAGING=" + filepath.Join(root, "staging"),
		"NO_COLOR=1",
	}}
}

// run runs rveil in dir and returns stdout; it fails the test on error.
func (e *env) run(dir string, args ...string) string {
	e.t.Helper()
	out, stderr, err := e.try(dir, "", args...)
	if err != nil {
		e.t.Fatalf("rveil %s: %v\n%s", strings.Join(args, " "), err, stderr)
	}
	return out
}

func (e *env) try(dir, stdin string, args ...string) (string, string, error) {
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), e.vars...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return out.String(), errb.String(), err
}

func (e *env) path(p ...string) string { return filepath.Join(append([]string{e.root}, p...)...) }

func write(t *testing.T, p, content string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// sameTree compares two trees: types, permissions, contents, link targets.
func sameTree(t *testing.T, a, b string) {
	t.Helper()
	filepath.WalkDir(a, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(a, p)
		q := filepath.Join(b, rel)
		fa, _ := os.Lstat(p)
		fb, err := os.Lstat(q)
		if err != nil {
			t.Fatalf("%s missing in the copy", rel)
		}
		if fa.Mode() != fb.Mode() {
			t.Fatalf("%s: mode %v, copy %v", rel, fa.Mode(), fb.Mode())
		}
		switch {
		case fa.Mode()&fs.ModeSymlink != 0:
			la, _ := os.Readlink(p)
			lb, _ := os.Readlink(q)
			if la != lb {
				t.Fatalf("%s: link %q, copy %q", rel, la, lb)
			}
		case fa.Mode().IsRegular():
			ca, _ := os.ReadFile(p)
			cb, _ := os.ReadFile(q)
			if !bytes.Equal(ca, cb) {
				t.Fatalf("%s: contents differ", rel)
			}
		}
		return nil
	})
}

func idOf(t *testing.T, lsLong, name string) string {
	t.Helper()
	for _, line := range strings.Split(lsLong, "\n") {
		if strings.Contains(line, "  "+name) {
			return line[strings.LastIndex(line, "(")+1 : strings.LastIndex(line, ")")]
		}
	}
	t.Fatalf("%s not in:\n%s", name, lsLong)
	return ""
}

func remoteFiles(t *testing.T, e *env) []string {
	entries, _ := os.ReadDir(e.path("remote"))
	var names []string
	for _, d := range entries {
		names = append(names, d.Name())
	}
	return names
}

func TestLifecycle(t *testing.T) {
	e := newEnv(t)
	src := e.path("src", "tax docs 2019")
	write(t, filepath.Join(src, "a.txt"), "alpha")
	write(t, filepath.Join(src, "sub", "b.bin"), strings.Repeat("0123456789", 300000))
	os.Symlink("a.txt", filepath.Join(src, "link"))
	write(t, e.path("src", "note.txt"), "a note")
	if runtime.GOOS == "darwin" {
		exec.Command("xattr", "-w", "com.apple.metadata:_kMDItemUserTags", `("Red")`, filepath.Join(src, "a.txt")).Run()
	}

	if _, stderr, err := e.try(e.root, "", "put", src); err == nil || !strings.Contains(stderr, "rveil keys new") {
		t.Fatalf("put without a key: %v %s", err, stderr)
	}
	k1 := strings.TrimSpace(e.run(e.root, "keys", "new"))

	e.run(e.root, "put", src)
	e.run(e.root, "put", "--direct", e.path("src", "note.txt"))
	e.run(e.root, "push")
	if staged, _ := os.ReadDir(e.path("staging")); len(staged) != 0 {
		t.Fatalf("staging not cleared: %v", staged)
	}
	ls := e.run(e.root, "ls", "-l")
	taxID, noteID := idOf(t, ls, "tax docs 2019/"), idOf(t, ls, "note.txt")

	// get, twice: the second lands beside the first.
	out := e.path("out")
	os.Mkdir(out, 0o755)
	e.run(out, "get", "TAX")
	e.run(out, "get", taxID)
	sameTree(t, src, filepath.Join(out, "tax docs 2019"))
	sameTree(t, src, filepath.Join(out, "tax docs 2019.unsealed", "tax docs 2019"))
	if runtime.GOOS == "darwin" {
		x, _ := exec.Command("xattr", "-p", "com.apple.metadata:_kMDItemUserTags", filepath.Join(out, "tax docs 2019", "a.txt")).Output()
		if !strings.Contains(string(x), "Red") {
			t.Fatalf("Finder tag lost: %q", x)
		}
	}

	// key: by id without the index, by match with it.
	if a, b := e.run(e.root, "key", noteID), e.run(e.root, "key", "note"); a != b || len(strings.TrimSpace(a)) != 43 {
		t.Fatalf("key: %q %q", a, b)
	}

	// rekey everything to a new key; the content stays the same.
	k2 := strings.TrimSpace(e.run(e.root, "keys", "new"))
	if _, _, err := e.try(e.root, "", "rekey", "--from", k1); err == nil {
		t.Fatal("rekey without a terminal or -y went ahead")
	}
	e.run(e.root, "rekey", "-y", "--from", k1)
	ls = e.run(e.root, "ls", "-l")
	if strings.Contains(ls, k1) || strings.Count(ls, k2) != 4 {
		t.Fatalf("after rekey:\n%s", ls)
	}
	taxID = idOf(t, ls, "tax docs 2019/")
	os.RemoveAll(out)
	os.Mkdir(out, 0o755)
	e.run(out, "get", taxID)
	sameTree(t, src, filepath.Join(out, "tax docs 2019"))
	e.run(e.root, "check", "--deep")

	// An older index put back: check drops the entry whose archive is gone.
	old, _ := os.ReadFile(e.path("remote", "index.age"))
	e.run(e.root, "rm", "-y", "note")
	os.WriteFile(e.path("remote", "index.age"), old, 0o644)
	if _, _, err := e.try(e.root, "", "check"); err == nil {
		t.Fatal("check without a terminal or -y fixed things")
	}
	e.run(e.root, "check", "-y")
	if ls := e.run(e.root, "ls"); strings.Contains(ls, "note.txt") {
		t.Fatalf("note.txt survived:\n%s", ls)
	}

	// No index at all: check rebuilds it from the archives, plus a partial.
	before := e.run(e.root, "ls", "-l")
	os.Remove(e.path("remote", "index.age"))
	write(t, e.path("remote", k2+".abcdefghijklmnopqrstuvwxyz.age.partial"), "junk")
	e.run(e.root, "check", "-y")
	if after := e.run(e.root, "ls", "-l"); after != before {
		t.Fatalf("rebuilt index differs:\n%s\nvs\n%s", after, before)
	}
	for _, f := range remoteFiles(t, e) {
		if strings.HasSuffix(f, ".partial") {
			t.Fatalf("partial left: %s", f)
		}
	}
	e.run(e.root, "check")
}

func TestSealOpen(t *testing.T) {
	e := newEnv(t)
	e.run(e.root, "keys", "new")
	src := e.path("pkg")
	write(t, filepath.Join(src, "f"), "hello")
	f := strings.TrimSpace(e.run(e.root, "seal", "-o", e.root, src))
	id := strings.TrimSuffix(filepath.Base(f), ".age")

	// A browser-renamed copy still finds its key.
	renamed := e.path(id + " (1).age")
	data, _ := os.ReadFile(f)
	os.WriteFile(renamed, data, 0o644)
	dest := e.path("dest")
	os.Mkdir(dest, 0o755)
	e.run(e.root, "open", "-C", dest, renamed)
	sameTree(t, src, filepath.Join(dest, "pkg"))

	pass := strings.TrimSpace(e.run(e.root, "key", id))
	if _, _, err := e.try(e.root, "wrong\n", "open", "-k", "-", "-C", dest, f); err == nil {
		t.Fatal("wrong passphrase opened")
	}
	if _, stderr, err := e.try(e.root, pass+"\n", "open", "-k", "-", "-C", dest, f); err != nil {
		t.Fatalf("open -k -: %v %s", err, stderr)
	}
	sameTree(t, src, filepath.Join(dest, "pkg.unsealed", "pkg"))
}

// A friend without bsdtar: open extracts with GNU tar (on Linux CI, or with
// gtar installed), the only program on its PATH.
func TestOpenWithGNUTar(t *testing.T) {
	gnu := ""
	for _, c := range []string{"tar", "gtar"} {
		if p, err := exec.LookPath(c); err == nil {
			if out, _ := exec.Command(p, "--version").Output(); bytes.Contains(out, []byte("GNU tar")) {
				gnu = p
				break
			}
		}
	}
	if gnu == "" {
		t.Skip("no GNU tar")
	}
	e := newEnv(t)
	e.run(e.root, "keys", "new")
	src := e.path("pkg")
	write(t, filepath.Join(src, "f"), "hello")
	f := strings.TrimSpace(e.run(e.root, "seal", "-o", e.root, src))
	pass := strings.TrimSpace(e.run(e.root, "key", strings.TrimSuffix(filepath.Base(f), ".age")))

	pathDir := e.path("path")
	os.Mkdir(pathDir, 0o755)
	os.Symlink(gnu, filepath.Join(pathDir, "tar"))
	dest := e.path("dest")
	os.Mkdir(dest, 0o755)
	cmd := exec.Command(bin, "open", "-k", "-", "-C", dest, f)
	cmd.Env = append(os.Environ(), "PATH="+pathDir)
	cmd.Stdin = strings.NewReader(pass + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("open with GNU tar: %v\n%s", err, out)
	} else if strings.Contains(string(out), "unknown extended header") {
		t.Fatalf("GNU tar's warnings weren't silenced:\n%s", out)
	}
	sameTree(t, src, filepath.Join(dest, "pkg"))
}

// Stock recovery: only age, zstd and tar, with the passphrase from rveil key
// and from the openssl recipe in docs/FORMAT.md.
func TestStockRecovery(t *testing.T) {
	for _, tool := range []string{"age", "age-plugin-batchpass", "zstd"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	e := newEnv(t)
	e.run(e.root, "keys", "new")
	src := e.path("pkg")
	write(t, filepath.Join(src, "f"), strings.Repeat("stock tools ", 10000))
	f := strings.TrimSpace(e.run(e.root, "seal", "-o", e.root, src))
	id := strings.TrimSuffix(filepath.Base(f), ".age")
	pass := strings.TrimSpace(e.run(e.root, "key", id))

	dest := e.path("dest")
	os.Mkdir(dest, 0o755)
	// zstd -d without --long: the window fits the reference decoder's default.
	sh := `age -d -j batchpass "$1" | zstd -d | tar -x -f - -C "$2"`
	cmd := exec.Command("sh", "-c", sh, "sh", f, dest)
	cmd.Env = append(os.Environ(), "AGE_PASSPHRASE="+pass)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("stock tools: %v\n%s", err, out)
	}
	sameTree(t, src, filepath.Join(dest, "pkg"))

	openssl := ""
	for _, c := range []string{"openssl", "/opt/homebrew/opt/openssl@3/bin/openssl", "/usr/local/opt/openssl@3/bin/openssl"} {
		if out, err := exec.Command(c, "version").Output(); err == nil && strings.HasPrefix(string(out), "OpenSSL 3") {
			openssl = c
			break
		}
	}
	if openssl == "" {
		t.Log("no OpenSSL 3; skipping the openssl recipe")
		return
	}
	var keys struct{ Keys []struct{ Key string } }
	b, _ := os.ReadFile(e.path("keys.json"))
	json.Unmarshal(b, &keys)
	master, _ := base64.RawURLEncoding.DecodeString(keys.Keys[0].Key)
	kdf := exec.Command(openssl, "kdf", "-keylen", "32", "-kdfopt", "digest:SHA256",
		"-kdfopt", fmt.Sprintf("hexkey:%x", master), "-kdfopt", "salt:rveil/v1",
		"-kdfopt", fmt.Sprintf("hexinfo:%x", id), "-binary", "HKDF")
	okm, err := kdf.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.RawURLEncoding.EncodeToString(okm); got != pass {
		t.Fatalf("openssl recipe gives %q, rveil key %q", got, pass)
	}
}

// What a friend runs: the rendered open.sh, fetching this binary from a
// local "release" folder. The tree holds awkward cases: a read-only folder,
// a dangling symlink and a ..-name; the download folder already holds a
// dangling symlink with the archive's name.
func TestOpenShare(t *testing.T) {
	e := newEnv(t)
	e.run(e.root, "keys", "new")
	src := e.path("src", "pkg")
	write(t, filepath.Join(src, "ro", "f"), "hello")
	write(t, filepath.Join(src, "..odd"), "odd")
	os.Symlink("/nonexistent", filepath.Join(src, "dangling"))
	os.Chmod(filepath.Join(src, "ro"), 0o555)
	defer os.Chmod(filepath.Join(src, "ro"), 0o755)

	dl := e.path("Downloads")
	os.Mkdir(dl, 0o755)
	os.Symlink("/nowhere", filepath.Join(dl, "pkg"))
	f := strings.TrimSpace(e.run(e.root, "seal", "-o", dl, src))
	id := strings.TrimSuffix(filepath.Base(f), ".age")
	pass := strings.TrimSpace(e.run(e.root, "key", id))
	// Downloaded twice: the browser renamed the copy.
	os.Rename(f, filepath.Join(dl, id+" (1).age"))

	script := e.path("open.sh")
	rendered, err := exec.Command("bash", "../../scripts/render-open.sh", "v0.0.0-test", filepath.Dir(bin)).Output()
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(script, rendered, 0o644)
	home := e.path("home")
	os.Mkdir(home, 0o755)
	os.Symlink(dl, filepath.Join(home, "Downloads"))

	defer os.Chmod(filepath.Join(dl, "pkg.unsealed", "pkg", "ro"), 0o755) // for the temp dir's cleanup

	// From the home folder, as a friend would: the file is found in ~/Downloads.
	cmd := exec.Command("bash", script, pass, id+".age")
	cmd.Dir = home
	cmd.Env = append(os.Environ(), "HOME="+home, "RVEIL_OPEN_BASE_URL=file://"+filepath.Dir(bin))
	cmd.Stdin = strings.NewReader("")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("open.sh: %v\n%s", err, out)
	}
	sameTree(t, src, filepath.Join(dl, "pkg.unsealed", "pkg"))
}
