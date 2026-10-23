package seal

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

// Creating archives needs libarchive's bsdtar, which records metadata
// (xattrs, ACLs, flags) the same way everywhere. Extracting takes any tar.

var (
	createOnce sync.Once
	createTar  string
	createErr  error
)

func bsdtar() (string, error) {
	createOnce.Do(func() {
		for _, name := range []string{"bsdtar", "tar"} {
			p, err := exec.LookPath(name)
			if err != nil {
				continue
			}
			out, _ := exec.Command(p, "--version").Output()
			if bytes.Contains(out, []byte("libarchive")) {
				createTar = p
				return
			}
		}
		createErr = errors.New("rveil needs libarchive's bsdtar to create archives " +
			"(on Debian/Ubuntu: apt install libarchive-tools)")
	})
	return createTar, createErr
}

// Source is a file or folder being archived.
type Source struct {
	Path string // resolved: a top-level symlink is replaced by its target
	Name string // the top-level name inside the tar
	Kind string // "file" or "dir"
}

// Resolve checks a path to archive. A top-level symlink is followed:
// archiving the link itself would make its target look backed up.
func Resolve(p string) (Source, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return Source{}, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return Source{}, err
	}
	fi, err := os.Stat(real)
	if err != nil {
		return Source{}, err
	}
	kind := "file"
	if fi.IsDir() {
		kind = "dir"
	}
	return Source{Path: real, Name: filepath.Base(real), Kind: kind}, nil
}

// SealPath archives src with bsdtar (default options: what's there, as it
// is) and seals the tar stream into out.
func SealPath(src Source, pass string, out io.Writer, progress io.Writer) (Result, error) {
	tarBin, err := bsdtar()
	if err != nil {
		return Result{}, err
	}
	cmd := exec.Command(tarBin, "-c", "-f", "-", "-C", filepath.Dir(src.Path), "--", src.Name)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{}, err
	}
	if err := cmd.Start(); err != nil {
		return Result{}, err
	}
	var r io.Reader = stdout
	if progress != nil {
		r = io.TeeReader(stdout, progress)
	}
	res, err := Stream(r, pass, out)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return Result{}, err
	}
	if err := cmd.Wait(); err != nil {
		return Result{}, fmt.Errorf("tar failed: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return res, nil
}

// Inspect reads an archive's plaintext tar stream to the end and returns
// its top-level name and kind, from the first real entry. macOS bsdtar
// writes an AppleDouble "._<name>" entry (metadata) before each file; those
// are skipped.
func Inspect(r io.Reader) (name, kind string, err error) {
	tr := tar.NewReader(r)
	var hdr *tar.Header
	for {
		hdr, err = tr.Next() // pax headers are merged into the entry
		if err != nil {
			return "", "", fmt.Errorf("reading the tar stream: %w", err)
		}
		if !strings.HasPrefix(path.Base(hdr.Name), "._") {
			break
		}
	}
	clean := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
	name, _, _ = strings.Cut(clean, "/")
	kind = "file"
	if hdr.Typeflag == tar.TypeDir || strings.Contains(clean, "/") {
		kind = "dir"
	}
	// The rest still has to be read, for the caller's hash.
	if _, err := io.Copy(io.Discard, r); err != nil {
		return "", "", err
	}
	return name, kind, nil
}

var (
	extractOnce sync.Once
	extractTar  []string
	extractErr  error
)

// extractor returns the tar command line for extracting: bsdtar if it's
// there, else whatever tar is installed.
func extractor() ([]string, error) {
	extractOnce.Do(func() {
		if p, err := bsdtar(); err == nil {
			extractTar = []string{p}
			return
		}
		p, err := exec.LookPath("tar")
		if err != nil {
			extractErr = errors.New("no tar found to extract with")
			return
		}
		extractTar = []string{p}
		out, _ := exec.Command(p, "--version").Output()
		if bytes.Contains(out, []byte("GNU tar")) {
			// Only quiets its notes about libarchive's pax headers.
			extractTar = append(extractTar, "--warning=no-unknown-keyword")
		}
	})
	return extractTar, extractErr
}

// softWriter forwards to w until the first error, then swallows the rest,
// so the stream can still be read to the end (and hashed) if tar stops
// reading before its trailing padding.
type softWriter struct {
	w   io.Writer
	err error
}

func (s *softWriter) Write(b []byte) (int, error) {
	if s.err == nil {
		_, s.err = s.w.Write(b)
	}
	return len(b), nil
}

// Extract unpacks the tar stream from plain into dest. It extracts into a
// fresh folder inside dest first; check runs after tar has finished and
// must approve the result (it compares hashes) before anything moves into
// place. Nothing existing is overwritten: if a top-level name is taken, the
// contents go into <name>.unsealed (or .unsealed-2, …). It returns the
// paths it created.
func Extract(plain io.Reader, dest string, check func() error) ([]string, error) {
	argv, err := extractor()
	if err != nil {
		return nil, err
	}
	stage, err := os.MkdirTemp(dest, ".rveil-")
	if err != nil {
		return nil, err
	}
	placed := false
	defer func() {
		if !placed {
			removeAll(stage)
		}
	}()
	cmd := exec.Command(argv[0], append(argv[1:], "-x", "-f", "-", "-C", stage)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	_, copyErr := io.Copy(&softWriter{w: stdin}, plain)
	stdin.Close()
	waitErr := cmd.Wait()
	if copyErr != nil {
		return nil, copyErr
	}
	if waitErr != nil {
		return nil, fmt.Errorf("tar failed: %v: %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	if err := check(); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(stage)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("the archive is empty")
	}
	clash := false
	for _, e := range entries {
		if _, err := os.Lstat(filepath.Join(dest, e.Name())); err == nil {
			clash = true
		}
	}
	var out []string
	if clash {
		// Named after the content, not an AppleDouble "._" entry that a
		// non-Mac tar leaves beside it.
		top := entries[0].Name()
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), "._") {
				top = e.Name()
				break
			}
		}
		base := filepath.Join(dest, top+".unsealed")
		keep := base
		for n := 2; exists(keep); n++ {
			keep = fmt.Sprintf("%s-%d", base, n)
		}
		// A new folder rather than the stage itself, which MkdirTemp made 0700.
		if err := os.Mkdir(keep, 0o755); err != nil {
			return nil, err
		}
		for _, e := range entries {
			if err := os.Rename(filepath.Join(stage, e.Name()), filepath.Join(keep, e.Name())); err != nil {
				return nil, err
			}
		}
		out = append(out, keep)
	} else {
		for _, e := range entries {
			to := filepath.Join(dest, e.Name())
			if err := os.Rename(filepath.Join(stage, e.Name()), to); err != nil {
				return nil, err
			}
			out = append(out, to)
		}
	}
	placed = true
	os.Remove(stage)
	return out, nil
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// removeAll deletes a staging folder, making read-only parts writable first.
func removeAll(dir string) {
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			os.Chmod(p, 0o700)
		}
		return nil
	})
	os.RemoveAll(dir)
}
