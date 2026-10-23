// Package remote stores archives in a folder on an rclone remote: any
// rclone path, including a local folder. Upload verification needs the
// remote to report SHA-256 (Google Drive and local folders do).
package remote

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Entry is a file in the remote folder.
type Entry struct {
	Name    string
	Size    int64
	ModTime time.Time
	SHA256  string // only when listed with hashes
}

// Remote is a folder that holds archives. Names are relative to it.
type Remote interface {
	List(withHashes bool) ([]Entry, error)
	Open(name string) (io.ReadCloser, error)
	Create(name string) (io.WriteCloser, error)
	Upload(local, name string, progress func(done, total int64)) error
	SHA256(name string) (string, error)
	Move(from, to string) error
	Remove(name string) error
	Link(name string) (string, error)
	CheckSHA256() error
	String() string
}

// ErrNoSHA256 means the remote doesn't report SHA-256 hashes, which rveil
// needs to verify uploads.
var ErrNoSHA256 = errors.New("this remote doesn't report SHA-256 hashes, which rveil needs " +
	"to verify uploads; use one that does (e.g. Google Drive or a local folder)")

// Rclone is a folder on an rclone remote, e.g. "rveil:rveil" or "/Volumes/Ext/rveil".
type Rclone struct{ Base string }

func (r Rclone) String() string { return r.Base }

func (r Rclone) path(name string) string {
	if name == "" {
		return r.Base
	}
	if strings.HasSuffix(r.Base, ":") || strings.HasSuffix(r.Base, "/") {
		return r.Base + name
	}
	return r.Base + "/" + name
}

func (r Rclone) cmd(args ...string) *exec.Cmd {
	c := exec.Command("rclone", args...)
	c.Env = os.Environ()
	if os.Getenv("RCLONE_DRIVE_CHUNK_SIZE") == "" {
		c.Env = append(c.Env, "RCLONE_DRIVE_CHUNK_SIZE=64M")
	}
	return c
}

// rcloneError turns a failed run into a short message: rclone's last
// complaint, without its timestamps.
func rcloneError(op string, err error, stderr []byte) error {
	if errors.Is(err, exec.ErrNotFound) {
		return errors.New("rclone isn't installed")
	}
	lines := strings.Split(strings.TrimSpace(string(stderr)), "\n")
	msg := lines[len(lines)-1]
	for _, tag := range []string{"ERROR : ", "NOTICE: ", "CRITICAL: "} {
		if i := strings.Index(msg, tag); i >= 0 {
			msg = msg[i+len(tag):]
		}
	}
	if msg == "" {
		msg = err.Error()
	}
	return fmt.Errorf("rclone %s: %s", op, msg)
}

func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func (r Rclone) run(op string, args ...string) ([]byte, error) {
	c := r.cmd(args...)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return out, &runError{rcloneError(op, err, stderr.Bytes()), exitCode(err)}
	}
	return out, nil
}

type runError struct {
	err  error
	code int
}

func (e *runError) Error() string { return e.err.Error() }

// rclone's exit codes for a missing directory and a missing file.
func notFound(err error) bool {
	var re *runError
	return errors.As(err, &re) && (re.code == 3 || re.code == 4)
}

// List returns the files in the folder; a folder that doesn't exist yet is
// empty. With hashes, a local remote reads every file, while Drive just
// reports them.
func (r Rclone) List(withHashes bool) ([]Entry, error) {
	args := []string{"lsjson", "--files-only"}
	if withHashes {
		args = append(args, "--hash", "--hash-type", "sha256")
	}
	out, err := r.run("lsjson", append(args, r.Base)...)
	if notFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var items []struct {
		Name    string
		Size    int64
		ModTime time.Time
		Hashes  map[string]string
	}
	if err := json.Unmarshal(out, &items); err != nil {
		return nil, fmt.Errorf("reading rclone's listing: %w", err)
	}
	es := make([]Entry, len(items))
	for i, it := range items {
		es[i] = Entry{Name: it.Name, Size: it.Size, ModTime: it.ModTime, SHA256: it.Hashes["sha256"]}
	}
	return es, nil
}

// catReader streams a file out of rclone cat.
type catReader struct {
	c      *exec.Cmd
	r      io.Reader
	stderr bytes.Buffer
	eof    bool
}

func (c *catReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	if err == io.EOF {
		c.eof = true
	}
	return n, err
}

// Close reports whether rclone finished cleanly. Closing before the end
// stops rclone, which would otherwise block on the unread rest.
func (c *catReader) Close() error {
	if !c.eof {
		c.c.Process.Kill()
		c.c.Wait()
		return nil
	}
	if err := c.c.Wait(); err != nil {
		return rcloneError("cat", err, c.stderr.Bytes())
	}
	return nil
}

// Open streams a file.
func (r Rclone) Open(name string) (io.ReadCloser, error) {
	c := &catReader{c: r.cmd("cat", r.path(name))}
	c.c.Stderr = &c.stderr
	out, err := c.c.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := c.c.Start(); err != nil {
		return nil, rcloneError("cat", err, nil)
	}
	c.r = out
	return c, nil
}

// rcatWriter streams into rclone rcat.
type rcatWriter struct {
	c      *exec.Cmd
	w      io.WriteCloser
	stderr bytes.Buffer
}

func (w *rcatWriter) Write(b []byte) (int, error) { return w.w.Write(b) }

// Close ends the stream and waits for the upload to finish.
func (w *rcatWriter) Close() error {
	w.w.Close()
	if err := w.c.Wait(); err != nil {
		return rcloneError("rcat", err, w.stderr.Bytes())
	}
	return nil
}

// Create streams into a new file (rclone rcat).
func (r Rclone) Create(name string) (io.WriteCloser, error) {
	w := &rcatWriter{c: r.cmd("rcat", r.path(name))}
	w.c.Stderr = &w.stderr
	in, err := w.c.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := w.c.Start(); err != nil {
		return nil, rcloneError("rcat", err, nil)
	}
	w.w = in
	return w, nil
}

// Upload copies a local file (rclone copyto), which knows the size up front
// and resumes chunks; progress comes from rclone's JSON stats.
func (r Rclone) Upload(local, name string, progress func(done, total int64)) error {
	c := r.cmd("copyto", "--checksum", "--use-json-log", "--stats", "500ms",
		"--stats-log-level", "NOTICE", "--", local, r.path(name))
	stderr, err := c.StderrPipe()
	if err != nil {
		return err
	}
	if err := c.Start(); err != nil {
		return rcloneError("copyto", err, nil)
	}
	var last []byte
	sc := bufio.NewScanner(stderr)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var line struct {
			Msg   string `json:"msg"`
			Level string `json:"level"`
			Stats *struct {
				Bytes      int64 `json:"bytes"`
				TotalBytes int64 `json:"totalBytes"`
			} `json:"stats"`
		}
		if json.Unmarshal(sc.Bytes(), &line) != nil {
			continue
		}
		if line.Stats != nil {
			if progress != nil {
				progress(line.Stats.Bytes, line.Stats.TotalBytes)
			}
		} else if line.Level == "error" || line.Level == "critical" {
			last = []byte(line.Msg)
		}
	}
	if err := c.Wait(); err != nil {
		return rcloneError("copyto", err, last)
	}
	return nil
}

// SHA256 returns the hash the remote stores for a file.
func (r Rclone) SHA256(name string) (string, error) {
	out, err := r.run("hashsum", "hashsum", "sha256", r.path(name))
	if err != nil {
		return "", err
	}
	h, _, _ := strings.Cut(strings.TrimSpace(string(out)), " ")
	if len(h) != 64 {
		return "", ErrNoSHA256
	}
	return h, nil
}

// Move replaces to with from. --ignore-times stops rclone from skipping
// the move when both happen to have the same size and time, which padding
// makes likely; unlike --no-check-dest, it still replaces the destination
// instead of adding a second file with its name (Drive allows that).
func (r Rclone) Move(from, to string) error {
	_, err := r.run("moveto", "moveto", "--ignore-times", r.path(from), r.path(to))
	return err
}

// CheckSHA256 fails fast if the remote doesn't report SHA-256 hashes,
// before anything is uploaded.
func (r Rclone) CheckSHA256() error {
	out, err := r.run("backend features", "backend", "features", r.Base)
	if err != nil {
		return err
	}
	var f struct{ Hashes []string }
	if err := json.Unmarshal(out, &f); err != nil {
		return fmt.Errorf("reading rclone's feature list: %w", err)
	}
	for _, h := range f.Hashes {
		if h == "sha256" {
			return nil
		}
	}
	return ErrNoSHA256
}

func (r Rclone) Remove(name string) error {
	_, err := r.run("deletefile", "deletefile", "--retries", "1", r.path(name))
	return err
}

// Link returns a public anyone-with-the-link URL.
func (r Rclone) Link(name string) (string, error) {
	out, err := r.run("link", "link", r.path(name))
	return strings.TrimSpace(string(out)), err
}
