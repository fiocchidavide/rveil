package vault

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"davidefiocchi.com/rveil/internal/format"
	"davidefiocchi.com/rveil/internal/keystore"
	"davidefiocchi.com/rveil/internal/seal"
	"davidefiocchi.com/rveil/internal/ui"
	"davidefiocchi.com/rveil/internal/version"
)

func newRecord(id string, key string, src seal.Source, res seal.Result) format.Record {
	return format.Record{ID: id, Key: key, Name: src.Name, Kind: src.Kind,
		Created: time.Now().UTC().Truncate(time.Second), Size: res.Size,
		SHA256: res.SHA256, AgeSHA256: res.AgeSHA256}
}

// contentSize adds up the sizes under p, for progress and the staging
// space check.
func contentSize(p string) int64 {
	var n int64
	filepath.WalkDir(p, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

func freeSpace(dir string) (int64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

// --- put / push ----------------------------------------------------------------

// Put seals each path into staging, or with direct straight to the remote.
func (v *Vault) Put(paths []string, direct bool) error {
	cur, err := v.current()
	if err != nil {
		return err
	}
	if direct {
		if err := v.needSHA256(); err != nil {
			return err
		}
		if err := v.load(); err != nil {
			return err
		}
	} else if err := os.MkdirAll(v.Staging, 0o700); err != nil {
		return err
	}
	failed := 0
	for i, p := range paths {
		src, err := seal.Resolve(p)
		if err != nil {
			ui.Error(err.Error(), "event", "failed", "path", p, "error", err.Error())
			failed++
			continue
		}
		size := contentSize(src.Path)
		ui.Info(fmt.Sprintf("%s: sealing %s (%d/%d)", src.Name, ui.Bytes(size), i+1, len(paths)),
			"event", "archive", "archive", src.Name, "kind", src.Kind, "path", src.Path, "files_bytes", size,
			"n", i+1, "of", len(paths))
		if src.Path != mustAbs(p) {
			ui.Info(fmt.Sprintf("%s is a symlink; sealing what it points to: %s", p, src.Path),
				"event", "symlink", "path", p, "target", src.Path)
		}
		id := format.NewArchiveID(cur.ID)
		pass, err := format.Passphrase(cur.Master, id)
		if err != nil {
			return err
		}
		if direct {
			err = v.putDirect(src, id, cur.ID, pass, size)
		} else {
			err = v.putStaged(src, id, cur.ID, pass, size)
		}
		if err != nil {
			ui.Error(fmt.Sprintf("%s: %v", src.Name, err), "event", "failed", "archive", src.Name, "error", err.Error())
			failed++
		}
	}
	if !direct {
		if n := len(v.staged()); n > 0 {
			ui.Info(fmt.Sprintf("%d archive(s) staged; upload with: rveil push", n), "event", "staged_total", "count", n)
		}
	}
	if failed > 0 {
		return errQuiet
	}
	return nil
}

// sealed logs a new archive with its size after each stage of sealing.
func sealed(msg string, files int64, rec format.Record, res seal.Result) {
	ui.Info(fmt.Sprintf("%s: %s files → %s tar → %s zstd → %s padded → %s age", rec.Name, ui.Bytes(files),
		ui.Bytes(res.Size), ui.Bytes(res.Compressed), ui.Bytes(res.Padded), ui.Bytes(res.AgeSize)),
		append([]any{"event", "sizes", "files_bytes", files, "tar_bytes", res.Size, "zstd_bytes", res.Compressed,
			"padded_bytes", res.Padded, "age_bytes", res.AgeSize}, fields(rec)...)...)
	ui.Info(rec.Name+": "+msg, append([]any{"event", "sealed", "sha256", rec.SHA256, "age_sha256", rec.AgeSHA256},
		fields(rec)...)...)
}

func mustAbs(p string) string {
	a, _ := filepath.Abs(p)
	return a
}

func (v *Vault) putDirect(src seal.Source, id, key, pass string, size int64) error {
	s := ui.Begin("seal", fmt.Sprintf("%s: sealing and uploading as %s.age", src.Name, id),
		"archive", src.Name, "id", id, "key", key, "files_bytes", size)
	prog := ui.NewProgress("seal", src.Name+": sealed", size, "archive", src.Name, "id", id)
	res, err := v.upload(id+".age", func(w io.Writer) (seal.Result, error) {
		return seal.SealPath(src, pass, w, prog)
	})
	prog.End()
	s.End(err)
	if err != nil {
		return err
	}
	rec := newRecord(id, key, src, res)
	v.index = append(v.index, rec)
	if err := v.save(); err != nil {
		return fmt.Errorf("%w; %s.age is on the remote but not in the index (rveil check re-adds it)", err, id)
	}
	sealed("on the remote as "+id+".age, verified", size, rec, res)
	v.emit(rec)
	return nil
}

func (v *Vault) putStaged(src seal.Source, id, key, pass string, size int64) error {
	free, err := freeSpace(v.Staging)
	if err == nil && free < size+size/8+(64<<20) {
		return fmt.Errorf("staging (%s) has %s free, too little for %s; upload it with rveil put --direct",
			v.Staging, ui.Bytes(free), ui.Bytes(size))
	}
	out := filepath.Join(v.Staging, id+".age")
	f, err := os.OpenFile(out+partial, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	s := ui.Begin("seal", fmt.Sprintf("%s: sealing into %s", src.Name, out+partial),
		"archive", src.Name, "id", id, "key", key, "files_bytes", size, "file", out+partial)
	prog := ui.NewProgress("seal", src.Name+": sealed", size, "archive", src.Name, "id", id)
	res, err := seal.SealPath(src, pass, f, prog)
	prog.End()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(out+partial, out)
	}
	s.End(err)
	if err != nil {
		os.Remove(out + partial)
		return err
	}
	rec := newRecord(id, key, src, res)
	b, _ := json.Marshal(rec)
	if err := os.WriteFile(filepath.Join(v.Staging, id+".json"), append(b, '\n'), 0o600); err != nil {
		os.Remove(out)
		return err
	}
	sealed("staged as "+id+".age, verified", size, rec, res)
	v.emit(rec)
	return nil
}

// staged returns the staged records, oldest first.
func (v *Vault) staged() []format.Record {
	files, _ := filepath.Glob(filepath.Join(v.Staging, "*.json"))
	var recs []format.Record
	for _, f := range files {
		var r format.Record
		if b, err := os.ReadFile(f); err == nil && json.Unmarshal(b, &r) == nil && format.IsArchiveID(r.ID) {
			recs = append(recs, r)
		}
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Created.Before(recs[j].Created) })
	return recs
}

// Push uploads staged archives (all, or those matching an argument) and
// removes each staged copy once its upload is verified and indexed.
func (v *Vault) Push(args []string) error {
	var todo []format.Record
	for _, r := range v.staged() {
		if len(args) == 0 || slices.ContainsFunc(args, func(a string) bool { return matches(r, a) }) {
			todo = append(todo, r)
		}
	}
	ui.Debug(fmt.Sprintf("%d archive(s) to push", len(todo)), "event", "push_plan", "count", len(todo))
	if len(todo) == 0 {
		ui.Info("Nothing staged to push", "event", "nothing_to_do")
		return nil
	}
	if err := v.needSHA256(); err != nil {
		return err
	}
	if err := v.load(); err != nil {
		return err
	}
	failed := 0
	for i, r := range todo {
		local := filepath.Join(v.Staging, r.ID+".age")
		fi, err := os.Stat(local)
		if err != nil {
			ui.Error(fmt.Sprintf("%s: its staged archive is missing; skipping", r.Name),
				append([]any{"event", "failed", "error", "staged archive missing"}, fields(r)...)...)
			failed++
			continue
		}
		ui.Info(fmt.Sprintf("%s: pushing %s (%d/%d)", r.Name, ui.Bytes(fi.Size()), i+1, len(todo)),
			append([]any{"event", "archive", "age_bytes", fi.Size(), "n", i + 1, "of", len(todo)}, fields(r)...)...)
		// Uploaded and indexed by an earlier push that stopped short of
		// cleaning up.
		if v.has(r.ID) {
			ui.Info(r.Name+": already on the remote and indexed by an earlier push", append([]any{"event", "already_pushed"}, fields(r)...)...)
		} else {
			s := ui.Begin("upload", fmt.Sprintf("%s: uploading %s.age%s", r.Name, r.ID, partial),
				"archive", r.Name, "id", r.ID, "file", r.ID+".age"+partial, "age_bytes", fi.Size())
			prog := ui.NewProgress("upload", r.Name+": uploaded", fi.Size(), "archive", r.Name, "id", r.ID)
			err = v.Remote.Upload(local, r.ID+".age"+partial, prog.Set)
			prog.End()
			s.End(err)
			if err == nil {
				err = v.verifyAndMove(r.ID+".age", r.AgeSHA256)
			}
			if err != nil {
				v.Remote.Remove(r.ID + ".age" + partial)
				ui.Error(fmt.Sprintf("%s: %v; it stays staged", r.Name, err),
					append([]any{"event", "failed", "error", err.Error()}, fields(r)...)...)
				failed++
				continue
			}
			v.index = append(v.index, r)
			if err := v.save(); err != nil {
				v.removeRecord(r.ID)
				ui.Error(fmt.Sprintf("%v; %s stays staged, run rveil push again", err, r.Name),
					append([]any{"event", "failed", "error", err.Error()}, fields(r)...)...)
				return errQuiet
			}
		}
		os.Remove(local)
		os.Remove(filepath.Join(v.Staging, r.ID+".json"))
		ui.Debug(r.Name+": removed from staging", append([]any{"event", "unstaged"}, fields(r)...)...)
		ui.Info(fmt.Sprintf("%s: on the remote as %s.age, verified", r.Name, r.ID), append([]any{"event", "pushed"}, fields(r)...)...)
		v.emit(r)
	}
	if failed > 0 {
		return errQuiet
	}
	return nil
}

// --- browse / restore --------------------------------------------------------

// Ls lists archives, oldest first.
// With staged, it lists the archives waiting in staging instead, without
// the key store or the remote.
func (v *Vault) Ls(match string, long, staged bool) error {
	var recs []format.Record
	if staged {
		recs = v.staged()
	} else {
		if err := v.load(); err != nil {
			return err
		}
		recs = slices.Clone(v.index)
		sort.SliceStable(recs, func(i, j int) bool { return recs[i].Created.Before(recs[j].Created) })
	}
	var n, total int64
	for _, r := range recs {
		if match != "" && !matches(r, match) {
			continue
		}
		if v.JSON {
			v.emit(r)
		} else {
			fmt.Fprintln(v.Out, row(r, long))
		}
		n++
		total += r.Size
	}
	ui.Info(fmt.Sprintf("%d archive(s), %s of content", n, ui.Bytes(total)), "event", "listed", "count", n, "size", total)
	return nil
}

// Get downloads one archive and extracts it into dir.
func (v *Vault) Get(arg, dir string) error {
	if err := v.load(); err != nil {
		return err
	}
	r, err := v.one(arg)
	if err != nil {
		return err
	}
	ks, err := v.Keys()
	if err != nil {
		return err
	}
	pass, err := ks.Passphrase(r.ID)
	if err != nil {
		return err
	}
	size := v.listing[r.ID+".age"].Size
	s := ui.Begin("restore", fmt.Sprintf("%s: downloading %s.age and extracting into %s", r.Name, r.ID, dir),
		append([]any{"dir", dir, "age_bytes", size}, fields(r)...)...)
	rc, err := v.Remote.Open(r.ID + ".age")
	if err != nil {
		s.End(err)
		return err
	}
	prog := ui.NewProgress("restore", r.Name+": downloaded", size, "archive", r.Name, "id", r.ID)
	placed, err := extract(io.TeeReader(rc, prog), pass, dir, r.SHA256)
	prog.End()
	if cerr := rc.Close(); err == nil {
		err = cerr
	}
	s.End(err)
	if err != nil {
		return err
	}
	for _, p := range placed {
		ui.Info(r.Name+": extracted "+p, append([]any{"event", "extracted", "path", p}, fields(r)...)...)
		fmt.Fprintln(v.Out, p)
	}
	ui.Info(r.Name+": restored, verified", append([]any{"event", "restored", "dir", dir}, fields(r)...)...)
	return nil
}

// extract decrypts and unpacks into dir; with want set, the content's hash
// must match before anything moves into place.
func extract(in io.Reader, pass, dir, want string) ([]string, error) {
	r, err := seal.NewReader(in, pass)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return seal.Extract(r, dir, func() error {
		if sha, _ := r.Sum(); want != "" && sha != want {
			return errors.New("the content doesn't match its recorded hash; nothing was extracted")
		}
		return nil
	})
}

// Key prints an archive's passphrase, or with index the index's, one per
// key, newest first.
func (v *Vault) Key(arg string, index bool) error {
	ks, err := v.Keys()
	if err != nil {
		return err
	}
	if index {
		if len(ks) == 0 {
			return keystore.ErrNoKeys
		}
		for _, k := range ks {
			pass, _ := format.Passphrase(k.Master, format.IndexID)
			fmt.Fprintf(v.Out, "%s  %s\n", k.ID, pass)
		}
		ui.Info("The index is sealed under one of these keys (usually the first): age -d index.age | zstd -d",
			"event", "index_passphrases", "keys", len(ks))
		return nil
	}
	id := format.FindArchiveID(arg)
	if id == "" || id != strings.TrimSuffix(filepath.Base(arg), ".age") {
		if err := v.load(); err != nil {
			return err
		}
		r, err := v.one(arg)
		if err != nil {
			return err
		}
		id = r.ID
	}
	pass, err := ks.Passphrase(id)
	if err != nil {
		return err
	}
	fmt.Fprintln(v.Out, pass)
	ui.Info(fmt.Sprintf("Decrypt with: age -d %s.age | zstd -d | tar x (age asks for this passphrase)", id),
		"event", "passphrase", "id", id)
	return nil
}

// --- keys --------------------------------------------------------------------

// KeysList lists the keys, newest (current) first.
func (v *Vault) KeysList() error {
	ks, err := v.Keys()
	if err != nil {
		return err
	}
	if len(ks) == 0 {
		return keystore.ErrNoKeys
	}
	for i, k := range ks {
		if v.JSON {
			b, _ := json.Marshal(struct {
				ID      string    `json:"id"`
				Created time.Time `json:"created"`
				Current bool      `json:"current"`
			}{k.ID, k.Created, i == 0})
			fmt.Fprintf(v.Out, "%s\n", b)
			continue
		}
		mark := ""
		if i == 0 {
			mark = "  current"
		}
		fmt.Fprintf(v.Out, "%s  %s%s\n", k.ID, k.Created.Local().Format("2006-01-02 15:04"), mark)
	}
	return nil
}

// KeysNew creates a key, which becomes the current one.
func (v *Vault) KeysNew() error {
	ks, err := v.Keys()
	if err != nil {
		return err
	}
	s := ui.Begin("create_key", fmt.Sprintf("Creating a key in the %s", v.Store), "store", v.Store.String())
	k, err := keystore.New(v.Store, ks)
	s.End(err)
	if err != nil {
		return err
	}
	v.keys = append(keystore.Keys{k}, ks...)
	ui.Info(fmt.Sprintf("Created key %s in the %s; it is the current key", k.ID, v.Store),
		"event", "key_created", "key", k.ID, "store", v.Store.String())
	if len(ks) > 0 {
		ui.Info("Archives under older keys stay readable; move them with: rveil rekey --from <key>",
			"event", "older_keys", "keys", len(ks))
	}
	fmt.Fprintln(v.Out, k.ID)
	return nil
}

// --- rekey / rm -------------------------------------------------------------

// Rekey re-encrypts archives under the current key, remote to remote: from
// selects every archive under that key, args select by match.
func (v *Vault) Rekey(from string, args []string, yes bool) error {
	cur, err := v.current()
	if err != nil {
		return err
	}
	if err := v.load(); err != nil {
		return err
	}
	var todo []format.Record
	for _, r := range v.index {
		hit := from != "" && r.Key == from
		for _, a := range args {
			hit = hit || matches(r, a)
		}
		if hit && r.Key != cur.ID {
			todo = append(todo, r)
		}
	}
	if len(todo) == 0 {
		ui.Notice("Nothing to rekey: no matching archive is under an older key", "event", "nothing_to_do")
		return nil
	}
	var items []string
	for _, r := range todo {
		ui.Info(fmt.Sprintf("%s: to re-encrypt, %s → %s", r.Name, r.Key, cur.ID),
			append([]any{"event", "rekey_plan", "to_key", cur.ID}, fields(r)...)...)
		items = append(items, row(r, false))
	}
	if err := confirm(yes, fmt.Sprintf("Re-encrypt these %d archive(s) under key %s?", len(todo), cur.ID), items); err != nil {
		return err
	}
	ks, _ := v.Keys()
	failed := 0
	for i, r := range todo {
		ui.Info(fmt.Sprintf("%s: re-encrypting, %s → %s (%d/%d)", r.Name, r.Key, cur.ID, i+1, len(todo)),
			append([]any{"event", "archive", "to_key", cur.ID, "n", i + 1, "of", len(todo)}, fields(r)...)...)
		if err := v.rekeyOne(ks, r, cur); err != nil {
			ui.Error(fmt.Sprintf("%s: %v; the old archive is untouched", r.Name, err),
				append([]any{"event", "failed", "error", err.Error()}, fields(r)...)...)
			failed++
			continue
		}
	}
	if failed > 0 {
		ui.Error(fmt.Sprintf("%d archive(s) failed; run the same command again to retry them", failed),
			"event", "failed_total", "count", failed)
		return errQuiet
	}
	return nil
}

func (v *Vault) rekeyOne(ks keystore.Keys, r format.Record, cur keystore.Key) error {
	oldPass, err := ks.Passphrase(r.ID)
	if err != nil {
		return err
	}
	newID := format.NewArchiveID(cur.ID)
	newPass, err := format.Passphrase(cur.Master, newID)
	if err != nil {
		return err
	}
	in, err := v.Remote.Open(r.ID + ".age")
	if err != nil {
		return err
	}
	size := v.listing[r.ID+".age"].Size
	s := ui.Begin("rewrap", fmt.Sprintf("%s: re-encrypting %s.age as %s.age", r.Name, r.ID, newID),
		append([]any{"new_id", newID, "to_key", cur.ID, "age_bytes", size}, fields(r)...)...)
	prog := ui.NewProgress("rewrap", r.Name+": re-encrypted", size, "archive", r.Name, "id", r.ID)
	res, err := v.upload(newID+".age", func(w io.Writer) (seal.Result, error) {
		return seal.Rewrap(io.TeeReader(in, prog), oldPass, newPass, r.SHA256, w)
	})
	prog.End()
	s.End(err)
	in.Close() // the new archive verified on its own
	if err != nil {
		return err
	}
	for i := range v.index {
		if v.index[i].ID == r.ID {
			v.index[i].ID, v.index[i].Key, v.index[i].AgeSHA256 = newID, cur.ID, res.AgeSHA256
		}
	}
	if err := v.save(); err != nil {
		return fmt.Errorf("%w; %s.age is an orphan now (rveil check)", err, newID)
	}
	d := ui.Begin("delete", fmt.Sprintf("%s: deleting the old %s.age", r.Name, r.ID), "archive", r.Name, "id", r.ID)
	err = v.Remote.Remove(r.ID + ".age")
	d.End(err)
	if err != nil {
		ui.Notice(fmt.Sprintf("Couldn't delete the old %s.age: %v (rveil check lists it)", r.ID, err),
			"event", "delete_failed", "id", r.ID, "error", err.Error())
	}
	ui.Info(fmt.Sprintf("%s: now %s.age under key %s", r.Name, newID, cur.ID),
		append([]any{"event", "rekeyed", "new_id", newID, "to_key", cur.ID}, fields(r)...)...)
	return nil
}

// Rm deletes archives: from the index first, then from the remote, so an
// interruption leaves at worst an orphan, never an entry without data.
func (v *Vault) Rm(args []string, yes bool) error {
	if err := v.load(); err != nil {
		return err
	}
	var todo []format.Record
	for _, a := range args {
		found := v.find(a)
		if len(found) == 0 {
			ui.Notice(fmt.Sprintf("No archive matches %q", a), "event", "no_match", "match", a)
		}
		for _, r := range found {
			if !slices.ContainsFunc(todo, func(t format.Record) bool { return t.ID == r.ID }) {
				todo = append(todo, r)
			}
		}
	}
	if len(todo) == 0 {
		return errQuiet
	}
	var total int64
	var items []string
	for _, r := range todo {
		ui.Info(r.Name+": to delete", append([]any{"event", "rm_plan"}, fields(r)...)...)
		items = append(items, row(r, false))
		total += r.Size
	}
	if err := confirm(yes, fmt.Sprintf("Delete these %d archive(s) permanently?", len(todo)), items); err != nil {
		return err
	}
	for _, r := range todo {
		v.removeRecord(r.ID)
	}
	if err := v.save(); err != nil {
		return err
	}
	failed := 0
	for _, r := range todo {
		s := ui.Begin("delete", fmt.Sprintf("%s: deleting %s.age", r.Name, r.ID), fields(r)...)
		err := v.Remote.Remove(r.ID + ".age")
		s.End(err)
		if err != nil {
			ui.Notice(fmt.Sprintf("Couldn't delete %s.age: %v (rveil check lists it)", r.ID, err),
				append([]any{"event", "delete_failed", "error", err.Error()}, fields(r)...)...)
			failed++
			continue
		}
		ui.Info(r.Name+": deleted", append([]any{"event", "deleted"}, fields(r)...)...)
	}
	ui.Info(fmt.Sprintf("Deleted %d archive(s), %s of content", len(todo)-failed, ui.Bytes(total)),
		"event", "deleted_total", "count", len(todo)-failed, "size", total)
	if failed > 0 {
		return errQuiet
	}
	return nil
}

// --- share -------------------------------------------------------------------

// Share makes a public link to an archive in the vault and prints a message
// for the recipient: the link, the archive's passphrase (which opens only
// that archive) and the command that opens it.
func (v *Vault) Share(arg string) error {
	if !version.Released() {
		return errors.New("share needs a release build: the message points at the open.sh of this " +
			"version's GitHub release, and a dev build has none")
	}
	if err := v.load(); err != nil {
		return err
	}
	r, err := v.one(arg)
	if err != nil {
		return err
	}
	ks, err := v.Keys()
	if err != nil {
		return err
	}
	pass, err := ks.Passphrase(r.ID)
	if err != nil {
		return err
	}
	s := ui.Begin("link", fmt.Sprintf("%s: making a public link to %s.age", r.Name, r.ID), fields(r)...)
	link, err := v.Remote.Link(r.ID + ".age")
	s.End(err)
	if err != nil {
		return err
	}
	fmt.Fprintf(v.Out, "I'm sending you %s (encrypted).\n1. Download it: %s\n2. Open Terminal and paste:\n"+
		"curl -fsSL %s | bash -s -- %s %s.age\n",
		r.Name, link, version.OpenScript(), pass, r.ID)
	ui.Info(fmt.Sprintf("Anyone with this message can open %s, and nothing else; rveil rm %s deletes it "+
		"and the link, rveil rekey %s cuts the passphrase off", r.Name, r.ID, r.ID),
		append([]any{"event", "shared", "link", link}, fields(r)...)...)
	return nil
}

// --- local archives ------------------------------------------------------------

// Seal writes a local archive under the current key, not indexed.
func (v *Vault) Seal(path, out string) error {
	cur, err := v.current()
	if err != nil {
		return err
	}
	src, err := seal.Resolve(path)
	if err != nil {
		return err
	}
	id := format.NewArchiveID(cur.ID)
	pass, err := format.Passphrase(cur.Master, id)
	if err != nil {
		return err
	}
	if out == "" {
		out = id + ".age"
	} else if fi, err := os.Stat(out); err == nil && fi.IsDir() {
		out = filepath.Join(out, id+".age")
	}
	if _, err := os.Lstat(out); err == nil {
		return fmt.Errorf("refusing to overwrite %s", out)
	}
	if format.FindArchiveID(filepath.Base(out)) != id {
		ui.Notice(fmt.Sprintf("%s doesn't contain the archive id %s; open it with: rveil open -k - (and its passphrase)", out, id),
			"event", "id_not_in_name", "file", out, "id", id)
	}
	size := contentSize(src.Path)
	f, err := os.OpenFile(out+partial, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	s := ui.Begin("seal", fmt.Sprintf("%s: sealing into %s", src.Name, out),
		"archive", src.Name, "id", id, "key", cur.ID, "files_bytes", size, "file", out)
	prog := ui.NewProgress("seal", src.Name+": sealed", size, "archive", src.Name, "id", id)
	res, err := seal.SealPath(src, pass, f, prog)
	prog.End()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(out+partial, out)
	}
	s.End(err)
	if err != nil {
		os.Remove(out + partial)
		return err
	}
	sealed("written to "+out+", verified", size, newRecord(id, cur.ID, src, res), res)
	fmt.Fprintln(v.Out, out)
	return nil
}

// Open extracts a local archive into dir. The passphrase is derived from
// the archive id in the file name, or read from stdin.
func (v *Vault) Open(file, dir string, stdin io.Reader) error {
	var pass string
	if stdin != nil {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && line == "" {
			return errors.New("no passphrase on stdin")
		}
		pass = strings.TrimSpace(line)
	} else {
		id := format.FindArchiveID(filepath.Base(file))
		if id == "" {
			return fmt.Errorf("can't tell the archive id from the name %s; pass its passphrase with -k -", filepath.Base(file))
		}
		ks, err := v.Keys()
		if err != nil {
			return err
		}
		if pass, err = ks.Passphrase(id); err != nil {
			return err
		}
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, _ := f.Stat()
	name := filepath.Base(file)
	s := ui.Begin("open", fmt.Sprintf("%s: decrypting and extracting into %s", name, dir),
		"file", file, "dir", dir, "age_bytes", fi.Size())
	prog := ui.NewProgress("open", name+": read", fi.Size(), "file", file)
	placed, err := extract(io.TeeReader(f, prog), pass, dir, "")
	prog.End()
	if seal.IsWrongKey(err) {
		err = errors.New("wrong passphrase for this archive")
	}
	s.End(err)
	if err != nil {
		return err
	}
	for _, p := range placed {
		ui.Info(name+": extracted "+p, "event", "extracted", "file", file, "path", p)
		fmt.Fprintln(v.Out, p)
	}
	ui.Info(name+": opened", "event", "opened", "file", file, "dir", dir)
	return nil
}

// StagedNames returns "name\tid" for each staged archive, for completion.
// It reads only the staging folder: no key store, no remote.
func (v *Vault) StagedNames() []string {
	var out []string
	for _, r := range v.staged() {
		out = append(out, r.Name+"\t"+r.ID)
	}
	return out
}
