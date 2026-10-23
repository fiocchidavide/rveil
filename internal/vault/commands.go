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

	"github.com/fiocchidavide/rveil/internal/format"
	"github.com/fiocchidavide/rveil/internal/keystore"
	"github.com/fiocchidavide/rveil/internal/seal"
	"github.com/fiocchidavide/rveil/internal/ui"
	"github.com/fiocchidavide/rveil/internal/version"
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
			ui.Err("%v", err)
			failed++
			continue
		}
		size := contentSize(src.Path)
		ui.Step("[%d/%d] %s (%s)", i+1, len(paths), src.Name, ui.Bytes(size))
		if src.Path != mustAbs(p) {
			ui.Info("%s is a symlink; sealing what it points to: %s", p, src.Path)
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
			ui.Err("%s: %v", src.Name, err)
			failed++
		}
	}
	if !direct {
		if n := len(v.staged()); n > 0 {
			ui.Info("%d archive(s) staged. Upload with: rveil push", n)
		}
	}
	if failed > 0 {
		return errQuiet
	}
	return nil
}

func mustAbs(p string) string {
	a, _ := filepath.Abs(p)
	return a
}

func (v *Vault) putDirect(src seal.Source, id, key, pass string, size int64) error {
	prog := ui.NewProgress(src.Name, size)
	res, err := v.upload(id+".age", func(w io.Writer) (seal.Result, error) {
		return seal.SealPath(src, pass, w, prog)
	})
	prog.Done()
	if err != nil {
		return err
	}
	v.index = append(v.index, newRecord(id, key, src, res))
	if err := v.save(); err != nil {
		return fmt.Errorf("%w; %s.age is on the remote but not in the index (rveil check re-adds it)", err, id)
	}
	ui.OK("%s is on the remote as %s.age, verified (%s)", src.Name, id, ui.Bytes(res.AgeSize))
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
	prog := ui.NewProgress(src.Name, size)
	res, err := seal.SealPath(src, pass, f, prog)
	prog.Done()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(out+partial, out)
	}
	if err != nil {
		os.Remove(out + partial)
		return err
	}
	rec, _ := json.Marshal(newRecord(id, key, src, res))
	if err := os.WriteFile(filepath.Join(v.Staging, id+".json"), append(rec, '\n'), 0o600); err != nil {
		os.Remove(out)
		return err
	}
	ui.OK("Sealed %s: %s → %s, verified", src.Name, ui.Bytes(res.Size), ui.Bytes(res.AgeSize))
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
	if len(todo) == 0 {
		ui.OK("Nothing staged to push.")
		return nil
	}
	if err := v.load(); err != nil {
		return err
	}
	failed := 0
	for i, r := range todo {
		local := filepath.Join(v.Staging, r.ID+".age")
		fi, err := os.Stat(local)
		if err != nil {
			ui.Err("%s: its staged archive is missing; skipping", r.Name)
			failed++
			continue
		}
		ui.Step("[%d/%d] %s (%s)", i+1, len(todo), r.Name, ui.Bytes(fi.Size()))
		// Uploaded and indexed by an earlier push that stopped short of
		// cleaning up.
		if !v.has(r.ID) {
			prog := ui.NewProgress(r.Name, fi.Size())
			err = v.Remote.Upload(local, r.ID+".age"+partial, prog.Set)
			prog.Done()
			if err == nil {
				err = v.verifyAndMove(r.ID+".age", r.AgeSHA256)
			}
			if err != nil {
				v.Remote.Remove(r.ID + ".age" + partial)
				ui.Err("%s: %v; it stays staged", r.Name, err)
				failed++
				continue
			}
			v.index = append(v.index, r)
			if err := v.save(); err != nil {
				v.removeRecord(r.ID)
				ui.Err("%v; %s stays staged, run rveil push again", err, r.Name)
				return errQuiet
			}
		}
		os.Remove(local)
		os.Remove(filepath.Join(v.Staging, r.ID+".json"))
		ui.OK("%s is on the remote as %s.age, verified", r.Name, r.ID)
	}
	if failed > 0 {
		return errQuiet
	}
	return nil
}

// --- browse / restore --------------------------------------------------------

// Ls lists archives, oldest first.
func (v *Vault) Ls(match string, long bool) error {
	if err := v.load(); err != nil {
		return err
	}
	recs := slices.Clone(v.index)
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Created.Before(recs[j].Created) })
	var n, total int64
	for _, r := range recs {
		if match != "" && !matches(r, match) {
			continue
		}
		fmt.Fprintln(v.Out, row(r, long))
		n++
		total += r.Size
	}
	ui.Info("%d archive(s), %s of content", n, ui.Bytes(total))
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
	ui.Step("Restoring %s", r.Name)
	rc, err := v.Remote.Open(r.ID + ".age")
	if err != nil {
		return err
	}
	prog := ui.NewProgress(r.Name, v.listing[r.ID+".age"].Size)
	placed, err := extract(io.TeeReader(rc, prog), pass, dir, r.SHA256)
	prog.Done()
	if cerr := rc.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	for _, p := range placed {
		fmt.Fprintln(v.Out, p)
	}
	ui.OK("Restored %s, verified", r.Name)
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
		ui.Info("The index is sealed under one of these keys (usually the first):")
		ui.Info("  age -d index.age | zstd -d    (age asks for the passphrase)")
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
	ui.Info("Decrypt with: age -d %s.age | zstd -d | tar x   (age asks for this passphrase)", id)
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
	k, err := keystore.New(v.Store, ks)
	if err != nil {
		return err
	}
	v.keys = append(keystore.Keys{k}, ks...)
	ui.OK("Created key %s in the %s; it is the current key", k.ID, v.Store)
	if len(ks) > 0 {
		ui.Info("Archives under older keys stay readable. Move them with: rveil rekey --from <key>")
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
		ui.OK("Nothing to rekey: no matching archive is under an older key.")
		return nil
	}
	ui.Step("%d archive(s) to re-encrypt under key %s:", len(todo), cur.ID)
	for _, r := range todo {
		fmt.Fprintf(os.Stderr, "  %s\n", row(r, false))
	}
	if err := confirm(yes, "Re-encrypt them?"); err != nil {
		return err
	}
	ks, _ := v.Keys()
	failed := 0
	for i, r := range todo {
		ui.Step("[%d/%d] %s: %s → %s", i+1, len(todo), r.Name, r.Key, cur.ID)
		if err := v.rekeyOne(ks, r, cur); err != nil {
			ui.Err("%s: %v; the old archive is untouched", r.Name, err)
			failed++
			continue
		}
	}
	if failed > 0 {
		ui.Warn("%d archive(s) failed; run the same command again to retry them.", failed)
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
	prog := ui.NewProgress("re-keying", v.listing[r.ID+".age"].Size)
	res, err := v.upload(newID+".age", func(w io.Writer) (seal.Result, error) {
		return seal.Rewrap(io.TeeReader(in, prog), oldPass, newPass, r.SHA256, w)
	})
	prog.Done()
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
	if err := v.Remote.Remove(r.ID + ".age"); err != nil {
		ui.Warn("Couldn't remove the old %s.age: %v (rveil check lists it)", r.ID, err)
	}
	ui.OK("Now %s.age", newID)
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
			ui.Warn("No archive matches %q.", a)
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
	ui.Step("%d archive(s) to delete from the remote:", len(todo))
	for _, r := range todo {
		fmt.Fprintf(os.Stderr, "  %s\n", row(r, false))
		total += r.Size
	}
	if err := confirm(yes, "Delete them permanently?"); err != nil {
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
		if err := v.Remote.Remove(r.ID + ".age"); err != nil {
			ui.Warn("Couldn't delete %s.age: %v (rveil check lists it)", r.ID, err)
			failed++
		}
	}
	ui.OK("Deleted %d archive(s) (%s of content).", len(todo)-failed, ui.Bytes(total))
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
	link, err := v.Remote.Link(r.ID + ".age")
	if err != nil {
		return err
	}
	fmt.Fprintf(v.Out, "I'm sending you %s (encrypted).\n1. Download it: %s\n2. Open Terminal and paste:\n"+
		"curl -fsSL https://github.com/%s/releases/download/%s/open.sh | bash -s -- %s %s.age\n",
		r.Name, link, version.Repo, version.Version, pass, r.ID)
	ui.Info("Anyone with this message can open %s, and nothing else.", r.Name)
	ui.Info("rveil rm %s deletes it and the link; rveil rekey %s cuts the passphrase off.", r.ID, r.ID)
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
		ui.Warn("%s doesn't contain the archive id %s; open it with: rveil open -k - (and its passphrase)", out, id)
	}
	size := contentSize(src.Path)
	ui.Step("Sealing %s (%s)", src.Name, ui.Bytes(size))
	f, err := os.OpenFile(out+partial, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	prog := ui.NewProgress(src.Name, size)
	res, err := seal.SealPath(src, pass, f, prog)
	prog.Done()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(out+partial, out)
	}
	if err != nil {
		os.Remove(out + partial)
		return err
	}
	ui.OK("Sealed %s: %s → %s, verified", src.Name, ui.Bytes(res.Size), ui.Bytes(res.AgeSize))
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
	ui.Step("Opening %s", filepath.Base(file))
	prog := ui.NewProgress(filepath.Base(file), fi.Size())
	placed, err := extract(io.TeeReader(f, prog), pass, dir, "")
	prog.Done()
	if seal.IsWrongKey(err) {
		return errors.New("wrong passphrase for this archive")
	}
	if err != nil {
		return err
	}
	for _, p := range placed {
		fmt.Fprintln(v.Out, p)
	}
	ui.OK("Opened %s", filepath.Base(file))
	return nil
}
