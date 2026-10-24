// Package vault implements rveil's commands: archives on a remote, an
// encrypted index of them, keys in a key store.
package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"

	"davidefiocchi.com/rveil/internal/format"
	"davidefiocchi.com/rveil/internal/keystore"
	"davidefiocchi.com/rveil/internal/remote"
	"davidefiocchi.com/rveil/internal/seal"
	"davidefiocchi.com/rveil/internal/ui"
)

const partial = ".partial"

// Vault is one remote folder of archives, its index and the key store.
type Vault struct {
	Store   keystore.Store
	Remote  remote.Remote
	Staging string
	Out     io.Writer // data (listings, passphrases, paths); the log goes to stderr
	JSON    bool      // data as JSON lines

	keysMu  sync.Mutex
	keys    keystore.Keys
	keysErr error

	shaChecked bool

	loaded   bool
	index    []format.Record
	indexSHA string // ciphertext hash of index.age as read; "" if there was none
	listing  map[string]remote.Entry
}

// Keys loads the key store, once per command. A failure is kept too, so
// 1Password asks at most once.
func (v *Vault) Keys() (keystore.Keys, error) {
	v.keysMu.Lock()
	defer v.keysMu.Unlock()
	if v.keys == nil && v.keysErr == nil {
		s := ui.Begin("unlock_keys", fmt.Sprintf("Unlocking keys in the %s", v.Store), "store", v.Store.String())
		v.keys, v.keysErr = keystore.LoadKeys(v.Store)
		if v.keys == nil && v.keysErr == nil {
			v.keys = keystore.Keys{}
		}
		s.End(v.keysErr, "keys", len(v.keys))
		if v.keysErr == nil {
			ui.Debug(fmt.Sprintf("%d key(s); current %s", len(v.keys), currentID(v.keys)), "event", "keys",
				"keys", len(v.keys), "current", currentID(v.keys))
		}
	}
	return v.keys, v.keysErr
}

func currentID(ks keystore.Keys) string {
	if len(ks) == 0 {
		return ""
	}
	return ks[0].ID
}

func (v *Vault) current() (keystore.Key, error) {
	ks, err := v.Keys()
	if err != nil {
		return keystore.Key{}, err
	}
	return ks.Current()
}

// --- index -------------------------------------------------------------------

// load reads the index from the remote, trying keys newest first. If a save
// was interrupted after its upload was verified but before the move, only
// index.age.partial exists; it is used if it opens (age authenticates the
// whole file, so a truncated partial never does).
func (v *Vault) load() (err error) {
	if v.loaded {
		return nil
	}
	// The keys are needed only to open the index: unlock them meanwhile.
	go v.Keys()
	s := ui.Begin("read_index", fmt.Sprintf("Reading the index on %s", v.Remote), "remote", v.Remote.String())
	defer func() { s.End(err, "archives", len(v.index)) }()
	l := ui.Begin("list_remote", fmt.Sprintf("Listing %s", v.Remote), "remote", v.Remote.String())
	entries, err := v.Remote.List(false)
	l.End(err, "files", len(entries))
	if err != nil {
		return err
	}
	v.listing = map[string]remote.Entry{}
	for _, e := range entries {
		v.listing[e.Name] = e
	}
	if _, ok := v.listing[format.IndexFile]; !ok {
		ui.Debug("No "+format.IndexFile+" on the remote", "event", "no_index", "remote", v.Remote.String())
	}
	for _, name := range []string{format.IndexFile, format.IndexFile + partial} {
		if _, ok := v.listing[name]; !ok {
			continue
		}
		recs, sum, err := v.readIndex(name)
		if err != nil {
			if name == format.IndexFile {
				return err
			}
			ui.Debug(fmt.Sprintf("%s doesn't open: %v; no index yet", name, err), "event", "broken_partial", "file", name)
			break // a broken partial: no index yet
		}
		if name != format.IndexFile {
			ui.Notice(fmt.Sprintf("Using %s: a save of the index was interrupted (rveil check repairs it)", name),
				"event", "index_from_partial", "file", name)
		}
		v.index = recs
		if name == format.IndexFile {
			v.indexSHA = sum
		}
		break
	}
	v.loaded = true
	return nil
}

func (v *Vault) readIndex(name string) ([]format.Record, string, error) {
	d := ui.Begin("download_index", "Downloading "+name, "file", name, "size", v.listing[name].Size)
	rc, err := v.Remote.Open(name)
	if err != nil {
		d.End(err)
		return nil, "", err
	}
	data, err := io.ReadAll(rc)
	if cerr := rc.Close(); err == nil {
		err = cerr
	}
	d.End(err, "bytes", len(data))
	if err != nil {
		return nil, "", fmt.Errorf("reading %s: %w", name, err)
	}
	sum := sha256.Sum256(data)
	ks, err := v.Keys()
	if err != nil {
		return nil, "", err
	}
	if len(ks) == 0 {
		return nil, "", keystore.ErrNoKeys
	}
	for _, k := range ks {
		o := ui.Begin("decrypt_index", fmt.Sprintf("Decrypting %s with key %s", name, k.ID), "file", name, "key", k.ID)
		pass, err := format.Passphrase(k.Master, format.IndexID)
		if err != nil {
			o.End(err)
			return nil, "", err
		}
		r, err := seal.NewReader(bytes.NewReader(data), pass)
		if seal.IsWrongKey(err) {
			o.End(err)
			ui.Debug(fmt.Sprintf("%s isn't under key %s", name, k.ID), "event", "wrong_key", "file", name, "key", k.ID)
			continue
		}
		if err != nil {
			o.End(err)
			return nil, "", fmt.Errorf("opening %s: %w", name, err)
		}
		plain, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			o.End(err)
			return nil, "", fmt.Errorf("opening %s: %w", name, err)
		}
		recs, err := format.DecodeIndex(plain)
		o.End(err, "archives", len(recs))
		return recs, hex.EncodeToString(sum[:]), err
	}
	return nil, "", fmt.Errorf("%s doesn't open with any key in the %s", name, v.Store)
}

// save writes the index under the current key: upload to a partial,
// verify, move into place. It refuses if the index on the remote changed
// since this command read it.
func (v *Vault) save() (err error) {
	cur, err := v.current()
	if err != nil {
		return err
	}
	s := ui.Begin("save_index", fmt.Sprintf("Saving the index (%d archive(s)) under key %s", len(v.index), cur.ID),
		"archives", len(v.index), "key", cur.ID)
	defer func() { s.End(err) }()
	c := ui.Begin("check_index", "Checking the index on the remote is the one read")
	entries, err := v.Remote.List(false)
	if err != nil {
		return err
	}
	now := ""
	if slices.ContainsFunc(entries, func(e remote.Entry) bool { return e.Name == format.IndexFile }) {
		if now, err = v.Remote.SHA256(format.IndexFile); err != nil {
			return err
		}
	}
	c.End(err, "sha256", now)
	if now != v.indexSHA {
		return errors.New("the index on the remote changed while this ran (another machine?); run the command again")
	}
	pass, err := format.Passphrase(cur.Master, format.IndexID)
	if err != nil {
		return err
	}
	data := format.EncodeIndex(v.index)
	res, err := v.upload(format.IndexFile, func(w io.Writer) (seal.Result, error) {
		return seal.Stream(bytes.NewReader(data), pass, w)
	})
	if err != nil {
		return fmt.Errorf("saving the index: %w (the one on the remote is unchanged)", err)
	}
	v.indexSHA = res.AgeSHA256
	ui.Info(fmt.Sprintf("Saved the index: %d archive(s)", len(v.index)), "event", "index_saved",
		"archives", len(v.index), "key", cur.ID, "sha256", res.AgeSHA256)
	return nil
}

// upload streams an archive to name.partial, checks the remote's hash of it
// against the one computed while writing, and moves it into place. On any
// failure the partial is removed.
func (v *Vault) upload(name string, write func(io.Writer) (seal.Result, error)) (seal.Result, error) {
	if err := v.needSHA256(); err != nil {
		return seal.Result{}, err
	}
	u := ui.Begin("upload", fmt.Sprintf("Uploading %s%s", name, partial), "file", name+partial)
	w, err := v.Remote.Create(name + partial)
	if err != nil {
		u.End(err)
		return seal.Result{}, err
	}
	res, err := write(w)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	u.End(err, "bytes", res.AgeSize)
	if err == nil {
		err = v.verifyAndMove(name, res.AgeSHA256)
	}
	if err != nil {
		ui.Debug("Removing "+name+partial, "event", "remove_partial", "file", name+partial)
		v.Remote.Remove(name + partial)
		return seal.Result{}, err
	}
	return res, nil
}

// verifyAndMove checks an uploaded partial against the hash computed while
// writing, moves it into place, and checks that the move took effect.
func (v *Vault) verifyAndMove(name, want string) (err error) {
	s := ui.Begin("verify_upload", fmt.Sprintf("Checking the remote's SHA-256 of %s%s", name, partial),
		"file", name+partial, "want", want)
	got, err := v.Remote.SHA256(name + partial)
	if err == nil && got != want {
		err = fmt.Errorf("the remote's copy of %s doesn't match what was sent", name)
	}
	s.End(err, "got", got)
	if err != nil {
		return err
	}
	s = ui.Begin("move", fmt.Sprintf("Moving %s%s to %s", name, partial, name), "from", name+partial, "to", name)
	err = v.Remote.Move(name+partial, name)
	if err == nil {
		got, err = v.Remote.SHA256(name)
	}
	if err == nil && got != want {
		err = fmt.Errorf("%s on the remote isn't the copy just uploaded after the move", name)
	}
	s.End(err, "got", got)
	if err == nil {
		ui.Debug(fmt.Sprintf("%s verified on the remote: sha256 %s", name, want), "event", "verified",
			"file", name, "sha256", want)
	}
	return err
}

// needSHA256 checks once per command, before the first upload, that the
// remote can verify uploads at all.
func (v *Vault) needSHA256() error {
	if !v.shaChecked {
		s := ui.Begin("check_sha256", fmt.Sprintf("Checking %s reports SHA-256", v.Remote), "remote", v.Remote.String())
		err := v.Remote.CheckSHA256()
		s.End(err)
		if err != nil {
			return err
		}
		v.shaChecked = true
	}
	return nil
}

// --- matching ----------------------------------------------------------------

// matches: an archive id (with or without .age), or a case-insensitive part
// of the name.
func matches(r format.Record, arg string) bool {
	if arg == "" {
		return false // or `rm ""` would mean everything
	}
	if r.ID == strings.TrimSuffix(arg, ".age") {
		return true
	}
	return strings.Contains(strings.ToLower(r.Name), strings.ToLower(arg))
}

func (v *Vault) find(arg string) []format.Record {
	var out []format.Record
	for _, r := range v.index {
		if matches(r, arg) {
			out = append(out, r)
		}
	}
	return out
}

// one returns the single archive arg matches; with several, it lists them
// and stops.
func (v *Vault) one(arg string) (format.Record, error) {
	found := v.find(arg)
	switch len(found) {
	case 0:
		return format.Record{}, fmt.Errorf("no archive matches %q (see rveil ls)", arg)
	case 1:
		return found[0], nil
	}
	ui.Error(fmt.Sprintf("%q matches %d archives; use the id of one", arg, len(found)),
		"event", "ambiguous", "match", arg, "count", len(found))
	for _, r := range found {
		ui.Error(fmt.Sprintf("%q matches %s (%s)", arg, r.Name, r.ID), "event", "candidate", "match", arg,
			"id", r.ID, "archive", r.Name)
	}
	return format.Record{}, errQuiet
}

// errQuiet is a failure already explained on stderr.
var errQuiet = errors.New("")

// IsQuiet reports whether err was already explained to the user.
func IsQuiet(err error) bool { return errors.Is(err, errQuiet) }

func row(r format.Record, long bool) string {
	name := r.Name
	if r.Kind == "dir" {
		name += "/"
	}
	s := fmt.Sprintf("%s  %s  %10s  %s", r.Created.Local().Format("2006-01-02"), r.Key, ui.Bytes(r.Size), name)
	if long {
		s += "  (" + r.ID + ")"
	}
	return s
}

// emit prints one record as data: JSON, or its id.
func (v *Vault) emit(r format.Record) {
	if v.JSON {
		b, _ := json.Marshal(r)
		fmt.Fprintf(v.Out, "%s\n", b)
		return
	}
	fmt.Fprintln(v.Out, r.ID)
}

// fields describes an archive for the log.
func fields(r format.Record) []any {
	return []any{"id", r.ID, "archive", r.Name, "kind", r.Kind, "key", r.Key, "size", r.Size}
}

func (v *Vault) removeRecord(id string) {
	v.index = slices.DeleteFunc(v.index, func(r format.Record) bool { return r.ID == id })
}

func (v *Vault) has(id string) bool {
	return slices.ContainsFunc(v.index, func(r format.Record) bool { return r.ID == id })
}

// confirm asks, after listing items, unless yes is set.
func confirm(yes bool, question string, items []string) error {
	if yes {
		return nil
	}
	ok, err := ui.Confirm(question, items)
	if err != nil {
		return err
	}
	if !ok {
		ui.Notice("Stopped; nothing changed", "event", "declined")
		return errQuiet
	}
	return nil
}
