// Package vault implements rveil's commands: archives on a remote, an
// encrypted index of them, keys in a key store.
package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/fiocchidavide/rveil/internal/format"
	"github.com/fiocchidavide/rveil/internal/keystore"
	"github.com/fiocchidavide/rveil/internal/remote"
	"github.com/fiocchidavide/rveil/internal/seal"
	"github.com/fiocchidavide/rveil/internal/ui"
)

const partial = ".partial"

// Vault is one remote folder of archives, its index and the key store.
type Vault struct {
	Store   keystore.Store
	Remote  remote.Remote
	Staging string
	Out     io.Writer // data (listings, passphrases, paths); status goes to stderr

	keys keystore.Keys

	loaded   bool
	index    []format.Record
	indexSHA string // ciphertext hash of index.age as read; "" if there was none
	listing  map[string]remote.Entry
}

// Keys loads the key store, once per command.
func (v *Vault) Keys() (keystore.Keys, error) {
	if v.keys == nil {
		ks, err := keystore.LoadKeys(v.Store)
		if err != nil {
			return nil, err
		}
		v.keys = ks
	}
	return v.keys, nil
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
func (v *Vault) load() error {
	if v.loaded {
		return nil
	}
	entries, err := v.Remote.List(false)
	if err != nil {
		return err
	}
	v.listing = map[string]remote.Entry{}
	for _, e := range entries {
		v.listing[e.Name] = e
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
			break // a broken partial: no index yet
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
	rc, err := v.Remote.Open(name)
	if err != nil {
		return nil, "", err
	}
	data, err := io.ReadAll(rc)
	if cerr := rc.Close(); err == nil {
		err = cerr
	}
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
		pass, err := format.Passphrase(k.Master, format.IndexID)
		if err != nil {
			return nil, "", err
		}
		r, err := seal.NewReader(bytes.NewReader(data), pass)
		if seal.IsWrongKey(err) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("opening %s: %w", name, err)
		}
		plain, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			return nil, "", fmt.Errorf("opening %s: %w", name, err)
		}
		recs, err := format.DecodeIndex(plain)
		return recs, hex.EncodeToString(sum[:]), err
	}
	return nil, "", fmt.Errorf("%s doesn't open with any key in the %s", name, v.Store)
}

// save writes the index under the current key: upload to a partial,
// verify, move into place. It refuses if the index on the remote changed
// since this command read it.
func (v *Vault) save() error {
	cur, err := v.current()
	if err != nil {
		return err
	}
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
	return nil
}

// upload streams an archive to name.partial, checks the remote's hash of it
// against the one computed while writing, and moves it into place. On any
// failure the partial is removed.
func (v *Vault) upload(name string, write func(io.Writer) (seal.Result, error)) (seal.Result, error) {
	w, err := v.Remote.Create(name + partial)
	if err != nil {
		return seal.Result{}, err
	}
	res, err := write(w)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = v.verifyAndMove(name, res.AgeSHA256)
	}
	if err != nil {
		v.Remote.Remove(name + partial)
		return seal.Result{}, err
	}
	return res, nil
}

func (v *Vault) verifyAndMove(name, want string) error {
	got, err := v.Remote.SHA256(name + partial)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("the remote's copy of %s doesn't match what was sent", name)
	}
	return v.Remote.Move(name+partial, name)
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
	ui.Err("%q matches %d archives; use the id of one:", arg, len(found))
	for _, r := range found {
		fmt.Fprintf(os.Stderr, "  %s\n", row(r, true))
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

func (v *Vault) removeRecord(id string) {
	v.index = slices.DeleteFunc(v.index, func(r format.Record) bool { return r.ID == id })
}

func (v *Vault) has(id string) bool {
	return slices.ContainsFunc(v.index, func(r format.Record) bool { return r.ID == id })
}

// confirm asks unless yes is set.
func confirm(yes bool, question string) error {
	if yes {
		return nil
	}
	ok, err := ui.Confirm(question)
	if err != nil {
		return err
	}
	if !ok {
		ui.Warn("Stopped; nothing changed.")
		return errQuiet
	}
	return nil
}
