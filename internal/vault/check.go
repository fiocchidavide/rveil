package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fiocchidavide/rveil/internal/format"
	"github.com/fiocchidavide/rveil/internal/remote"
	"github.com/fiocchidavide/rveil/internal/seal"
	"github.com/fiocchidavide/rveil/internal/ui"
)

// Check compares the index with the remote: every archive must be there
// with the recorded hash. It offers to fix what it can: leftover partial
// uploads are deleted, and orphans (archives on the remote but not in the
// index, e.g. from an interrupted rekey or an older index put back) are
// read and re-added. With deep, every archive is also downloaded and
// decrypted.
func (v *Vault) Check(deep, yes bool) error {
	if err := v.load(); err != nil {
		return err
	}
	entries, err := v.Remote.List(true)
	if err != nil {
		return err
	}
	onRemote := map[string]remote.Entry{}
	for _, e := range entries {
		onRemote[e.Name] = e
	}
	var partials []string
	var orphans []remote.Entry
	for _, e := range entries {
		switch {
		case strings.HasSuffix(e.Name, partial):
			// The index's partial is the index itself while index.age is missing.
			if e.Name == format.IndexFile+partial && v.indexSHA == "" && len(v.index) > 0 {
				continue
			}
			partials = append(partials, e.Name)
		case e.Name == format.IndexFile:
		case strings.HasSuffix(e.Name, ".age") && format.IsArchiveID(strings.TrimSuffix(e.Name, ".age")):
			if !v.has(strings.TrimSuffix(e.Name, ".age")) {
				orphans = append(orphans, e)
			}
		default:
			ui.Info("Not rveil's, left alone: %s", e.Name)
		}
	}

	bad, archives := 0, 0
	var missing []string
	for _, r := range v.index {
		e, ok := onRemote[r.ID+".age"]
		switch {
		case !ok:
			ui.Warn("In the index but not on the remote: %s", row(r, true))
			missing = append(missing, r.ID)
		case e.SHA256 != "" && e.SHA256 != r.AgeSHA256:
			ui.Err("Doesn't match its recorded hash: %s", row(r, true))
			bad++
		}
	}
	for name := range onRemote {
		if format.IsArchiveID(strings.TrimSuffix(name, ".age")) {
			archives++
		}
	}
	ui.Info("%d archive(s) in the index, %d on the remote", len(v.index), archives)

	if deep {
		bad += v.deepCheck(onRemote)
	}

	if len(partials) > 0 {
		ui.Warn("%d unfinished upload(s) (*.partial) to delete.", len(partials))
	}
	if len(orphans) > 0 {
		ui.Warn("%d archive(s) on the remote but not in the index:", len(orphans))
		for _, e := range orphans {
			fmt.Fprintf(os.Stderr, "  %s  %s\n", e.Name, ui.Bytes(e.Size))
		}
	}
	indexFromPartial := v.indexSHA == "" && len(v.index) > 0
	if indexFromPartial {
		ui.Warn("The index was only found as %s (a save was interrupted).", format.IndexFile+partial)
	}
	if len(partials)+len(orphans)+len(missing) > 0 || indexFromPartial {
		question := "Fix this (delete unfinished uploads, re-add orphans after reading them, " +
			"drop entries whose archive is gone, save the index)?"
		if err := confirm(yes, question); err != nil {
			return err
		}
		v.repair(partials, orphans, missing)
	} else if bad == 0 {
		ui.OK("The index and the remote agree.")
	}
	if bad > 0 {
		return errQuiet
	}
	return nil
}

func (v *Vault) deepCheck(onRemote map[string]remote.Entry) int {
	ks, err := v.Keys()
	if err != nil {
		ui.Err("%v", err)
		return 1
	}
	bad := 0
	for i, r := range v.index {
		if _, ok := onRemote[r.ID+".age"]; !ok {
			continue
		}
		ui.Step("[%d/%d] Verifying %s", i+1, len(v.index), r.Name)
		if err := v.verifyArchive(ks.Passphrase, r, onRemote[r.ID+".age"].Size); err != nil {
			ui.Err("%s: %v", r.Name, err)
			bad++
		}
	}
	return bad
}

func (v *Vault) verifyArchive(passFor func(string) (string, error), r format.Record, size int64) error {
	pass, err := passFor(r.ID)
	if err != nil {
		return err
	}
	rc, err := v.Remote.Open(r.ID + ".age")
	if err != nil {
		return err
	}
	defer rc.Close()
	ageSum := sha256.New()
	prog := ui.NewProgress(r.Name, size)
	defer prog.Done()
	rd, err := seal.NewReader(io.TeeReader(io.TeeReader(rc, ageSum), prog), pass)
	if err != nil {
		return err
	}
	defer rd.Close()
	if _, err := io.Copy(io.Discard, rd); err != nil {
		return err
	}
	io.Copy(ageSum, rc) // anything after age's last chunk, which age doesn't read
	if sha, _ := rd.Sum(); sha != r.SHA256 {
		return fmt.Errorf("content hash %s, recorded %s", sha, r.SHA256)
	}
	if got := hex.EncodeToString(ageSum.Sum(nil)); got != r.AgeSHA256 {
		return fmt.Errorf("archive hash %s, recorded %s", got, r.AgeSHA256)
	}
	return nil
}

// repair deletes partial uploads, drops entries whose archive is gone and
// re-adds orphans, then saves the index. An orphan is read in full: its
// name and kind come from the tar, its hashes are recomputed, and created
// is when it reached the remote.
func (v *Vault) repair(partials []string, orphans []remote.Entry, missing []string) {
	ks, err := v.Keys()
	if err != nil {
		ui.Err("%v", err)
		return
	}
	for _, id := range missing {
		v.removeRecord(id)
	}
	var unreadable []string
	added := 0
	for _, e := range orphans {
		id := strings.TrimSuffix(e.Name, ".age")
		ui.Step("Reading %s", e.Name)
		rec, err := v.readOrphan(ks.Passphrase, id, e)
		if err != nil {
			ui.Err("%s: %v", e.Name, err)
			unreadable = append(unreadable, e.Name)
			continue
		}
		v.index = append(v.index, rec)
		added++
		ui.OK("%s is %s", e.Name, rec.Name)
	}
	if added > 0 || len(missing) > 0 || (v.indexSHA == "" && len(v.index) > 0) {
		if err := v.save(); err != nil {
			ui.Err("%v", err)
			return
		}
		ui.OK("Saved the index (%d re-added, %d dropped).", added, len(missing))
	}
	for _, p := range partials {
		if err := v.Remote.Remove(p); err != nil {
			ui.Warn("Couldn't delete %s: %v", p, err)
		}
	}
	if len(partials) > 0 {
		ui.OK("Deleted %d unfinished upload(s).", len(partials))
	}
	if len(unreadable) > 0 {
		ui.Warn("%d orphan(s) don't open with their key (damaged, or their key is gone).", len(unreadable))
		if ok, _ := ui.Confirm("Delete them from the remote?"); ok {
			for _, name := range unreadable {
				if err := v.Remote.Remove(name); err != nil {
					ui.Warn("Couldn't delete %s: %v", name, err)
				}
			}
		}
	}
}

func (v *Vault) readOrphan(passFor func(string) (string, error), id string, e remote.Entry) (format.Record, error) {
	pass, err := passFor(id)
	if err != nil {
		return format.Record{}, err
	}
	rc, err := v.Remote.Open(e.Name)
	if err != nil {
		return format.Record{}, err
	}
	defer rc.Close()
	ageSum := sha256.New()
	rd, err := seal.NewReader(io.TeeReader(rc, ageSum), pass)
	if err != nil {
		return format.Record{}, err
	}
	defer rd.Close()
	name, kind, err := seal.Inspect(rd)
	if err != nil {
		return format.Record{}, err
	}
	io.Copy(ageSum, rc)
	sha, size := rd.Sum()
	return format.Record{ID: id, Key: format.KeyOf(id), Name: name, Kind: kind,
		Created: e.ModTime.UTC().Truncate(1e9), Size: size, SHA256: sha,
		AgeSHA256: hex.EncodeToString(ageSum.Sum(nil))}, nil
}
