package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"davidefiocchi.com/rveil/internal/format"
	"davidefiocchi.com/rveil/internal/remote"
	"davidefiocchi.com/rveil/internal/seal"
	"davidefiocchi.com/rveil/internal/ui"
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
	s := ui.Begin("list_remote", fmt.Sprintf("Listing %s with hashes", v.Remote), "remote", v.Remote.String(), "hashes", true)
	entries, err := v.Remote.List(true)
	s.End(err, "files", len(entries))
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
			ui.Info("Not rveil's, left alone: "+e.Name, "event", "foreign", "file", e.Name, "size", e.Size)
		}
	}

	bad, archives := 0, 0
	var missing []string
	for _, r := range v.index {
		e, ok := onRemote[r.ID+".age"]
		switch {
		case !ok:
			ui.Notice(fmt.Sprintf("%s: in the index but not on the remote (%s.age)", r.Name, r.ID),
				append([]any{"event", "missing"}, fields(r)...)...)
			missing = append(missing, r.ID)
		case e.SHA256 != "" && e.SHA256 != r.AgeSHA256:
			ui.Error(fmt.Sprintf("%s: %s.age doesn't match its recorded hash", r.Name, r.ID),
				append([]any{"event", "hash_mismatch", "got", e.SHA256, "want", r.AgeSHA256}, fields(r)...)...)
			bad++
		default:
			ui.Debug(fmt.Sprintf("%s: %s.age present, hash matches", r.Name, r.ID), append([]any{"event", "ok"}, fields(r)...)...)
		}
	}
	for name := range onRemote {
		if format.IsArchiveID(strings.TrimSuffix(name, ".age")) {
			archives++
		}
	}
	ui.Info(fmt.Sprintf("%d archive(s) in the index, %d on the remote", len(v.index), archives),
		"event", "counts", "indexed", len(v.index), "on_remote", archives)

	if deep {
		bad += v.deepCheck(onRemote)
	}

	for _, p := range partials {
		ui.Notice("Unfinished upload: "+p, "event", "partial", "file", p)
	}
	for _, e := range orphans {
		ui.Notice(fmt.Sprintf("On the remote but not in the index: %s (%s)", e.Name, ui.Bytes(e.Size)),
			"event", "orphan", "file", e.Name, "size", e.Size)
	}
	indexFromPartial := v.indexSHA == "" && len(v.index) > 0
	if indexFromPartial {
		ui.Notice(fmt.Sprintf("The index was only found as %s (a save was interrupted)", format.IndexFile+partial),
			"event", "index_from_partial")
	}
	if len(partials)+len(orphans)+len(missing) > 0 || indexFromPartial {
		question := "Fix this (delete unfinished uploads, re-add orphans after reading them, " +
			"drop entries whose archive is gone, save the index)?"
		if err := confirm(yes, question, nil); err != nil {
			return err
		}
		v.repair(partials, orphans, missing)
	} else if bad == 0 {
		ui.Notice("The index and the remote agree", "event", "agree", "archives", len(v.index))
	}
	if bad > 0 {
		return errQuiet
	}
	return nil
}

func (v *Vault) deepCheck(onRemote map[string]remote.Entry) int {
	ks, err := v.Keys()
	if err != nil {
		ui.Error(err.Error(), "event", "failed", "error", err.Error())
		return 1
	}
	bad := 0
	for i, r := range v.index {
		if _, ok := onRemote[r.ID+".age"]; !ok {
			continue
		}
		size := onRemote[r.ID+".age"].Size
		s := ui.Begin("verify", fmt.Sprintf("%s: downloading and decrypting %s.age (%d/%d)", r.Name, r.ID, i+1, len(v.index)),
			append([]any{"age_bytes", size, "n", i + 1, "of", len(v.index)}, fields(r)...)...)
		err := v.verifyArchive(ks.Passphrase, r, size)
		s.End(err)
		if err != nil {
			ui.Error(fmt.Sprintf("%s: %v", r.Name, err), append([]any{"event", "failed", "error", err.Error()}, fields(r)...)...)
			bad++
			continue
		}
		ui.Info(r.Name+": verified", append([]any{"event", "verified"}, fields(r)...)...)
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
	prog := ui.NewProgress("verify", r.Name+": verified", size, "archive", r.Name, "id", r.ID)
	defer prog.End()
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
		ui.Error(err.Error(), "event", "failed", "error", err.Error())
		return
	}
	for _, id := range missing {
		ui.Info("Dropping "+id+" from the index", "event", "dropped", "id", id)
		v.removeRecord(id)
	}
	var unreadable []string
	added := 0
	for _, e := range orphans {
		id := strings.TrimSuffix(e.Name, ".age")
		s := ui.Begin("read_orphan", "Reading "+e.Name, "file", e.Name, "size", e.Size)
		rec, err := v.readOrphan(ks.Passphrase, id, e)
		s.End(err)
		if err != nil {
			ui.Error(fmt.Sprintf("%s: %v", e.Name, err), "event", "failed", "file", e.Name, "error", err.Error())
			unreadable = append(unreadable, e.Name)
			continue
		}
		v.index = append(v.index, rec)
		added++
		ui.Info(fmt.Sprintf("%s is %s; re-added", e.Name, rec.Name), append([]any{"event", "readded"}, fields(rec)...)...)
	}
	if added > 0 || len(missing) > 0 || (v.indexSHA == "" && len(v.index) > 0) {
		if err := v.save(); err != nil {
			ui.Error(err.Error(), "event", "failed", "error", err.Error())
			return
		}
		ui.Notice(fmt.Sprintf("Repaired the index: %d re-added, %d dropped", added, len(missing)),
			"event", "repaired", "readded", added, "dropped", len(missing))
	}
	for _, p := range partials {
		v.removeFile(p)
	}
	if len(unreadable) > 0 {
		ui.Notice(fmt.Sprintf("%d orphan(s) don't open with their key (damaged, or their key is gone)", len(unreadable)),
			"event", "unreadable", "count", len(unreadable))
		if ok, _ := ui.Confirm("Delete them from the remote?", unreadable); ok {
			for _, name := range unreadable {
				v.removeFile(name)
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

// removeFile deletes a file from the remote, logging how it went.
func (v *Vault) removeFile(name string) {
	s := ui.Begin("delete", "Deleting "+name, "file", name)
	err := v.Remote.Remove(name)
	s.End(err)
	if err != nil {
		ui.Notice(fmt.Sprintf("Couldn't delete %s: %v", name, err), "event", "delete_failed", "file", name, "error", err.Error())
		return
	}
	ui.Info("Deleted "+name, "event", "deleted", "file", name)
}
