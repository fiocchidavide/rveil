package keystore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/fiocchidavide/rveil/internal/format"
)

// File keeps keys in a JSON file readable only by its owner, for tests and
// for people without 1Password.
type File struct{ Path string }

type fileItem struct {
	ID      string    `json:"id"`
	Created time.Time `json:"created"`
	Key     string    `json:"key"`
}

type fileData struct {
	Keys []fileItem `json:"keys"`
}

func (f File) String() string { return "key file " + f.Path }

func (f File) read() (fileData, error) {
	var d fileData
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return d, nil
	}
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return d, fmt.Errorf("%s: %w", f.Path, err)
	}
	return d, nil
}

func (f File) Load() ([]Key, error) {
	d, err := f.read()
	if err != nil {
		return nil, err
	}
	var ks []Key
	for _, it := range d.Keys {
		m, err := format.DecodeMaster(it.Key)
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", it.ID, err)
		}
		ks = append(ks, Key{ID: it.ID, Created: it.Created, Master: m})
	}
	return ks, nil
}

func (f File) Create(k Key) error {
	d, err := f.read()
	if err != nil {
		return err
	}
	d.Keys = append(d.Keys, fileItem{ID: k.ID, Created: k.Created, Key: format.EncodeMaster(k.Master)})
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		return err
	}
	// Written beside the file and renamed over it, so a failure never
	// leaves a half-written key file.
	tmp := f.Path + ".new"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.Path)
}
