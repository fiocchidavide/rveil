// Package keystore holds master keys. A store only lists and adds keys;
// the current key is the newest.
package keystore

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"davidefiocchi.com/rveil/internal/format"
)

// Key is a master key.
type Key struct {
	ID      string
	Created time.Time
	Master  []byte
}

// Store is where master keys live.
type Store interface {
	// Load returns every key. It is called at most once per command.
	Load() ([]Key, error)
	// Create stores a new key.
	Create(Key) error
	// String names the store for messages.
	String() string
}

// ErrNoKeys means the store has no keys yet.
var ErrNoKeys = errors.New("no keys yet; create one with: rveil keys new")

// Open returns the store for a spec: "op:<vault>" or "file:<path>".
func Open(spec string) (Store, error) {
	kind, arg, ok := strings.Cut(spec, ":")
	if ok && arg != "" {
		switch kind {
		case "op":
			return OnePassword{Vault: arg}, nil
		case "file":
			return File{Path: arg}, nil
		}
	}
	return nil, fmt.Errorf("RVEIL_KEYSTORE must be op:<vault> or file:<path>, not %q", spec)
}

// Keys is a loaded set of keys, newest first.
type Keys []Key

// LoadKeys loads and sorts a store's keys. Keys created in the same instant
// sort by id, so the order is always the same.
func LoadKeys(s Store) (Keys, error) {
	ks, err := s.Load()
	if err != nil {
		return nil, err
	}
	sort.Slice(ks, func(i, j int) bool {
		if !ks[i].Created.Equal(ks[j].Created) {
			return ks[i].Created.After(ks[j].Created)
		}
		return ks[i].ID < ks[j].ID
	})
	return ks, nil
}

// Current returns the newest key.
func (ks Keys) Current() (Key, error) {
	if len(ks) == 0 {
		return Key{}, ErrNoKeys
	}
	return ks[0], nil
}

// Get returns key id.
func (ks Keys) Get(id string) (Key, error) {
	for _, k := range ks {
		if k.ID == id {
			return k, nil
		}
	}
	return Key{}, fmt.Errorf("no key %q in the key store", id)
}

// Passphrase derives an archive's passphrase from the key it was made under.
func (ks Keys) Passphrase(id string) (string, error) {
	k, err := ks.Get(format.KeyOf(id))
	if err != nil {
		return "", err
	}
	return format.Passphrase(k.Master, id)
}

// New creates a key, which becomes the current one. Stores that record
// time to the second (1Password) would make two keys from the same second
// tie, so New waits for the next second when the newest key is that recent.
func New(s Store, ks Keys) (Key, error) {
	if cur, err := ks.Current(); err == nil {
		if wait := time.Until(cur.Created.Truncate(time.Second).Add(time.Second)); wait > 0 {
			time.Sleep(wait)
		}
	}
	k := Key{Master: format.NewMasterKey()}
	for {
		k.ID = format.NewKeyID()
		if _, err := ks.Get(k.ID); err != nil {
			break
		}
	}
	k.Created = time.Now().UTC()
	if err := s.Create(k); err != nil {
		return Key{}, err
	}
	return k, nil
}
