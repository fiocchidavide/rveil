package keystore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"davidefiocchi.com/rveil/internal/format"
)

// OnePassword keeps keys in a 1Password vault, one item per key: the title
// is the key id, the concealed field "key" the master key. Keys reach op as
// JSON on stdin, never in argv.
type OnePassword struct{ Vault string }

func (o OnePassword) String() string { return "1Password vault " + o.Vault }

// Trace, if set, is told each command before it runs.
var Trace func(name string, args ...string)

func (o OnePassword) op(stdin []byte, args ...string) ([]byte, error) {
	if Trace != nil {
		Trace("op", args...)
	}
	cmd := exec.Command("op", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if errors.Is(err, exec.ErrNotFound) {
		return nil, errors.New("the 1Password CLI (op) isn't installed")
	}
	if err != nil {
		return nil, fmt.Errorf("op %s: %s", args[0]+" "+args[1], strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func (o OnePassword) vaultExists() bool {
	_, err := o.op(nil, "vault", "get", o.Vault)
	return err == nil
}

type opItem struct {
	Title     string    `json:"title"`
	CreatedAt time.Time `json:"created_at"`
	Fields    []struct {
		Label string `json:"label"`
		Value string `json:"value"`
	} `json:"fields"`
}

// Load reads every key with two op calls in one pipeline: the item list,
// then all items in full (op item get reads the list on stdin).
func (o OnePassword) Load() ([]Key, error) {
	list, err := o.op(nil, "item", "list", "--vault", o.Vault, "--format", "json")
	if err != nil {
		if !o.vaultExists() {
			return nil, nil // no vault yet: no keys
		}
		return nil, err
	}
	if bytes.Equal(bytes.TrimSpace(list), []byte("[]")) {
		return nil, nil // op item get - fails on an empty list
	}
	full, err := o.op(list, "item", "get", "-", "--vault", o.Vault, "--format", "json")
	if err != nil {
		return nil, err
	}
	// One JSON object per item, one after the other (or an array of them).
	var items []opItem
	if trimmed := bytes.TrimSpace(full); len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, fmt.Errorf("reading op's output: %w", err)
		}
	} else {
		dec := json.NewDecoder(bytes.NewReader(full))
		for {
			var it opItem
			if err := dec.Decode(&it); errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				return nil, fmt.Errorf("reading op's output: %w", err)
			}
			items = append(items, it)
		}
	}
	var ks []Key
	for _, it := range items {
		if !format.IsKeyID(it.Title) {
			continue
		}
		for _, f := range it.Fields {
			if f.Label != "key" {
				continue
			}
			m, err := format.DecodeMaster(f.Value)
			if err != nil {
				return nil, fmt.Errorf("key %s: %w", it.Title, err)
			}
			ks = append(ks, Key{ID: it.Title, Created: it.CreatedAt, Master: m})
		}
	}
	return ks, nil
}

// Create stores a key, creating the vault first if it's missing.
func (o OnePassword) Create(k Key) error {
	if !o.vaultExists() {
		if _, err := o.op(nil, "vault", "create", o.Vault, "--icon", "vault-door"); err != nil {
			return err
		}
	}
	type field struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Purpose string `json:"purpose,omitempty"`
		Label   string `json:"label"`
		Value   string `json:"value"`
	}
	tmpl, err := json.Marshal(map[string]any{
		"title":    k.ID,
		"category": "SECURE_NOTE",
		"fields": []field{
			{ID: "key", Type: "CONCEALED", Label: "key", Value: format.EncodeMaster(k.Master)},
			{ID: "notesPlain", Type: "STRING", Purpose: "NOTES", Label: "notesPlain",
				Value: "rveil master key. Archives named " + k.ID + ".*.age derive their " +
					"passphrases from it. Without it they cannot be decrypted."},
		},
	})
	if err != nil {
		return err
	}
	_, err = o.op(tmpl, "item", "create", "--vault", o.Vault, "-")
	return err
}
