// Package format defines rveil/v1: key ids, archive ids, the per-archive
// passphrase, Padmé padding and index records. docs/FORMAT.md is the spec.
package format

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	// Salt is the HKDF salt. It is an input to every key: never change it.
	Salt = "rveil/v1"
	// WorkFactor is age's scrypt logN. Every passphrase is a derived 256-bit
	// value, so stretching it adds nothing; age needs a passphrase, though,
	// for stock `age -d` to open archives.
	WorkFactor = 10
	// IndexID is the id the index is sealed under, with every key.
	IndexID = "index"
	// IndexFile is the index's name on the remote.
	IndexFile = "index.age"
	// MasterKeySize is the length of a master key in bytes.
	MasterKeySize = 32
)

var (
	keyIDRe     = regexp.MustCompile(`^[a-z2-7]{6}$`)
	archiveIDRe = regexp.MustCompile(`^[a-z2-7]{6}\.[a-z2-7]{26}$`)
	embeddedRe  = regexp.MustCompile(`[a-z2-7]{6}\.[a-z2-7]{26}`)
)

// NewMasterKey returns 32 random bytes.
func NewMasterKey() []byte {
	k := make([]byte, MasterKeySize)
	rand.Read(k)
	return k
}

// NewKeyID returns 6 random base32 characters (30 bits).
func NewKeyID() string {
	return strings.ToLower(rand.Text())[:6]
}

// NewArchiveID returns <keyid>.<26 random base32 characters> (130 bits).
func NewArchiveID(keyID string) string {
	return keyID + "." + strings.ToLower(rand.Text())
}

// IsKeyID reports whether s is a key id.
func IsKeyID(s string) bool { return keyIDRe.MatchString(s) }

// IsArchiveID reports whether s is an archive id.
func IsArchiveID(s string) bool { return archiveIDRe.MatchString(s) }

// FindArchiveID returns the last archive id inside s (a file name, perhaps
// renamed by a browser to "<id> (1).age"), or "".
func FindArchiveID(s string) string {
	all := embeddedRe.FindAllString(s, -1)
	if len(all) == 0 {
		return ""
	}
	return all[len(all)-1]
}

// KeyOf returns the key id an archive id was made under.
func KeyOf(id string) string {
	k, _, _ := strings.Cut(id, ".")
	return k
}

// Passphrase derives the passphrase of archive id from a master key:
// base64url(HKDF-SHA256(ikm = master, salt = Salt, info = id, 32 bytes)).
func Passphrase(master []byte, id string) (string, error) {
	if len(master) != MasterKeySize {
		return "", fmt.Errorf("master key must be %d bytes, not %d", MasterKeySize, len(master))
	}
	if id == "" {
		return "", errors.New("empty archive id")
	}
	okm, err := hkdf.Key(sha256.New, master, []byte(Salt), id, 32)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(okm), nil
}

// EncodeMaster renders a master key as unpadded base64url, as stored.
func EncodeMaster(k []byte) string { return base64.RawURLEncoding.EncodeToString(k) }

// DecodeMaster parses a stored master key.
func DecodeMaster(s string) ([]byte, error) {
	k, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(s), "="))
	if err != nil {
		return nil, fmt.Errorf("master key isn't base64url: %w", err)
	}
	if len(k) != MasterKeySize {
		return nil, fmt.Errorf("master key must be %d bytes, not %d", MasterKeySize, len(k))
	}
	return k, nil
}
