package format

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 5869 appendix A, test cases 1-3: the KDF Passphrase is built on.
func TestHKDFVectors(t *testing.T) {
	vectors := []struct {
		ikm, salt, info string
		n               int
		okm             string
	}{
		{"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42,
			"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"},
		{hex.EncodeToString(seq(0x00, 0x50)), hex.EncodeToString(seq(0x60, 0xb0)), hex.EncodeToString(seq(0xb0, 0x100)), 82,
			"b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"},
		{"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "", 42,
			"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"},
	}
	for i, v := range vectors {
		got, err := hkdf.Key(sha256.New, unhex(t, v.ikm), unhex(t, v.salt), string(unhex(t, v.info)), v.n)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != v.okm {
			t.Errorf("RFC 5869 case %d: got %x", i+1, got)
		}
	}
}

func seq(from, to int) []byte {
	var b []byte
	for i := from; i < to; i++ {
		b = append(b, byte(i))
	}
	return b
}

// Known answers, computed independently with OpenSSL 3:
// openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt hexkey:<master>
// -kdfopt salt:rveil/v1 -kdfopt hexinfo:<id> -binary HKDF | base64url
func TestPassphrase(t *testing.T) {
	master := seq(0, 32)
	for id, want := range map[string]string{
		"index":                             "Vn3qApvGlfw9FeIZBHwmYXgnPbyXnUUblcIt3DmrM5A",
		"abcdef.abcdefghijklmnopqrstuvwxyz": "OgkGKN6XtUkv8zx4KXJvYMTOpn5jUwdZv6UA8FNyRec",
	} {
		got, err := Passphrase(master, id)
		if err != nil || got != want {
			t.Errorf("Passphrase(%q) = %q, %v; want %q", id, got, err, want)
		}
	}
	if _, err := Passphrase(master[:31], "index"); err == nil {
		t.Error("short master key accepted")
	}
}

func TestIDs(t *testing.T) {
	k := NewKeyID()
	id := NewArchiveID(k)
	if !IsKeyID(k) || !IsArchiveID(id) || KeyOf(id) != k {
		t.Fatalf("bad ids %q %q", k, id)
	}
	if got := FindArchiveID("Downloads/" + id + " (1).age"); got != id {
		t.Errorf("FindArchiveID = %q", got)
	}
	if FindArchiveID("index.age") != "" {
		t.Error("found an id in index.age")
	}
	m := NewMasterKey()
	back, err := DecodeMaster(EncodeMaster(m))
	if err != nil || !bytes.Equal(back, m) {
		t.Fatal("master key round trip failed")
	}
}

// Vectors from x vault's xstream.py (padme, padding_frames).
func TestPadme(t *testing.T) {
	cases := []struct {
		n, bucket int64
		frames    []int64
	}{
		{0, 0, []int64{0}}, {1, 1, []int64{1}}, {2, 2, []int64{0}}, {7, 7, []int64{1}},
		{8, 8, []int64{0}}, {9, 10, []int64{1}}, {100, 104, []int64{4}}, {1000, 1024, []int64{16}},
		{4095, 4096, []int64{249}}, {4096, 4096, []int64{248}}, {4097, 4352, []int64{247}},
		{65536, 65536, []int64{2040}}, {1000000, 1015808, []int64{15800}},
		{123456789, 123731968, []int64{275171}}, {5000000000, 5033164800, []int64{33164792}},
		{5000000000000, 5016521801728, []int64{4294967295, 4294967295, 4294967295, 3636899811}},
	}
	for _, c := range cases {
		if got := Padme(c.n); got != c.bucket {
			t.Errorf("Padme(%d) = %d, want %d", c.n, got, c.bucket)
		}
		if got := PaddingFrames(c.n); !slices.Equal(got, c.frames) {
			t.Errorf("PaddingFrames(%d) = %v, want %v", c.n, got, c.frames)
		}
	}
}

// The padded stream is a Padmé bucket in size and decodes, padding skipped,
// to exactly the payload.
func TestPadWriterRoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte("rveil padding test "), 5000)
	var out bytes.Buffer
	p := NewPadWriter(&out)
	z, _ := zstd.NewWriter(p)
	z.Write(data)
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if int64(out.Len()) != p.Total() || p.Total() != Padme(p.Payload()+8) {
		t.Fatalf("total %d, payload %d, len %d", p.Total(), p.Payload(), out.Len())
	}
	r, _ := zstd.NewReader(&out)
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("round trip: %v", err)
	}
}

// Several frames back to back (as for payloads near 4 GiB multiples) are
// skipped too.
func TestZstdSkipsSeveralFrames(t *testing.T) {
	var out bytes.Buffer
	z, _ := zstd.NewWriter(&out)
	z.Write([]byte("hello"))
	z.Close()
	for _, body := range []int{3, 0, 100} {
		out.Write([]byte{0x50, 0x2a, 0x4d, 0x18, byte(body), 0, 0, 0})
		out.Write(make([]byte, body))
	}
	r, _ := zstd.NewReader(&out)
	got, err := io.ReadAll(r)
	if err != nil || string(got) != "hello" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestIndexRoundTrip(t *testing.T) {
	recs := []Record{{ID: NewArchiveID("abcdef"), Key: "abcdef", Name: "tax docs", Kind: "dir",
		Created: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC), Size: 10, SHA256: "aa", AgeSHA256: "bb"}}
	got, err := DecodeIndex(EncodeIndex(recs))
	if err != nil || !slices.Equal(got, recs) {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := DecodeIndex([]byte(`{"id":"nope"}`)); err == nil {
		t.Error("bad id accepted")
	}
}
