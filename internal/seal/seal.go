// Package seal turns content into rveil archives and back:
// tar → zstd → Padmé → age, verified in-process while it is written.
package seal

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"

	"davidefiocchi.com/rveil/internal/format"
)

// zstd window: well under the reference decoder's default limit (2^27), so
// stock `zstd -d` needs no --long.
const windowSize = 1 << 23

// Result describes a sealed stream.
type Result struct {
	Size      int64  // plaintext bytes (the tar stream)
	SHA256    string // of the plaintext
	AgeSize   int64
	AgeSHA256 string
}

// ErrVerify means the inline check of the written archive failed.
var ErrVerify = errors.New("the archive did not verify")

func recipient(pass string) (age.Recipient, error) {
	r, err := age.NewScryptRecipient(pass)
	if err != nil {
		return nil, err
	}
	r.SetWorkFactor(format.WorkFactor)
	return r, nil
}

func identity(pass string) (age.Identity, error) {
	id, err := age.NewScryptIdentity(pass)
	if err != nil {
		return nil, err
	}
	// rveil only ever writes this work factor; anything else is not ours.
	id.SetMaxWorkFactor(format.WorkFactor)
	return id, nil
}

// counter hashes and counts what passes through it.
type counter struct {
	h hash.Hash
	n int64
}

func newCounter() *counter { return &counter{h: sha256.New()} }

func (c *counter) Write(b []byte) (int, error) {
	c.h.Write(b)
	c.n += int64(len(b))
	return len(b), nil
}

func (c *counter) sum() string { return hex.EncodeToString(c.h.Sum(nil)) }

// verifier decrypts and decompresses a ciphertext stream fed to it, and
// reports the plaintext's hash and size.
type verifier struct {
	pw   *io.PipeWriter
	done chan struct{}
	sha  string
	size int64
	err  error
}

func newVerifier(pass string, decompress bool) *verifier {
	pr, pw := io.Pipe()
	v := &verifier{pw: pw, done: make(chan struct{})}
	go func() {
		defer close(v.done)
		c := newCounter()
		v.err = func() error {
			id, err := identity(pass)
			if err != nil {
				return err
			}
			plain, err := age.Decrypt(pr, id)
			if err != nil {
				return err
			}
			if decompress {
				zr, err := zstd.NewReader(plain, zstd.WithDecoderMaxWindow(1<<27))
				if err != nil {
					return err
				}
				defer zr.Close()
				plain = zr
			}
			_, err = io.Copy(c, plain)
			return err
		}()
		pr.CloseWithError(v.err) // unblock the writer if we stopped early
		v.sha, v.size = c.sum(), c.n
	}()
	return v
}

func (v *verifier) Write(b []byte) (int, error) { return v.pw.Write(b) }

// finish closes the input and waits for the result.
func (v *verifier) finish() (string, int64, error) {
	v.pw.Close()
	<-v.done
	return v.sha, v.size, v.err
}

// abort stops the verifier after a failure upstream.
func (v *verifier) abort(err error) {
	v.pw.CloseWithError(err)
	<-v.done
}

// Stream seals plaintext from r into out under pass: zstd, Padmé padding,
// age. The ciphertext is decrypted again in-process as it is written and
// must give back the plaintext's hash, or Stream fails with ErrVerify.
func Stream(r io.Reader, pass string, out io.Writer) (Result, error) {
	rcp, err := recipient(pass)
	if err != nil {
		return Result{}, err
	}
	ageSum := newCounter()
	v := newVerifier(pass, true)
	aw, err := age.Encrypt(io.MultiWriter(out, ageSum, v), rcp)
	if err != nil {
		v.abort(err)
		return Result{}, err
	}
	pad := format.NewPadWriter(aw)
	zw, err := zstd.NewWriter(pad, zstd.WithEncoderLevel(zstd.SpeedBetterCompression),
		zstd.WithWindowSize(windowSize))
	if err != nil {
		v.abort(err)
		return Result{}, err
	}
	plain := newCounter()
	_, err = io.Copy(zw, io.TeeReader(r, plain))
	// Close in order: zstd flushes its last frame, padding goes after it,
	// then age writes its final chunk.
	for _, c := range []io.Closer{zw, pad, aw} {
		if cerr := c.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		v.abort(err)
		return Result{}, err
	}
	vsha, vsize, verr := v.finish()
	res := Result{Size: plain.n, SHA256: plain.sum(), AgeSize: ageSum.n, AgeSHA256: ageSum.sum()}
	if verr != nil || vsha != res.SHA256 || vsize != res.Size {
		return Result{}, fmt.Errorf("%w (%v)", ErrVerify, verr)
	}
	return res, nil
}

// Rewrap re-encrypts an archive from in under newPass into out, without
// recompressing: age is swapped, the padded zstd stream inside is kept. The
// new ciphertext is verified in-process and must decompress to a plaintext
// with hash wantSHA.
func Rewrap(in io.Reader, oldPass, newPass, wantSHA string, out io.Writer) (Result, error) {
	oldID, err := identity(oldPass)
	if err != nil {
		return Result{}, err
	}
	inner, err := age.Decrypt(in, oldID)
	if err != nil {
		return Result{}, err
	}
	rcp, err := recipient(newPass)
	if err != nil {
		return Result{}, err
	}
	ageSum := newCounter()
	v := newVerifier(newPass, true)
	aw, err := age.Encrypt(io.MultiWriter(out, ageSum, v), rcp)
	if err != nil {
		v.abort(err)
		return Result{}, err
	}
	_, err = io.Copy(aw, inner)
	if cerr := aw.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		v.abort(err)
		return Result{}, err
	}
	vsha, vsize, verr := v.finish()
	if verr != nil || vsha != wantSHA {
		return Result{}, fmt.Errorf("%w (%v)", ErrVerify, verr)
	}
	return Result{Size: vsize, SHA256: vsha, AgeSize: ageSum.n, AgeSHA256: ageSum.sum()}, nil
}

// Reader decrypts and decompresses an archive. Read it to the end, then
// call Sum for the plaintext's hash and size; Close releases the decoder.
type Reader struct {
	r  io.Reader
	zr *zstd.Decoder
	c  *counter
}

// NewReader opens the archive in in with pass. A wrong passphrase fails
// here, before any plaintext is read.
func NewReader(in io.Reader, pass string) (*Reader, error) {
	id, err := identity(pass)
	if err != nil {
		return nil, err
	}
	plain, err := age.Decrypt(in, id)
	if err != nil {
		return nil, err
	}
	zr, err := zstd.NewReader(plain, zstd.WithDecoderMaxWindow(1<<27))
	if err != nil {
		return nil, err
	}
	c := newCounter()
	return &Reader{r: io.TeeReader(zr, c), zr: zr, c: c}, nil
}

func (r *Reader) Read(b []byte) (int, error) { return r.r.Read(b) }

// Sum returns the hash and size of the plaintext read so far.
func (r *Reader) Sum() (string, int64) { return r.c.sum(), r.c.n }

// Close releases the decoder.
func (r *Reader) Close() error { r.zr.Close(); return nil }

// IsWrongKey reports whether err means the passphrase didn't match.
func IsWrongKey(err error) bool {
	var nm *age.NoIdentityMatchError
	return errors.As(err, &nm) || errors.Is(err, age.ErrIncorrectIdentity)
}
