package format

import (
	"encoding/binary"
	"io"
	"math/bits"
)

const (
	skippableMagic = 0x184D2A50
	frameHeader    = 8
	maxFrame       = frameHeader + 0xFFFFFFFF
)

// Padme returns the Padmé bucket for n bytes (Nikitin et al., PETS 2019):
// it leaks O(log log n) bits of the length, for at most 12% overhead.
func Padme(n int64) int64 {
	if n < 2 {
		return n
	}
	e := int64(bits.Len64(uint64(n))) - 1
	s := int64(bits.Len64(uint64(e)))
	mask := int64(1)<<(e-s) - 1
	return (n + mask) &^ mask
}

// PaddingFrames returns the body sizes of the zstd skippable frames that
// bring payload up to its Padmé bucket. The bucket is chosen on the whole
// stream, payload plus frames, which always holds at least one frame.
func PaddingFrames(payload int64) []int64 {
	target := Padme(payload + frameHeader)
	rest := target - payload
	var bodies []int64
	for rest > 0 {
		frame := min(rest, maxFrame)
		// Never leave a sliver too small for a frame header.
		if r := rest - frame; r > 0 && r < frameHeader {
			frame -= frameHeader
		}
		bodies = append(bodies, frame-frameHeader)
		rest -= frame
	}
	return bodies
}

// PadWriter passes a zstd stream through and, on Close, appends Padmé
// padding as zstd skippable frames, which `zstd -d` skips by itself. Close
// does not close the underlying writer.
type PadWriter struct {
	w       io.Writer
	payload int64
	total   int64
}

// NewPadWriter returns a PadWriter writing to w.
func NewPadWriter(w io.Writer) *PadWriter { return &PadWriter{w: w} }

func (p *PadWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.payload += int64(n)
	p.total += int64(n)
	return n, err
}

// Close writes the padding frames.
func (p *PadWriter) Close() error {
	zeros := make([]byte, 1<<16)
	for _, body := range PaddingFrames(p.payload) {
		var h [frameHeader]byte
		binary.LittleEndian.PutUint32(h[0:], skippableMagic)
		binary.LittleEndian.PutUint32(h[4:], uint32(body))
		if _, err := p.w.Write(h[:]); err != nil {
			return err
		}
		p.total += frameHeader
		for body > 0 {
			n := min(body, int64(len(zeros)))
			if _, err := p.w.Write(zeros[:n]); err != nil {
				return err
			}
			body -= n
			p.total += n
		}
	}
	return nil
}

// Payload is the number of bytes written before padding.
func (p *PadWriter) Payload() int64 { return p.payload }

// Total is the number of bytes written, padding included.
func (p *PadWriter) Total() int64 { return p.total }
