package format

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Record is one archive in the index.
type Record struct {
	ID        string    `json:"id"`
	Key       string    `json:"key"`
	Name      string    `json:"name"` // top-level file or folder name, as in the tar
	Kind      string    `json:"kind"` // "file" or "dir"
	Created   time.Time `json:"created"`
	Size      int64     `json:"size"`       // bytes of the tar stream
	SHA256    string    `json:"sha256"`     // of the tar stream
	AgeSHA256 string    `json:"age_sha256"` // of the .age file
}

// EncodeIndex renders records as JSON lines.
func EncodeIndex(recs []Record) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, r := range recs {
		enc.Encode(r)
	}
	return b.Bytes()
}

// DecodeIndex parses JSON lines.
func DecodeIndex(data []byte) ([]Record, error) {
	var recs []Record
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("index line %d: %w", n, err)
		}
		if !IsArchiveID(r.ID) {
			return nil, fmt.Errorf("index line %d: bad archive id %q", n, r.ID)
		}
		recs = append(recs, r)
	}
	return recs, sc.Err()
}
