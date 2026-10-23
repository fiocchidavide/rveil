package vault

import (
	"testing"

	"davidefiocchi.com/rveil/internal/format"
)

func TestMatches(t *testing.T) {
	r := format.Record{ID: "abcdef.abcdefghijklmnopqrstuvwxyz", Name: "Tax Docs 2019, scanned"}
	for arg, want := range map[string]bool{
		"tax":                                   true,
		"DOCS 2019":                             true,
		"abcdef.abcdefghijklmnopqrstuvwxyz":     true,
		"abcdef.abcdefghijklmnopqrstuvwxyz.age": true,
		"abcdef":                                false, // a key id isn't a name
		"2020":                                  false,
		"*.pdf":                                 false, // no globs
		"":                                      false, // never everything
	} {
		if got := matches(r, arg); got != want {
			t.Errorf("matches(%q) = %v, want %v", arg, got, want)
		}
	}
}
