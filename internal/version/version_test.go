package version

import "testing"

func TestIsRelease(t *testing.T) {
	for v, want := range map[string]bool{
		"v1.0.0":                               true,
		"v1.2.3-rc.1":                          true,
		"v1.0.0+dirty":                         false, // a checkout with local changes
		"v1.0.1-0.20261023112233-abcdef123456": false, // a commit after v1.0.0
		"v0.0.0-20261023112233-abcdef123456":   false,
		"(devel)":                              false,
		"":                                     false,
	} {
		if got := isRelease(v); got != want {
			t.Errorf("isRelease(%q) = %v, want %v", v, got, want)
		}
	}
}
