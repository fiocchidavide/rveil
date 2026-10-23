// Package version holds the release version: set at build time by the
// release workflow (-ldflags "-X davidefiocchi.com/rveil/internal/version.Version=v1.0.0"),
// or taken from the module version that `go install …@v1.0.0` records.
package version

import (
	"regexp"
	"runtime/debug"
)

// Version is the release tag, or "dev" for local builds.
var Version = "dev"

// Only a plain tag is a release. A pseudo-version (a commit after a tag,
// v1.0.1-0.20261023112233-abcdef123456) or one with build metadata (a
// checkout with local changes, v1.0.0+dirty) has no open.sh to link to.
var release = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$`)
var pseudo = regexp.MustCompile(`\d{14}-[0-9a-f]{12}$`)

func init() {
	if Version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v := bi.Main.Version; isRelease(v) {
			Version = v
		}
	}
}

func isRelease(v string) bool { return release.MatchString(v) && !pseudo.MatchString(v) }

// Released reports whether this is a release build, whose assets (the
// binaries and open.sh) exist on GitHub.
func Released() bool { return Version != "dev" && Version != "" }

// Repo is the GitHub repository releases are published from.
const Repo = "fiocchidavide/rveil"
