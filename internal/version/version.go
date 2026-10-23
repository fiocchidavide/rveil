// Package version holds the release version, set at build time:
// -ldflags "-X davidefiocchi.com/rveil/internal/version.Version=v1.0.0"
package version

// Version is the release tag, or "dev" for local builds.
var Version = "dev"

// Released reports whether this is a release build, whose assets (the
// binaries and open.sh) exist on GitHub.
func Released() bool { return Version != "dev" && Version != "" }

// Repo is the GitHub repository releases are published from.
const Repo = "fiocchidavide/rveil"
