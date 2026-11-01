// Package version holds the version of shawk, set at build time.
package version

// Version is overridden with -ldflags "-X github.com/yuuki/shawk/internal/version.Version=...".
// It has no leading v (0.8.0), like the versions of the release packages and
// of the collector; the agent sends it as service.version.
var Version = "dev"
