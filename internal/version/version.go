// Package version holds the version of shawk, set at build time.
package version

// Version is overridden with -ldflags "-X github.com/yuuki/shawk/internal/version.Version=...".
var Version = "dev"
