package version

import (
	"fmt"
	"io"
)

// name is application name.
const name = "shawk"

// version is application version.
const version = "0.5.1"

// commit describes latest git commit hash.
// This is automatically extracted by git describe --always.
var commit string

// date describes build date.
var date string

// PrintVersion prints version.
func PrintVersion(w io.Writer) {
	fmt.Fprintf(w, "%s version %s, build %s, date %s \n", name, version, commit, date)
}

// GetVersion returns version.
func GetVersion() string {
	return version
}
