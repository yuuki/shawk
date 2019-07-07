//go:generate statik -f -m -p genstatik -src=../assets

package statik

import (
	"io/ioutil"

	"github.com/rakyll/statik/fs"
	"golang.org/x/xerrors"

	// local import
	_ "github.com/yuuki/transtracer/statik/genstatik"
)

// FindString returns the string representation of the given file path.
func FindString(path string) (string, error) {
	fs, err := fs.New()
	if err != nil {
		return "", xerrors.Errorf("statik/fs.New() failed: %v", err)
	}
	f, err := fs.Open(path)
	if err != nil {
		return "", xerrors.Errorf("statik/fs.Open(%s) failed: %v", path, err)
	}
	defer f.Close()
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return "", xerrors.Errorf("read '%s' failed: %v", path, err)
	}
	return string(b), nil
}
