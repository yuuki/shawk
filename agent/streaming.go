package agent

import (
	"github.com/yuuki/transtracer/db"
	"github.com/yuuki/transtracer/probe/ebpf"

	"golang.org/x/xerrors"
)

// StartWithStreaming starts agent process on streaming mode.
func StartWithStreaming(db *db.DB) error {
	if !ebpf.IsSupportedLinux() {
		return xerrors.Errorf("Your linux kernel is out of supoort")
	}
	// launch collector
	// launch flusher
	return nil
}
