package ebpf

import (
	bpflib "github.com/iovisor/gobpf/elf"
	"golang.org/x/xerrors"

	"github.com/yuuki/transtracer/logging"
)

const (
	kprobeSupportVersion = "4.1.0"
)

var logger = logging.New("ebpf")

// IsSupportedLinux returns whether or not the current version of linux kernel supports eBPF tracer.
func IsSupportedLinux() (bool, error) {
	currKernelVersion, err := bpflib.CurrentKernelVersion()
	if err != nil {
		return false, xerrors.Errorf(
			"could not get current kernel version, will use kprobes from kernel version >= 4.1: %w",
			err)
	}

	// verify if version >= 4.1 to use kprobe.
	// see https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md.
	supportVersion, _ := bpflib.KernelVersionFromReleaseString(kprobeSupportVersion)
	if currKernelVersion < supportVersion {
		return false, nil
	}

	return true, nil
}
