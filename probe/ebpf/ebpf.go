package ebpf

import (
	bpflib "github.com/iovisor/gobpf/elf"

	"github.com/yuuki/transtracer/logging"
)

var logger = logging.New("ebpf")

// IsSupportedLinux returns whether the version of current linux kernel is supported.
func IsSupportedLinux() bool {
	currKernelVersion, err := bpflib.CurrentKernelVersion()
	if err != nil {
		logger.Warningf("could not get current kernel version, will use kprobes from kernel version >= 4.1.0")
	}
	logger.Infof("%s", currKernelVersion)
	return true
}
