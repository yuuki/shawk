package ebpf

import (
	bpflib "github.com/iovisor/gobpf/elf"
	"github.com/weaveworks/tcptracer-bpf/pkg/tracer"
	"github.com/yuuki/transtracer/logging"
	"golang.org/x/xerrors"
)

const (
	kprobeSupportVersion = "4.1.0"
)

var logger = logging.New("ebpf")

type tcpTracer struct {
	evChan chan interface{}
	lost   uint64
}

func (t *tcpTracer) TCPEventV4(ev tracer.TcpV4) {
	t.evChan <- ev
	logger.Infof("%v cpu#%d %s %v %s %v\n",
		ev.Timestamp, ev.CPU, ev.Type, ev.Pid, ev.Comm, ev.Fd)
}

func (t *tcpTracer) TCPEventV6(ev tracer.TcpV6) {
	t.evChan <- ev
}

func (t *tcpTracer) LostV4(count uint64) {
	t.lost += count
}

func (t *tcpTracer) LostV6(count uint64) {
	t.lost += count
}

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

func StartTracer() error {
	t := &tcpTracer{}
	t.evChan = make(chan interface{})
	tracer, err := tracer.NewTracer(t)
	if err != nil {
		return xerrors.Errorf("failed to create an instance of tcp-tracer")
	}

	tracer.Start()

	// TODO: scan /proc
	tracer.AddFdInstallWatcher(uint32(1620))
	tracer.AddFdInstallWatcher(uint32(1622))
	tracer.AddFdInstallWatcher(uint32(1625))

	return nil
}
