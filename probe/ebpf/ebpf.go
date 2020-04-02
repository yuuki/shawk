package ebpf

import (
	"fmt"
	"syscall"

	bpflib "github.com/iovisor/gobpf/elf"
	"github.com/weaveworks/tcptracer-bpf/pkg/tracer"
	"github.com/yuuki/transtracer/internal/lstf/tcpflow"
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

// StartTracer starts an ebpf tracing process.
func StartTracer(cb func(*tcpflow.HostFlow)) error {
	t := &tcpTracer{}
	t.evChan = make(chan interface{})
	tr, err := tracer.NewTracer(t)
	if err != nil {
		return xerrors.Errorf("failed to create an instance of tcp-tracer: %w", err)
	}

	tr.Start()

	// TODO: scan /proc
	// Should tr.AddFdInstallWatcher be executed each listening process here?

	for ev := range t.evChan {
		switch v := ev.(type) {
		case tracer.TcpV4:
			var pgid int
			if v.Type == tracer.EventConnect || v.Type == tracer.EventAccept {
				var err error
				pgid, err = syscall.Getpgid(int(v.Pid))
				if err != nil {
					pgid = int(v.Pid)
				}
			}
			proc := &tcpflow.Process{Name: v.Comm, Pgid: pgid}

			if v.Type == tracer.EventConnect {
				cb(&tcpflow.HostFlow{
					Direction: tcpflow.FlowActive,
					Local:     &tcpflow.AddrPort{Addr: v.SAddr.String(), Port: "many"},
					Peer:      &tcpflow.AddrPort{Addr: v.DAddr.String(), Port: fmt.Sprintf("%d", v.DPort)},
					Process:   proc,
				})
			} else if v.Type == tracer.EventAccept {
				cb(&tcpflow.HostFlow{
					Direction: tcpflow.FlowPassive,
					Local:     &tcpflow.AddrPort{Addr: v.SAddr.String(), Port: fmt.Sprintf("%d", v.SPort)},
					Peer:      &tcpflow.AddrPort{Addr: v.DAddr.String(), Port: "many"},
					Process:   proc,
				})
			}
			// TODO: handling close
		}
	}

	return nil
}
