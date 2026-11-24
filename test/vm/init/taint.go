//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// taintWarn is TAINT_WARN, the flag of /proc/sys/kernel/tainted (W) that a
// warning of the kernel sets.
const taintWarn = 1 << 9

// A knownWarning is a warning of a kernel itself, a bug of that kernel
// that the tests can set off but do not cause. On that kernel it does not
// fail the run; on any other, it fails it as any other warning does.
type knownWarning struct {
	release  string // of the kernel that has the bug (uname -r)
	site     string // file:line of the WARN_ON
	function string // that holds the WARN_ON
	reason   string
}

// knownWarnings are the warnings of the kernels of test/vm/run.sh that do
// not fail the run on them.
//
// On Linux before 5.16, the IPI that RCU Tasks Trace sends to check a task
// can run after the grace period has removed its count of one from
// trc_n_readers_need_end: the decrement of the late handler is then the
// last one, and trc_read_check_handler warns that it reached zero. The grace
// period still waits for the handler; only the check is wrong. Linux 5.16
// fixed it ("rcu-tasks: Wait for trc_read_check_handler() IPIs",
// cbe0d8d91415, and "rcu-tasks: Simplify trc_read_check_handler() atomic
// operations", 96017bf90397), and 5.15.224 has both; 5.14.21, the last
// 5.14, has neither. The tests set it off: a BPF trampoline without fexit
// programs frees its image after a grace period of RCU Tasks Trace
// (bpf_tramp_image_put). The three decrements in trc_read_check_handler
// (the task left the CPU, it is not in a reader, it is leaving one) are the
// same race.
var knownWarnings = []knownWarning{
	rcuTasksTrace("kernel/rcu/tasks.h:889"),
	rcuTasksTrace("kernel/rcu/tasks.h:897"),
	rcuTasksTrace("kernel/rcu/tasks.h:906"),
}

func rcuTasksTrace(site string) knownWarning {
	return knownWarning{
		release:  "5.14.21-051421-generic",
		site:     site,
		function: "trc_read_check_handler",
		reason:   "a false positive of RCU Tasks Trace when its IPI runs late, fixed in Linux 5.16 (cbe0d8d91415)",
	}
}

// warningHeader is the first line of the report of a warning: the CPU, the
// PID, the site and the function, with its offset and size.
var warningHeader = regexp.MustCompile(`^WARNING: CPU: \d+ PID: \d+ at (\S+:\d+) ([^+\s]+)\+0x[[:xdigit:]]+/0x[[:xdigit:]]+`)

// knownWarningOf returns the known warning of the kernel release that the
// message of the kernel log is the header of, if any.
func knownWarningOf(release, msg string) (knownWarning, bool) {
	m := warningHeader.FindStringSubmatch(msg)
	if m == nil {
		return knownWarning{}, false
	}
	for _, w := range knownWarnings {
		if w.release == release && w.site == m[1] && w.function == m[2] {
			return w, true
		}
	}
	return knownWarning{}, false
}

// An excuse is the header of a known warning in the kernel log.
type excuse struct {
	header string
	knownWarning
}

// excusedTaint tells whether the taint of the kernel, which went from
// before to after while the tests ran, does not fail the run on the
// kernel release, given the messages the kernel logged meanwhile and
// whether they are complete. That is the case when the tests added
// TAINT_WARN alone, every message that reports a warning or a bug is the
// header of a known warning of this kernel, and there is one at least. It
// returns those headers.
//
// A warning that fires once taints the kernel once: after a known warning,
// another one leaves the taint as it is, so the messages, not the taint,
// tell whether there was one.
func excusedTaint(release, before, after string, msgs []string, complete bool) ([]excuse, bool) {
	b, err := strconv.ParseUint(before, 10, 64)
	if err != nil {
		return nil, false
	}
	a, err := strconv.ParseUint(after, 10, 64)
	if err != nil || b&taintWarn != 0 || a != b|taintWarn || !complete {
		return nil, false
	}
	var excuses []excuse
	for _, msg := range msgs {
		if !strings.Contains(msg, "WARNING:") && !strings.Contains(msg, "BUG:") {
			continue
		}
		w, ok := knownWarningOf(release, msg)
		if !ok {
			return nil, false
		}
		excuses = append(excuses, excuse{msg, w})
	}
	return excuses, len(excuses) > 0
}

// A kernelLog reads the records that the kernel logs after it was opened,
// from /dev/kmsg.
type kernelLog struct {
	fd int // -1 if /dev/kmsg could not be opened
}

func openKernelLog() kernelLog {
	fd, err := unix.Open("/dev/kmsg", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		fmt.Println("init: opening the kernel log:", err)
		return kernelLog{fd: -1}
	}
	if _, err := unix.Seek(fd, 0, io.SeekEnd); err != nil {
		fmt.Println("init: seeking the end of the kernel log:", err)
		unix.Close(fd)
		return kernelLog{fd: -1}
	}
	return kernelLog{fd: fd}
}

// messages returns the messages of the records logged since the log was
// opened, or since messages was last called, and whether they are complete:
// the kernel overwrote none of them before it was read.
func (l kernelLog) messages() (msgs []string, complete bool) {
	if l.fd < 0 {
		return nil, false
	}
	complete = true
	buf := make([]byte, 8192) // the longest record, CONSOLE_EXT_LOG_MAX
	for {
		n, err := unix.Read(l.fd, buf)
		switch {
		case errors.Is(err, unix.EINTR):
		case errors.Is(err, unix.EPIPE):
			// Records were overwritten; the next read returns the
			// oldest one left.
			complete = false
		case errors.Is(err, unix.EAGAIN):
			return msgs, complete
		case err != nil:
			fmt.Println("init: reading the kernel log:", err)
			return msgs, false
		case n == 0:
			return msgs, complete
		default:
			msgs = append(msgs, kmsgMessage(buf[:n]))
		}
	}
}

// kmsgMessage returns the message of a record of /dev/kmsg, which is
// "priority,sequence,microseconds,flags[,...];message\n" followed by its
// properties, one per line that starts with a space.
func kmsgMessage(rec []byte) string {
	_, msg, _ := strings.Cut(string(rec), ";")
	msg, _, _ = strings.Cut(msg, "\n")
	return msg
}
