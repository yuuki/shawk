//go:build linux

// Command init is the first process of the virtual machines in which
// test/vm/run.sh runs the tests of the BPF programs on other kernels. The
// initramfs holds nothing else than this program, the test binaries and
// their inputs, so it runs on any distribution's kernel and architecture.
//
// It mounts the file systems the tests use, brings up the loopback, runs the
// commands of /vm/commands one after the other, prints a line with the exit
// status of the first that failed (or 0), and reboots, which ends QEMU
// started with -no-reboot. A kernel tainted while the commands ran, e.g. by
// a warning, fails the run and prints the kernel log.
//
// Each line of /vm/commands is a working directory followed by the program
// and its arguments, separated by spaces.
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// ExitMarker precedes the exit status in the output.
const exitMarker = "SHAWK-VM-EXIT"

func main() {
	status := run()
	fmt.Printf("\n%s %d\n", exitMarker, status)
	// Wait until the console has sent the status before rebooting.
	unix.IoctlSetInt(int(os.Stdout.Fd()), unix.TCSBRK, 1)
	unix.Sync()
	if err := unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART); err != nil {
		fmt.Fprintln(os.Stderr, "reboot:", err)
	}
	// The kernel panics when init exits; with panic=-1 it reboots too.
	time.Sleep(time.Hour)
}

func run() (status int) {
	if err := setup(); err != nil {
		fmt.Fprintln(os.Stderr, "init:", err)
		return 125
	}
	var uts unix.Utsname
	unix.Uname(&uts)
	fmt.Printf("init: Linux %s %s\n", unix.ByteSliceToString(uts.Release[:]), unix.ByteSliceToString(uts.Machine[:]))

	taint := tainted()
	defer func() {
		if t := tainted(); t != taint {
			fmt.Printf("init: the kernel was tainted (%s -> %s) while the tests ran:\n", taint, t)
			printKernelLog()
			if status == 0 {
				status = 1
			}
		}
	}()

	f, err := os.Open("/vm/commands")
	if err != nil {
		fmt.Fprintln(os.Stderr, "init:", err)
		return 125
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		fmt.Printf("init: running %s in %s\n", strings.Join(fields[1:], " "), fields[0])
		cmd := exec.Command(fields[1], fields[2:]...)
		cmd.Dir = fields[0]
		cmd.Stdin = nil
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("init: %s: %v\n", fields[1], err)
			if status == 0 {
				status = 1
				if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() > 0 {
					status = ee.ExitCode()
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "init:", err)
		return 125
	}
	return status
}

func setup() error {
	mounts := []struct {
		fstype, target string
		flags          uintptr
	}{
		{"devtmpfs", "/dev", unix.MS_NOSUID},
		{"proc", "/proc", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC},
		{"sysfs", "/sys", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC},
		{"cgroup2", "/sys/fs/cgroup", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC},
	}
	for _, m := range mounts {
		if err := os.MkdirAll(m.target, 0o755); err != nil {
			return err
		}
		if err := unix.Mount(m.fstype, m.target, m.fstype, m.flags, ""); err != nil && err != unix.EBUSY {
			return fmt.Errorf("mounting %s on %s: %w", m.fstype, m.target, err)
		}
	}
	for _, env := range []string{"PATH=/bin:/sbin", "HOME=/root", "TMPDIR=/tmp"} {
		k, v, _ := strings.Cut(env, "=")
		os.Setenv(k, v)
	}
	// The root file system, that of the initramfs, is writable. A file
	// system mounted on /tmp would hide a checkout under it.
	for dir, mode := range map[string]os.FileMode{"/root": 0o700, "/run": 0o755, "/tmp": 0o1777} {
		if err := os.MkdirAll(dir, mode); err != nil {
			return err
		}
	}
	return loopbackUp()
}

// tainted returns the taint flags of the kernel.
func tainted() string {
	b, err := os.ReadFile("/proc/sys/kernel/tainted")
	if err != nil {
		return err.Error()
	}
	return strings.TrimSpace(string(b))
}

// printKernelLog prints the end of the kernel log, which the quiet console
// does not show.
func printKernelLog() {
	buf := make([]byte, 1<<20)
	n, err := unix.Klogctl(3, buf) // SYSLOG_ACTION_READ_ALL
	if err != nil {
		fmt.Println("init: reading the kernel log:", err)
		return
	}
	lines := strings.Split(strings.TrimSpace(string(buf[:n])), "\n")
	fmt.Println(strings.Join(lines[max(0, len(lines)-100):], "\n"))
}

// loopbackUp brings up the loopback of the initial network namespace.
func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("reading the flags of lo: %w", err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("bringing up lo: %w", err)
	}
	return nil
}
