package procinfo

import (
	"os"
	"os/exec"
	"testing"
)

// The files of a process are read through its directory, opened once: once
// the process has exited, the reads fail, whatever takes its PID.
func TestProc(t *testing.T) {
	if _, err := OpenProc(0); err == nil {
		t.Error("OpenProc(0) succeeded")
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip(err)
	}
	cmd := exec.Command(sleep, "60")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	pid := uint32(cmd.Process.Pid)
	p, err := OpenProc(pid)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal(err)
	}
	defer p.Close()
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Exe(); got == "" || got == exe {
		t.Errorf("Exe = %q, want the executable of sleep", got)
	}
	if comm, ok := p.Comm(); !ok || comm != "sleep" {
		t.Errorf("Comm = %q, %v; want sleep", comm, ok)
	}
	if cg, ok := p.Cgroup(); !ok || cg != CgroupOf(pid) {
		t.Errorf("Cgroup = %q, %v; want %q", cg, ok, CgroupOf(pid))
	}

	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if got := p.Exe(); got != "" {
		t.Errorf("Exe after exit = %q", got)
	}
	if comm, ok := p.Comm(); ok {
		t.Errorf("Comm after exit = %q", comm)
	}
	if cg, ok := p.Cgroup(); ok {
		t.Errorf("Cgroup after exit = %q", cg)
	}
}
