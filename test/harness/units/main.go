//go:build linux

// Command units prints, for each process given by its PID, the unit that
// the agent names it after (procinfo.Unit of its cgroup), one line each:
//
//	PID COMM UNIT CGROUP
//
// test/harness/slurm.sh check runs it in the virtual machine of the Slurm
// cluster on the processes of a job. It exits with 1 if a process is gone.
package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/yuuki/shawk/internal/procinfo"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: units PID...")
		os.Exit(2)
	}
	status := 0
	for _, arg := range os.Args[1:] {
		pid, err := strconv.ParseUint(arg, 10, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "units: bad PID %q\n", arg)
			os.Exit(2)
		}
		cgroup := procinfo.CgroupOf(uint32(pid))
		if cgroup == "" {
			fmt.Fprintf(os.Stderr, "units: no cgroup of process %d\n", pid)
			status = 1
			continue
		}
		fmt.Printf("%d %s %s %s\n", pid, procinfo.Comm(uint32(pid)), procinfo.Unit(cgroup), cgroup)
	}
	os.Exit(status)
}
