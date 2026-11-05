// Command nodeload measures the load of shawk on the compute nodes of an
// HPC cluster, for docs/research/hpc-compute-nodes/compute_nodes.md (#172).
//
//	nodeload mesh [flags]      ranks that connect as MPI over TCP does
//	nodeload peer [flags]      the peer nodes of mesh
//	nodeload probe [flags]     the tracer of shawk, collected every interval
//	nodeload sink [flags]      an OTLP receiver that times what agents send
//	nodeload watch [flags]     the CPU time and memory of a process
//	nodeload fleet [flags]     agents of a cluster, for the connector
//	nodeload flows FILE...     summarize the output of probe
//
// mesh runs a process per rank, each in a cgroup of its own as Slurm makes
// one per task, that listens on a port of its own and connects to ports of
// the peer nodes, which peer serves from many addresses in another network
// namespace. probe loads the BPF programs of shawk as the agent does and
// collects them every interval: it counts the flows, the drops and the
// distinct flows seen so far, and times the collection. sink and watch time
// what the agent itself does: its requests, CPU time and memory. fleet sends
// the series of a cluster of agents to a connector.
//
// probe needs CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN, CAP_SYS_PTRACE and
// CAP_DAC_READ_SEARCH, or root; mesh writes to the cgroup hierarchy. The
// scripts of this directory run the measurements of the note.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmds := map[string]func([]string) error{
		"mesh":  runMesh,
		"rank":  runRank,
		"peer":  runPeer,
		"probe": runProbe,
		"sink":  runSink,
		"watch": runWatch,
		"fleet": runFleet,
		"flows": runFlows,
	}
	cmd, ok := cmds[os.Args[1]]
	if !ok {
		usage()
	}
	if err := cmd(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "nodeload %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: nodeload mesh|peer|probe|sink|watch|fleet|flows [flags]")
	os.Exit(2)
}

// emit writes v as a JSON line to stdout.
func emit(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	os.Stdout.Write(append(b, '\n'))
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
