//go:build !linux

package main

import "errors"

// The workload and the probe need Linux; the sink, fleet and the summaries
// run anywhere, e.g. the sink on another host than the agent.
var errLinux = errors.New("needs Linux")

func runMesh([]string) error  { return errLinux }
func runRank([]string) error  { return errLinux }
func runPeer([]string) error  { return errLinux }
func runProbe([]string) error { return errLinux }
