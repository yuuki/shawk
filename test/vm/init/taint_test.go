//go:build linux

package main

import (
	"slices"
	"testing"
)

const (
	upstream514 = "5.14.21-051421-generic"
	upstream515 = "5.15.224-0515224-generic"
	rocky96     = "5.14.0-570.58.1.el9_6.x86_64"
)

// rcuSplat is the report that the kernel logged in the job 138254313837 of
// the run 45337926182 of CI, abridged, and with the site of the warning
// given.
func rcuSplat(site string) []string {
	return []string{
		"ip_local_port_range: prefer different parity for start/end values.",
		"------------[ cut here ]------------",
		"WARNING: CPU: 1 PID: 0 at " + site + " trc_read_check_handler+0x6f/0xe0",
		"Modules linked in: nft_nat nft_redir nft_masq nft_chain_nat nf_nat nf_conntrack nf_tables nf_defrag_ipv6 nf_defrag_ipv4 veth nfnetlink libcrc32c",
		"CPU: 1 PID: 0 Comm: swapper/1 Not tainted 5.14.21-051421-generic #202111210831",
		"Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2 04/01/2014",
		"RIP: 0010:trc_read_check_handler+0x6f/0xe0",
		"Call Trace:",
		" <IRQ>",
		" flush_smp_call_function_queue+0xc9/0x190",
		" generic_smp_call_function_single_interrupt+0x13/0x20",
		" __sysvec_call_function_single+0x2d/0x90",
		" sysvec_call_function_single+0x77/0x90",
		" </IRQ>",
		" <TASK>",
		" asm_sysvec_call_function_single+0x12/0x20",
		"RIP: 0010:native_safe_halt+0xb/0x10",
		" secondary_startup_64_no_verify+0xc2/0xcb",
		" </TASK>",
		"---[ end trace 4e34fc752fa5ac91 ]---",
	}
}

func TestExcusedTaint(t *testing.T) {
	known := rcuSplat("kernel/rcu/tasks.h:889")
	other := []string{
		"------------[ cut here ]------------",
		"WARNING: CPU: 0 PID: 212 at kernel/bpf/trampoline.c:540 bpf_trampoline_update+0x1a2/0x4c0",
		"Call Trace:",
		"---[ end trace 2061984be69e74ee ]---",
	}
	tests := []struct {
		name          string
		release       string
		before, after string
		msgs          []string
		incomplete    bool
		excused       []string // the sites of the known warnings
	}{
		{name: "the warning of CI", release: upstream514, before: "0", after: "512", msgs: known,
			excused: []string{"kernel/rcu/tasks.h:889"}},
		{name: "the task is not in a reader", release: upstream514, before: "0", after: "512",
			msgs: rcuSplat("kernel/rcu/tasks.h:897"), excused: []string{"kernel/rcu/tasks.h:897"}},
		{name: "the task leaves a reader", release: upstream514, before: "0", after: "512",
			msgs: rcuSplat("kernel/rcu/tasks.h:906"), excused: []string{"kernel/rcu/tasks.h:906"}},
		{name: "two known sites", release: upstream514, before: "0", after: "512",
			msgs:    slices.Concat(rcuSplat("kernel/rcu/tasks.h:889"), rcuSplat("kernel/rcu/tasks.h:897")),
			excused: []string{"kernel/rcu/tasks.h:889", "kernel/rcu/tasks.h:897"}},
		{name: "taint from before the tests kept", release: upstream514, before: "8192", after: "8704", msgs: known,
			excused: []string{"kernel/rcu/tasks.h:889"}},

		{name: "5.15.224 has the fix", release: upstream515, before: "0", after: "512", msgs: known},
		{name: "Rocky Linux 9.6", release: rocky96, before: "0", after: "512", msgs: known},
		{name: "a kernel given by its path", release: "5.14.21", before: "0", after: "512", msgs: known},
		{name: "another warning of the function", release: upstream514, before: "0", after: "512",
			msgs: rcuSplat("kernel/rcu/tasks.h:915")},
		{name: "the site in another function", release: upstream514, before: "0", after: "512",
			msgs: []string{"WARNING: CPU: 1 PID: 0 at kernel/rcu/tasks.h:889 trc_inspect_reader+0x6f/0xe0"}},
		{name: "another warning after the known one", release: upstream514, before: "0", after: "512",
			msgs: slices.Concat(known, other)},
		{name: "another warning before the known one", release: upstream514, before: "0", after: "512",
			msgs: slices.Concat(other, known)},
		{name: "a bug", release: upstream514, before: "0", after: "512",
			msgs: append(slices.Clone(known), "BUG: sleeping function called from invalid context at mm/slab.h:494")},
		{name: "a warning of lockdep", release: upstream514, before: "0", after: "512",
			msgs: append(slices.Clone(known), "WARNING: possible circular locking dependency detected")},
		{name: "an oops too", release: upstream514, before: "0", after: "640", msgs: known},
		{name: "a soft lockup too", release: upstream514, before: "0", after: "16896", msgs: known},
		{name: "a warning before the tests", release: upstream514, before: "512", after: "640", msgs: known},
		{name: "the warning is not in the log", release: upstream514, before: "0", after: "512",
			msgs: []string{"ip_local_port_range: prefer different parity for start/end values."}},
		{name: "no log", release: upstream514, before: "0", after: "512", incomplete: true},
		{name: "records lost", release: upstream514, before: "0", after: "512", msgs: known, incomplete: true},
		{name: "taint unreadable", release: upstream514,
			before: "open /proc/sys/kernel/tainted: no such file or directory", after: "512", msgs: known},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			excuses, ok := excusedTaint(tt.release, tt.before, tt.after, tt.msgs, !tt.incomplete)
			if ok != (tt.excused != nil) {
				t.Fatalf("excused = %v, want %v (%+v)", ok, tt.excused != nil, excuses)
			}
			var sites []string
			for _, e := range excuses {
				if !warningHeader.MatchString(e.header) || e.reason == "" {
					t.Errorf("excuse %+v", e)
				}
				sites = append(sites, e.site)
			}
			if ok && !slices.Equal(sites, tt.excused) {
				t.Errorf("sites = %q, want %q", sites, tt.excused)
			}
		})
	}
}

// TestKnownWarnings checks that every known warning names a kernel of
// test/vm/run.sh, a site, a function and a reason, once.
func TestKnownWarnings(t *testing.T) {
	seen := map[[3]string]bool{}
	for _, w := range knownWarnings {
		key := [3]string{w.release, w.site, w.function}
		if w.release == "" || w.site == "" || w.function == "" || w.reason == "" || seen[key] {
			t.Errorf("known warning %+v", w)
		}
		seen[key] = true
		header := "WARNING: CPU: 0 PID: 1 at " + w.site + " " + w.function + "+0x1/0x2"
		if got, ok := knownWarningOf(w.release, header); !ok || got != w {
			t.Errorf("knownWarningOf(%q, %q) = %+v, %v", w.release, header, got, ok)
		}
	}
}

func TestKmsgMessage(t *testing.T) {
	for _, tt := range []struct{ rec, want string }{
		{
			"4,1234,50141122,-;WARNING: CPU: 1 PID: 0 at kernel/rcu/tasks.h:889 trc_read_check_handler+0x6f/0xe0\n",
			"WARNING: CPU: 1 PID: 0 at kernel/rcu/tasks.h:889 trc_read_check_handler+0x6f/0xe0",
		},
		{
			"6,339,5140382,-,caller=T1;usb 1-1: new device; speed high\n SUBSYSTEM=usb\n DEVICE=c189:1\n",
			"usb 1-1: new device; speed high",
		},
		{"4,1235,50141171,c;Call Trace:\n", "Call Trace:"},
		{"4,1236,50141173,c; <IRQ>\n", " <IRQ>"},
	} {
		if got := kmsgMessage([]byte(tt.rec)); got != tt.want {
			t.Errorf("kmsgMessage(%q) = %q, want %q", tt.rec, got, tt.want)
		}
	}
}
