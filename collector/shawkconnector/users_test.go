package shawkconnector

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"strings"
	"testing"
)

// TestJobUsers: with job_users, the user of a process of a Slurm job is
// part of its row in PostgreSQL, and the edges of the users are apart;
// other processes, and processes of jobs without a user, have none. The
// series of the users are separate inputs of one output, which has no user.
func TestJobUsers(t *testing.T) {
	for _, on := range []bool{true, false} {
		c, st, sink, now := testConnector(t, func(cfg *Config) { cfg.JobUsers = on })
		edge := func(user string, opened int64) tEdge {
			return tEdge{role: roleClient, proto: "tcp", local: "10.0.0.11", peer: "10.0.0.20", port: 27000,
				svc: "a.out", unit: "slurm/batch", comm: "a.out", exe: "/home/x/a.out", user: user, opened: opened}
		}
		out := consume(t, c, sink, tAgent{host: "cn01", machineID: "m", addrs: []string{"10.0.0.11"}, time: *now,
			edges: []tEdge{
				edge("1001", 2), edge("1002", 3), edge("", 4),
				// The user of a process outside jobs is not kept.
				{role: roleClient, proto: "tcp", local: "10.0.0.11", peer: "10.0.0.1", port: 6817, svc: "slurmd",
					unit: "slurmd.service", comm: "slurmd", exe: "/usr/sbin/slurmd", user: "0", opened: 1},
			},
			listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 40000, svc: "a.out", unit: "slurm/step",
				comm: "a.out", exe: "/home/x/a.out", user: "1001"}}})
		if s := find(out, metricConnOpened, slurmJobService, "*", roleClient, ""); len(s) != 1 || s[0].value != 9 {
			t.Errorf("job_users %v: outputs = %v, want one series of the three users", on, s)
		}
		c.flush(context.Background())
		if len(st.writes) != 1 {
			t.Fatalf("job_users %v: %d writes", on, len(st.writes))
		}
		h := st.writes[0]
		var want []procKey
		if on {
			want = []procKey{{"slurm/batch", "a.out", "a.out", ""}, {"slurm/batch", "a.out", "a.out", "1001"},
				{"slurm/batch", "a.out", "a.out", "1002"}, {"slurm/step", "a.out", "a.out", "1001"},
				{"slurmd.service", "slurmd", "slurmd", ""}}
		} else {
			want = []procKey{{"slurm/batch", "a.out", "a.out", ""}, {"slurm/step", "a.out", "a.out", ""},
				{"slurmd.service", "slurmd", "slurmd", ""}}
		}
		cmpKey := func(a, b procKey) int {
			return cmp.Or(strings.Compare(a.unit, b.unit), strings.Compare(a.comm, b.comm),
				strings.Compare(a.service, b.service), strings.Compare(a.user, b.user))
		}
		got := slices.SortedFunc(maps.Keys(h.processes), cmpKey)
		slices.SortFunc(want, cmpKey)
		if !slices.Equal(got, want) {
			t.Errorf("job_users %v: processes = %v, want %v", on, got, want)
		}
		wantEdges := 4
		if !on {
			wantEdges = 2
		}
		if len(h.edges) != wantEdges {
			t.Errorf("job_users %v: %d edges, want %d", on, len(h.edges), wantEdges)
		}
		for k := range h.listeners {
			if want := map[bool]string{true: "1001", false: ""}[on]; k.user != want {
				t.Errorf("job_users %v: listener of user %q, want %q", on, k.user, want)
			}
		}
	}
}

// TestUserIDParsed: a user id outside the range of uids is not taken.
func TestUserIDParsed(t *testing.T) {
	for v, want := range map[int64]string{0: "0", 1001: "1001", 4294967295: "4294967295", -1: "", 4294967296: ""} {
		md := tAgent{host: "h", edges: []tEdge{{user: "0"}}}.metrics()
		a := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Sum().DataPoints().At(0).Attributes()
		a.PutInt(attrUserID, v)
		if got := parseProcess(a).user; got != want {
			t.Errorf("process.user.id %d = %q, want %q", v, got, want)
		}
	}
	a := tAgent{host: "h", edges: []tEdge{{}}}.metrics().ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).
		Sum().DataPoints().At(0).Attributes()
	a.PutStr(attrUserID, "1001")
	if got := parseProcess(a).user; got != "1001" {
		t.Errorf("process.user.id as a string = %q", got)
	}
}
