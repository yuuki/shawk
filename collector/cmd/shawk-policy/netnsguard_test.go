package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Some tests of this package load tables of nftables, also the form that
// rejects, and bring interfaces up. They do it in network namespaces made
// for them. In the network namespace that the tests themselves run in, the
// same commands would filter the traffic of the machine: every command of
// a test that is meant for another namespace therefore goes through this
// file, which proves three times that it is not in the namespace of the
// test, and stops where it cannot prove it.
//
//  1. A namespace is used only once the process that holds it has told its
//     identity itself, after the namespace was made, and that identity is
//     not the one of the test. A process that `unshare` starts is still in
//     the namespace of its parent until unshare(2) returns: entering "its"
//     namespace before then is entering one's own.
//  2. Before a command is started, the namespace of the holder is read
//     again from outside and compared with the identity it told.
//  3. The command itself is started by a script (netnsGuard) that reads
//     the namespace it is in, and runs the command only if it is the
//     one that was made and not the one of the test. This is the guard at
//     the point of harm: it holds whatever was wrong before it.

// netnsRefused is the exit status of netnsGuard when it does not run its
// command.
const netnsRefused = 97

// netnsGuard runs a command in the network namespace it is started in,
// unless that is the namespace of the test. Its arguments are the identity
// of the namespace of the test, the identity of the namespace that the
// command is meant for (empty for one that was just made, of which only
// "another" is known), and the command.
const netnsGuard = `own=$1; want=$2; shift 2
ns=$(readlink /proc/self/ns/net) || exit 97
if [ -z "$own" ] || [ -z "$ns" ] || [ "$ns" = "$own" ]; then
	echo "refused: this is the network namespace of the test itself ($ns)" >&2
	exit 97
fi
if [ -n "$want" ] && [ "$ns" != "$want" ]; then
	echo "refused: this is the network namespace $ns, not $want, which was made for the test" >&2
	exit 97
fi
exec "$@"`

// ownNetns returns the identity of the network namespace of the test, as
// the kernel names it (net:[4026531840]). A test that cannot read it
// cannot tell its own namespace from another, and is skipped.
func ownNetns(t testing.TB) string {
	t.Helper()
	id, err := os.Readlink("/proc/self/ns/net")
	if err != nil || !strings.HasPrefix(id, "net:[") {
		t.Skipf("the network namespace of the test cannot be read (%q, %v): nothing is run in another", id, err)
	}
	for _, tool := range []string{"sh", "readlink"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not available: no command can be guarded", tool)
		}
	}
	return id
}

// guarded returns a command that is meant for another network namespace
// than the one of the test: `enter` gets there (unshare -n for a new
// namespace, nsenter for one that is held), `want` is the identity of the
// namespace where it is known, and args is the command. It runs through
// netnsGuard. Every such command of the tests is made here.
func guarded(own string, enter []string, want string, args ...string) *exec.Cmd {
	all := append(append([]string{}, enter[1:]...), "sh", "-c", netnsGuard, "sh", own, want)
	return exec.Command(enter[0], append(all, args...)...)
}

// netnsMaker makes new network namespaces: with `unshare -n` as root, or
// `unshare -rn` as root of a new user namespace.
type netnsMaker struct {
	own     string
	unshare []string
}

// command returns a command that runs in a new network namespace.
func (m netnsMaker) command(args ...string) *exec.Cmd {
	return guarded(m.own, m.unshare, "", args...)
}

// userns tells that the namespaces are made in a user namespace of their
// own.
func (m netnsMaker) userns() bool { return len(m.unshare) > 1 && m.unshare[1] == "-rn" }

// heldNetns is a network namespace that a process holds for a test.
type heldNetns struct {
	// own is the namespace of the test, in which no command may run.
	own string
	// id is the identity of the namespace, as its holder read it after the
	// namespace was made.
	id    string
	cmd   *exec.Cmd
	enter []string
}

// holdScript tells the namespace it runs in, then holds it.
const holdScript = `readlink /proc/self/ns/net && exec sleep 600`

// holdNetns starts a process that holds a new network namespace, made by
// the command `maker` (through the guard of `via` when the namespace is made
// from within another), and returns it once the process told a namespace
// that is not the one of the test. It fails otherwise, and no command was
// run in the namespace then.
func holdNetns(own string, maker []string, via *heldNetns, userns bool) (*heldNetns, error) {
	if !strings.HasPrefix(own, "net:[") {
		return nil, fmt.Errorf("the namespace of the test is not known (%q)", own)
	}
	script := append(append([]string{}, maker...), "sh", "-c", holdScript)
	cmd := exec.Command(script[0], script[1:]...)
	if via != nil {
		var err error
		if cmd, err = via.command(script...); err != nil {
			return nil, err
		}
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	ns := &heldNetns{own: own, cmd: cmd, enter: []string{"nsenter", "-t", strconv.Itoa(cmd.Process.Pid), "-n"}}
	if userns {
		ns.enter = append(ns.enter, "-U", "--preserve-credentials")
	}
	// The holder tells its namespace after unshare(2) returned: until it
	// did, nothing is known of where a command "in its namespace" would
	// run.
	told := firstLine(out)
	select {
	case ns.id = <-told:
	case <-time.After(20 * time.Second):
	}
	err = ns.check()
	if err == nil && via != nil && ns.id == via.id {
		err = fmt.Errorf("the new namespace is the one it was made from (%s)", ns.id)
	}
	if err != nil {
		ns.release()
		return nil, err
	}
	return ns, nil
}

// firstLine returns the first line that a holder writes, on a channel.
func firstLine(out io.Reader) <-chan string {
	told := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(out).ReadString('\n')
		told <- strings.TrimSpace(line)
	}()
	return told
}

// check tells why the namespace cannot be used: its holder did not tell an
// identity, the identity is the one of the test, or the holder is not in
// it any more.
func (ns *heldNetns) check() error {
	switch {
	case !strings.HasPrefix(ns.own, "net:["):
		return fmt.Errorf("the namespace of the test is not known (%q)", ns.own)
	case !strings.HasPrefix(ns.id, "net:["):
		return fmt.Errorf("the process that holds the namespace did not tell which it is (%q)", ns.id)
	case ns.id == ns.own:
		return fmt.Errorf("the process that holds the namespace is in the namespace of the test (%s)", ns.id)
	}
	now, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", ns.cmd.Process.Pid))
	if err != nil {
		return fmt.Errorf("the namespace of its holder cannot be read: %w", err)
	}
	if now != ns.id {
		return fmt.Errorf("its holder is in %s, and told %s", now, ns.id)
	}
	return nil
}

// command returns a command that runs in the namespace, through the guard.
// It fails when the namespace is not proven to be another than that of the
// test.
func (ns *heldNetns) command(args ...string) (*exec.Cmd, error) {
	if err := ns.check(); err != nil {
		return nil, err
	}
	return guarded(ns.own, ns.enter, ns.id, args...), nil
}

// release ends the process that holds the namespace.
func (ns *heldNetns) release() {
	_ = ns.cmd.Process.Kill()
	_ = ns.cmd.Wait()
}

// refused tells whether a command ended because the guard did not run it.
func refused(err error) bool {
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == netnsRefused
}

// TestNetnsGuardRefuses: the guard does not run a command in the network
// namespace of the test, however the command got there, and a namespace
// whose holder is in the namespace of the test is not used. This test
// needs no privilege: it only ever stays where it is.
func TestNetnsGuardRefuses(t *testing.T) {
	own := ownNetns(t)
	marker := filepath.Join(t.TempDir(), "ran")
	// "env" enters nothing, as a tool that failed to make or to enter a
	// namespace and went on: the command would run where the test runs.
	for name, cmd := range map[string]*exec.Cmd{
		"in the namespace of the test":                    guarded(own, []string{"env"}, "", "touch", marker),
		"in the namespace of the test, meant for another": guarded(own, []string{"env"}, "net:[1]", "touch", marker),
		"without the namespace of the test":               guarded("", []string{"env"}, "", "touch", marker),
		"meant for the namespace of the test":             guarded(own, []string{"env"}, own, "touch", marker),
	} {
		out, err := cmd.CombinedOutput()
		if !refused(err) || !strings.Contains(string(out), "refused: ") {
			t.Errorf("a command %s: %v, %q; want the exit status %d", name, err, out, netnsRefused)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("a command %s was run", name)
		}
	}
	// nsenter into the namespace of a process that is in the namespace of
	// the test, which is what entering a namespace too early does.
	if _, err := exec.LookPath("nsenter"); err == nil {
		enter := []string{"nsenter", "-t", strconv.Itoa(os.Getpid()), "-n"}
		out, err := guarded(own, enter, "", "touch", marker).CombinedOutput()
		if _, statErr := os.Stat(marker); statErr == nil || (err == nil) {
			t.Fatalf("a command entered the namespace of the test and was run: %v, %q", err, out)
		}
	}
	// A holder that made no namespace: "env" in the place of unshare.
	if ns, err := holdNetns(own, []string{"env"}, nil, false); err == nil {
		ns.release()
		t.Errorf("a holder in the namespace of the test (%s) is taken for a namespace of its own", ns.id)
	}
	if _, err := holdNetns("", []string{"env"}, nil, false); err == nil {
		t.Error("a namespace is held without knowing the one of the test")
	}
	// A holder that says nothing, or that is somewhere else than it said.
	sleeper := exec.Command("sleep", "30")
	if err := sleeper.Start(); err != nil {
		t.Skipf("sleep: %v", err)
	}
	defer func() { _ = sleeper.Process.Kill(); _ = sleeper.Wait() }()
	for name, ns := range map[string]*heldNetns{
		"told nothing":                       {own: own, cmd: sleeper},
		"told the namespace of the test":     {own: own, id: own, cmd: sleeper},
		"is not in the namespace it told":    {own: own, id: "net:[1]", cmd: sleeper},
		"with an unknown namespace of tests": {id: "net:[1]", cmd: sleeper},
	} {
		ns.enter = []string{"nsenter", "-t", strconv.Itoa(sleeper.Process.Pid), "-n"}
		if cmd, err := ns.command("touch", marker); err == nil {
			t.Errorf("a namespace whose holder %s gives the command %v", name, cmd.Args)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a command was run in the namespace of the test")
	}
}

// TestNetnsGuardRace: a process that unshare starts is in the namespace of
// its parent for a moment. Commands that enter "its" namespace at once, as
// a test did before it waited for the holder, run in the namespace of the
// test unless the guard stops them: with the guard none does, and with a
// namespace that is held properly none is even refused. The commands only
// read the namespace they are in. SHAWK_POLICY_TEST_GUARD_TRIES sets how
// many namespaces are made (40), by four at a time.
func TestNetnsGuardRace(t *testing.T) {
	maker := inNetns(t)
	if _, err := exec.LookPath("nsenter"); err != nil {
		t.Skip("nsenter is not available")
	}
	tries := 40
	if s := os.Getenv("SHAWK_POLICY_TEST_GUARD_TRIES"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			t.Fatalf("SHAWK_POLICY_TEST_GUARD_TRIES=%q", s)
		}
		tries = n
	}
	var early, earlyRefused, earlyOwn, held, heldOther, heldOwn, heldRefused atomic.Int64
	var wg sync.WaitGroup
	work := make(chan int)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range work {
				// The namespace entered at once, as before: only the guard
				// is between the command and the namespace of the test.
				racy := exec.Command(maker.unshare[0], append(maker.unshare[1:], "sleep", "30")...)
				if err := racy.Start(); err != nil {
					t.Errorf("unshare: %v", err)
					continue
				}
				enter := []string{"nsenter", "-t", strconv.Itoa(racy.Process.Pid), "-n"}
				if maker.userns() {
					enter = append(enter, "-U", "--preserve-credentials")
				}
				for range 15 {
					out, err := guarded(maker.own, enter, "", "readlink", "/proc/self/ns/net").Output()
					early.Add(1)
					switch id := strings.TrimSpace(string(out)); {
					case refused(err):
						earlyRefused.Add(1)
					case err != nil:
						// nsenter could not enter yet.
					case id == maker.own:
						earlyOwn.Add(1)
					}
				}
				_ = racy.Process.Kill()
				_ = racy.Wait()
				// The namespace held as the tests hold it.
				ns, err := holdNetns(maker.own, maker.unshare, nil, maker.userns())
				if err != nil {
					t.Errorf("a namespace cannot be held: %v", err)
					continue
				}
				for range 15 {
					cmd, err := ns.command("readlink", "/proc/self/ns/net")
					if err != nil {
						t.Errorf("the namespace that is held: %v", err)
						break
					}
					out, err := cmd.Output()
					held.Add(1)
					switch id := strings.TrimSpace(string(out)); {
					case refused(err):
						heldRefused.Add(1)
					case err == nil && id == maker.own:
						heldOwn.Add(1)
					case err == nil && id == ns.id:
						heldOther.Add(1)
					}
				}
				ns.release()
			}
		}()
	}
	for i := range tries {
		work <- i
	}
	close(work)
	wg.Wait()
	t.Logf("%d namespaces, by 4 at a time. Entered at once: %d commands, %d refused by the guard, %d run in the namespace of the test. "+
		"Held: %d commands, %d run in the namespace that is held, %d refused, %d run in the namespace of the test",
		tries, early.Load(), earlyRefused.Load(), earlyOwn.Load(), held.Load(), heldOther.Load(), heldRefused.Load(), heldOwn.Load())
	if earlyOwn.Load() != 0 || heldOwn.Load() != 0 {
		t.Errorf("%d commands ran in the namespace of the test", earlyOwn.Load()+heldOwn.Load())
	}
	if heldOther.Load() != held.Load() {
		t.Errorf("of %d commands for a namespace that is held, %d ran in it", held.Load(), heldOther.Load())
	}
}
