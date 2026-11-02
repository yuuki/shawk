package tracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// requireNFSClient loads the NFS client of the kernel if needed.
// SHAWK_TEST_NO_NFS=1 declares a kernel without it, such as those of the
// virtual machines of test/vm, whose initramfs has no modules: the test is
// then skipped even in strict mode.
func requireNFSClient(t *testing.T) {
	t.Helper()
	requireRoot(t)
	if hasFilesystem("nfs4") {
		return
	}
	// The error, e.g. without modprobe, shows in the check below.
	exec.Command("modprobe", "nfsv4").Run()
	if hasFilesystem("nfs4") {
		return
	}
	if noNFS, _ := strconv.ParseBool(os.Getenv("SHAWK_TEST_NO_NFS")); noNFS {
		t.Skip("the kernel has no NFS client, as SHAWK_TEST_NO_NFS declares")
	}
	skipUnavailable(t, "the kernel has no NFSv4 client (modprobe nfsv4)")
}

func hasFilesystem(name string) bool {
	b, err := os.ReadFile("/proc/filesystems")
	if err != nil {
		return false
	}
	for _, line := range bytes.Split(b, []byte("\n")) {
		f := bytes.Fields(line)
		if len(f) > 0 && string(f[len(f)-1]) == name {
			return true
		}
	}
	return false
}

// silentServer accepts connections and reads them without ever answering,
// so that an NFS mount against it hangs with its connection open.
type silentServer struct {
	ln    net.Listener
	conns chan net.Conn
}

func newSilentServer(t *testing.T) *silentServer {
	t.Helper()
	var lc net.ListenConfig
	lc.SetMultipathTCP(false)
	ln, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &silentServer{ln: ln, conns: make(chan net.Conn, 16)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(io.Discard, c)
			s.conns <- c
		}
	}()
	return s
}

func (s *silentServer) accept(t *testing.T) net.Conn {
	t.Helper()
	select {
	case c := <-s.conns:
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("the NFS client did not connect")
		return nil
	}
}

func (s *silentServer) close() {
	s.ln.Close()
	for {
		select {
		case c := <-s.conns:
			c.Close()
		default:
			return
		}
	}
}

// rpcReply returns an RPC reply record (RFC 5531) to a call that the client
// never made, which it reads and discards.
func rpcReply() []byte {
	body := binary.BigEndian.AppendUint32(nil, 0x5ca1ab1e) // xid
	for _, v := range []uint32{1, 0, 0, 0, 0} {            // REPLY, MSG_ACCEPTED, AUTH_NONE, empty verifier, SUCCESS
		body = binary.BigEndian.AppendUint32(body, v)
	}
	return append(binary.BigEndian.AppendUint32(nil, 1<<31|uint32(len(body))), body...)
}

// TestKernelSockets checks that the connections of the NFS client of the
// kernel, which it opens from a kernel worker and holds without a file,
// belong to the kernel: a new connection, and one opened before the tracer
// started, which no process can be found holding. The server answers
// nothing, so that the mount hangs with its connection open; nothing is
// mounted.
func TestKernelSockets(t *testing.T) {
	requireNFSClient(t)
	srv := newSilentServer(t)
	port := srv.ln.Addr().(*net.TCPAddr).AddrPort()
	defer srv.close()
	dir := t.TempDir()

	tr := newTestTracer(t)
	mounted := make(chan error, 1)
	go func() {
		opts := fmt.Sprintf("vers=4.2,proto=tcp,addr=127.0.0.1,clientaddr=127.0.0.1,port=%d,soft,timeo=100,retrans=2", port.Port())
		mounted <- unix.Mount("127.0.0.1:/", dir, "nfs4", 0, opts)
	}()
	defer func() {
		srv.close()
		select {
		case err := <-mounted:
			if err == nil {
				unix.Unmount(dir, unix.MNT_DETACH)
			}
		case <-time.After(time.Minute):
			t.Log("the mount did not return")
		}
	}()
	conn := srv.accept(t)
	time.Sleep(100 * time.Millisecond)

	snap, err := tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	checkKernelFlow(t, "new", snap.Flows, port.Port(), func(f *Flow) bool { return f.Conns >= 1 })
	tr.Close()

	// The connection is adopted by a tracer started now.
	tr = newTestTracer(t)
	reply := rpcReply()
	if _, err := conn.Write(reply); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	snap, err = tr.Collect()
	if err != nil {
		t.Fatal(err)
	}
	checkKernelFlow(t, "adopted", snap.Flows, port.Port(), func(f *Flow) bool {
		return f.OpenConns >= 1 && f.BytesRecv == uint64(len(reply))
	})
}

// checkKernelFlow checks that the outgoing TCP flows to port belong to the
// kernel and that together they satisfy ok.
func checkKernelFlow(t *testing.T, what string, flows []Flow, port uint16, ok func(*Flow) bool) {
	t.Helper()
	var sum *Flow
	for i := range flows {
		f := &flows[i]
		if f.Direction != DirOut || f.Proto != ProtoTCP || f.Port != port {
			continue
		}
		if !KernelOwned(f.Comm, f.CgroupID) || f.PID != 0 {
			t.Errorf("%s connection: flow %v->%v:%d belongs to %q/%d/%d, want the kernel",
				what, f.LocalAddr, f.RemoteAddr, f.Port, f.Comm, f.CgroupID, f.PID)
		}
		if sum == nil {
			sum = &Flow{FlowKey: f.FlowKey}
		}
		sum.FlowStats.Add(f.FlowStats)
	}
	if sum == nil {
		t.Fatalf("%s connection: no outgoing flow to %d in %+v", what, port, flows)
	}
	if !ok(sum) {
		t.Errorf("%s connection: stats %+v", what, sum.FlowStats)
	}
}
