package agent

import (
	"fmt"
	"net"
	"os"
)

// notify sends a state, e.g. "READY=1", to the service manager over the
// socket in NOTIFY_SOCKET, as sd_notify(3) does. Without NOTIFY_SOCKET it
// does nothing: the agent was not started by systemd with Type=notify.
// The protocol is one datagram on a Unix socket, so it is written here
// rather than taken from a library.
func notify(state string) error {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return nil
	}
	// A path, or a name in the abstract namespace after "@", which the
	// net package translates. systemd also accepts AF_VSOCK addresses
	// ("vsock:"), for services in virtual machines, which the agent is not.
	if addr[0] != '/' && addr[0] != '@' {
		return fmt.Errorf("unsupported NOTIFY_SOCKET %q", addr)
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("connecting to NOTIFY_SOCKET: %w", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(state)); err != nil {
		return fmt.Errorf("writing %q to NOTIFY_SOCKET: %w", state, err)
	}
	return nil
}
