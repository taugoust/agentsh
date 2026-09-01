//go:build linux

package permissiongate

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// verifyPermissionGatePeer binds the one-shot rendezvous to the exact process
// launched by AgentSH. A same-user process that discovers the short-lived
// socket path cannot race Pi and acquire command-authorization authority.
func verifyPermissionGatePeer(connection *net.UnixConn, expectedPID int) error {
	if connection == nil || expectedPID <= 0 {
		return errors.New("invalid permission gate peer claim")
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return fmt.Errorf("access peer socket: %w", err)
	}
	var credentials *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return fmt.Errorf("inspect peer socket: %w", err)
	}
	if controlErr != nil {
		return fmt.Errorf("read peer credentials: %w", controlErr)
	}
	if credentials == nil || int(credentials.Pid) != expectedPID {
		actualPID := 0
		if credentials != nil {
			actualPID = int(credentials.Pid)
		}
		return fmt.Errorf("peer PID %d does not match launched PID %d", actualPID, expectedPID)
	}
	return nil
}
