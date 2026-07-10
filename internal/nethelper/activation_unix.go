//go:build !windows

package nethelper

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// ListenSystemdActivation preserves the version-1 API and expects the socket to
// be owned by the current UID (or root). Root helper services should call
// ListenSystemdActivationForUID with their configured supervisor UID.
func ListenSystemdActivation(socketPath string) (net.Listener, bool, error) {
	return listenSystemdActivation(socketPath, uint32(os.Getuid()), true)
}

// ListenSystemdActivationForUID accepts exactly one named AF_UNIX/SOCK_STREAM
// activation fd and requires the filesystem socket to be owned by expectedUID.
func ListenSystemdActivationForUID(socketPath string, expectedUID uint32) (net.Listener, bool, error) {
	return listenSystemdActivation(socketPath, expectedUID, false)
}

func listenSystemdActivation(socketPath string, expectedUID uint32, allowRootOwner bool) (net.Listener, bool, error) {
	pidText := strings.TrimSpace(os.Getenv("LISTEN_PID"))
	fdsText := strings.TrimSpace(os.Getenv("LISTEN_FDS"))
	if pidText == "" && fdsText == "" {
		return nil, false, nil
	}
	pid, err := strconv.Atoi(pidText)
	if err != nil || pid != os.Getpid() {
		return nil, false, fmt.Errorf("invalid systemd socket activation LISTEN_PID")
	}
	fds, err := strconv.Atoi(fdsText)
	if err != nil || fds != 1 {
		return nil, false, fmt.Errorf("expected exactly one systemd activation fd, got %q", fdsText)
	}
	if names := strings.TrimSpace(os.Getenv("LISTEN_FDNAMES")); names != "control" {
		return nil, false, fmt.Errorf("expected systemd activation fd name control, got %q", names)
	}
	if err := validateListenSocketPath(socketPath); err != nil {
		return nil, false, err
	}
	if err := validateSocketParent(filepath.Dir(socketPath)); err != nil {
		return nil, false, err
	}
	if err := validateSocketFileOwner(socketPath, expectedUID, allowRootOwner); err != nil {
		return nil, false, err
	}

	file := os.NewFile(uintptr(3), "agentsh-nethelper.socket")
	if file == nil {
		return nil, false, fmt.Errorf("systemd activation fd 3 is unavailable")
	}
	defer file.Close()
	fdInfo, err := file.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("stat systemd activation fd: %w", err)
	}
	// Do not compare fstat(fd) with stat(socketPath): on Linux the live
	// AF_UNIX socket uses a socketfs inode while its pathname is a distinct
	// filesystem socket inode. Path ownership/canonicalization above and the
	// kernel-reported bound address below establish the activation identity.
	if fdInfo.Mode()&os.ModeSocket == 0 {
		return nil, false, fmt.Errorf("systemd activation fd is not a socket")
	}
	socketType, err := unix.GetsockoptInt(int(file.Fd()), unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return nil, false, fmt.Errorf("inspect systemd activation fd type: %w", err)
	}
	if socketType != unix.SOCK_STREAM {
		return nil, false, fmt.Errorf("systemd activation fd must be SOCK_STREAM")
	}
	accepting, err := unix.GetsockoptInt(int(file.Fd()), unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	if err != nil {
		return nil, false, fmt.Errorf("inspect systemd activation listener state: %w", err)
	}
	if accepting != 1 {
		return nil, false, fmt.Errorf("systemd activation fd is not listening")
	}
	address, err := unix.Getsockname(int(file.Fd()))
	if err != nil {
		return nil, false, fmt.Errorf("read systemd activation socket address: %w", err)
	}
	unixAddress, ok := address.(*unix.SockaddrUnix)
	if !ok || strings.TrimSpace(unixAddress.Name) == "" || filepath.Clean(unixAddress.Name) != filepath.Clean(socketPath) {
		return nil, false, fmt.Errorf("systemd activation fd has unexpected Unix socket path")
	}
	unix.CloseOnExec(int(file.Fd()))

	ln, err := net.FileListener(file)
	if err != nil {
		return nil, false, fmt.Errorf("use systemd activation listener: %w", err)
	}
	unixListener, ok := ln.(*net.UnixListener)
	if !ok || filepath.Clean(unixListener.Addr().String()) != filepath.Clean(socketPath) {
		_ = ln.Close()
		return nil, false, fmt.Errorf("activated listener is not the configured Unix socket")
	}
	for _, name := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		_ = os.Unsetenv(name)
	}
	return ln, true, nil
}
