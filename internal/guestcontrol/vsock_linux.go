//go:build linux

package guestcontrol

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func ListenVSock(port uint32) (*Server, error) {
	if port < 1024 || port > 65535 {
		return nil, fmt.Errorf("guest control VSOCK port is invalid")
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("create guest control VSOCK: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = unix.Close(fd)
		}
	}()
	address := &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}
	if err := unix.Bind(fd, address); err != nil {
		return nil, fmt.Errorf("bind guest control VSOCK: %w", err)
	}
	if err := unix.Listen(fd, 16); err != nil {
		return nil, fmt.Errorf("listen on guest control VSOCK: %w", err)
	}
	localCID := uint32(0)
	if bound, err := unix.Getsockname(fd); err == nil {
		if vm, isVM := bound.(*unix.SockaddrVM); isVM {
			localCID = vm.CID
		}
	}
	ok = true
	return &Server{fd: fd, localCID: localCID, port: port}, nil
}

func acceptVSock(fd int) (*os.File, error) {
	accepted, _, err := unix.Accept4(fd, unix.SOCK_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(accepted), "agentsh-guest-control-vsock"), nil
}

func closeVSock(fd int) error {
	return unix.Close(fd)
}
