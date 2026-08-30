//go:build linux

package guestcontrol

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

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

func dialHostVSock(ctx context.Context, cid, port uint32) (controlConn, error) {
	if cid != HostVSockCID || port < 1024 || port > 65535 {
		return nil, fmt.Errorf("guest egress VSOCK endpoint is invalid")
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("create guest egress VSOCK client: %w", err)
	}
	connected := false
	defer func() {
		if !connected {
			_ = unix.Close(fd)
		}
	}()
	address := &unix.SockaddrVM{CID: cid, Port: port}
	if err := unix.Connect(fd, address); err != nil && err != unix.EINPROGRESS {
		return nil, fmt.Errorf("connect guest egress VSOCK: %w", err)
	} else if err == unix.EINPROGRESS {
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			timeout := 100
			if deadline, ok := ctx.Deadline(); ok {
				remaining := time.Until(deadline)
				if remaining <= 0 {
					return nil, context.DeadlineExceeded
				}
				if millis := int(remaining.Milliseconds()); millis < timeout {
					timeout = max(millis, 1)
				}
			}
			ready, pollErr := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}, timeout)
			if pollErr == unix.EINTR {
				continue
			}
			if pollErr != nil {
				return nil, fmt.Errorf("poll guest egress VSOCK: %w", pollErr)
			}
			if ready == 0 {
				continue
			}
			connectErr, socketErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
			if socketErr != nil {
				return nil, fmt.Errorf("inspect guest egress VSOCK connection: %w", socketErr)
			}
			if connectErr != 0 {
				return nil, fmt.Errorf("connect guest egress VSOCK: %w", unix.Errno(connectErr))
			}
			break
		}
	}
	connected = true
	return newVSockConn(fd, "agentsh-guest-egress-vsock"), nil
}

func dialVSock(ctx context.Context, cid, port uint32) (controlConn, error) {
	if cid < 3 || cid == ^uint32(0) || port < 1024 || port > 65535 {
		return nil, fmt.Errorf("guest control VSOCK endpoint is invalid")
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("create guest control VSOCK client: %w", err)
	}
	connected := false
	defer func() {
		if !connected {
			_ = unix.Close(fd)
		}
	}()
	address := &unix.SockaddrVM{CID: cid, Port: port}
	if err := unix.Connect(fd, address); err != nil && err != unix.EINPROGRESS {
		return nil, fmt.Errorf("connect guest control VSOCK: %w", err)
	} else if err == unix.EINPROGRESS {
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			timeout := 100
			if deadline, ok := ctx.Deadline(); ok {
				remaining := time.Until(deadline)
				if remaining <= 0 {
					return nil, context.DeadlineExceeded
				}
				if millis := int(remaining.Milliseconds()); millis < timeout {
					timeout = max(millis, 1)
				}
			}
			ready, pollErr := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}, timeout)
			if pollErr == unix.EINTR {
				continue
			}
			if pollErr != nil {
				return nil, fmt.Errorf("poll guest control VSOCK: %w", pollErr)
			}
			if ready == 0 {
				continue
			}
			connectErr, socketErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
			if socketErr != nil {
				return nil, fmt.Errorf("inspect guest control VSOCK connection: %w", socketErr)
			}
			if connectErr != 0 {
				return nil, fmt.Errorf("connect guest control VSOCK: %w", unix.Errno(connectErr))
			}
			break
		}
	}
	connected = true
	return newVSockConn(fd, "agentsh-host-control-vsock"), nil
}

type vsockConn struct {
	*os.File
	closeOnce sync.Once
	closeErr  error
}

func newVSockConn(fd int, name string) *vsockConn {
	return &vsockConn{File: os.NewFile(uintptr(fd), name)}
}

func (c *vsockConn) Close() error {
	if c == nil || c.File == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		shutdownErr := unix.Shutdown(int(c.Fd()), unix.SHUT_RDWR)
		if shutdownErr == unix.ENOTCONN || shutdownErr == unix.EINVAL {
			shutdownErr = nil
		}
		c.closeErr = errors.Join(shutdownErr, c.File.Close())
	})
	return c.closeErr
}

func acceptVSock(fd int) (controlConn, error) {
	accepted, _, err := unix.Accept4(fd, unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
	if err != nil {
		return nil, err
	}
	return newVSockConn(accepted, "agentsh-guest-control-vsock"), nil
}

func closeVSock(fd int) error {
	shutdownErr := unix.Shutdown(fd, unix.SHUT_RDWR)
	if shutdownErr == unix.ENOTCONN || shutdownErr == unix.EINVAL {
		shutdownErr = nil
	}
	return errors.Join(shutdownErr, unix.Close(fd))
}
