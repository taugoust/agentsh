//go:build linux

package externalrunner

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type hostVSockAddr struct {
	cid  uint32
	port uint32
}

func (a hostVSockAddr) Network() string { return "vsock" }
func (a hostVSockAddr) String() string {
	return net.JoinHostPort(strconv.FormatUint(uint64(a.cid), 10), strconv.FormatUint(uint64(a.port), 10))
}
func (a hostVSockAddr) VSockCID() uint32 { return a.cid }

type hostVSockConn struct {
	*os.File
	local     hostVSockAddr
	remote    hostVSockAddr
	closeOnce sync.Once
	closeErr  error
}

func (c *hostVSockConn) LocalAddr() net.Addr  { return c.local }
func (c *hostVSockConn) RemoteAddr() net.Addr { return c.remote }
func (c *hostVSockConn) Close() error {
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

const hostVSockAcceptFlags = unix.SOCK_CLOEXEC | unix.SOCK_NONBLOCK

type rawHostVSockListener struct {
	fd        int
	address   hostVSockAddr
	closeOnce sync.Once
	closeErr  error
}

func listenHostEgressVSock(port, expectedCID uint32, expectedToken string, authenticationTimeout time.Duration) (net.Listener, error) {
	if port < 1024 || port > 65535 {
		return nil, fmt.Errorf("host egress VSOCK port is invalid")
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("create host egress VSOCK listener: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = unix.Close(fd)
		}
	}()
	address := &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}
	if err := unix.Bind(fd, address); err != nil {
		return nil, fmt.Errorf("bind host egress VSOCK listener: %w", err)
	}
	if err := unix.Listen(fd, 64); err != nil {
		return nil, fmt.Errorf("listen on host egress VSOCK: %w", err)
	}
	localCID := uint32(unix.VMADDR_CID_HOST)
	if bound, err := unix.Getsockname(fd); err == nil {
		if vm, isVM := bound.(*unix.SockaddrVM); isVM && vm.CID != unix.VMADDR_CID_ANY {
			localCID = vm.CID
		}
	}
	raw := &rawHostVSockListener{fd: fd, address: hostVSockAddr{cid: localCID, port: port}}
	verified, err := verifyVSockPeerListener(raw, expectedCID, expectedToken, authenticationTimeout)
	if err != nil {
		return nil, err
	}
	ok = true
	return verified, nil
}

func (l *rawHostVSockListener) Accept() (net.Conn, error) {
	for {
		fd, peer, err := unix.Accept4(l.fd, hostVSockAcceptFlags)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		vm, ok := peer.(*unix.SockaddrVM)
		if !ok {
			_ = unix.Close(fd)
			continue
		}
		file := os.NewFile(uintptr(fd), "agentsh-host-egress-vsock")
		if file == nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("wrap accepted host egress VSOCK stream")
		}
		return &hostVSockConn{
			File:   file,
			local:  l.address,
			remote: hostVSockAddr{cid: vm.CID, port: vm.Port},
		}, nil
	}
}

func (l *rawHostVSockListener) Addr() net.Addr { return l.address }

func (l *rawHostVSockListener) Close() error {
	if l == nil || l.fd < 0 {
		return nil
	}
	l.closeOnce.Do(func() {
		shutdownErr := unix.Shutdown(l.fd, unix.SHUT_RDWR)
		if shutdownErr == unix.ENOTCONN || shutdownErr == unix.EINVAL {
			shutdownErr = nil
		}
		l.closeErr = errors.Join(shutdownErr, unix.Close(l.fd))
	})
	return l.closeErr
}
