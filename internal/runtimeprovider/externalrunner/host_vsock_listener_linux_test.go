//go:build linux

package externalrunner

import (
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestHostVSockAcceptedStreamsAreNonblockingForDeadlines(t *testing.T) {
	if hostVSockAcceptFlags&unix.SOCK_NONBLOCK == 0 {
		t.Fatal("host VSOCK accept must request nonblocking streams for Go deadline support")
	}
	if hostVSockAcceptFlags&unix.SOCK_CLOEXEC == 0 {
		t.Fatal("host VSOCK accept must close accepted streams across exec")
	}
}

func TestRawHostVSockListenerCloseUnblocksAccept(t *testing.T) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "listener.sock")
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	listener := &rawHostVSockListener{fd: fd, address: hostVSockAddr{cid: 2, port: 41000}}
	result := make(chan error, 1)
	go func() {
		_, acceptErr := listener.Accept()
		result <- acceptErr
	}()
	time.Sleep(20 * time.Millisecond)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("listener close did not unblock Accept")
	}
}
