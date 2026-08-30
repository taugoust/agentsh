//go:build linux

package externalrunner

import (
	"testing"

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
