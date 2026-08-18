//go:build linux

package nethelper

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestPollProcessIdentityRetriesEINTR(t *testing.T) {
	calls := 0
	fds := []unix.PollFd{{Fd: 7, Events: unix.POLLIN}}
	n, err := pollProcessIdentity(fds, func(got []unix.PollFd, timeout int) (int, error) {
		calls++
		if timeout != 0 || len(got) != 1 || got[0].Fd != 7 {
			t.Fatalf("poll args = (%+v, %d)", got, timeout)
		}
		if calls == 1 {
			return 0, unix.EINTR
		}
		return 0, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || calls != 2 {
		t.Fatalf("poll result = (%d, %d calls), want (0, 2 calls)", n, calls)
	}
}
