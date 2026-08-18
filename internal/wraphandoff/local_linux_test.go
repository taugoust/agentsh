//go:build linux

package wraphandoff

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func localFiles(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	left := os.NewFile(uintptr(fds[0]), "left")
	right := os.NewFile(uintptr(fds[1]), "right")
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	return left, right
}

func TestLocalLineagePreludeCarriesKernelCredentials(t *testing.T) {
	sender, receiver := localFiles(t)
	if err := EnableLocalCredentials(int(receiver.Fd())); err != nil {
		t.Fatal(err)
	}
	if err := SendLocalPrelude(int(sender.Fd()), LocalMetadata{CommandJail: true}); err != nil {
		t.Fatal(err)
	}
	message, err := RecvLocalPrelude(receiver)
	if err != nil {
		t.Fatal(err)
	}
	defer message.Close()
	if message.Sender == nil || int(message.Sender.Pid) != os.Getpid() {
		t.Fatalf("sender = %#v, want pid %d", message.Sender, os.Getpid())
	}
	if !message.Metadata.CommandJail || message.NotifyFD != nil || message.FileLookup != nil {
		t.Fatalf("unexpected prelude: %+v", message)
	}
}

func TestLocalPreludeSendRetriesEINTR(t *testing.T) {
	calls := 0
	err := sendLocalFrame(7, []byte("frame"), func(_ int, payload, _ []byte, _ unix.Sockaddr, _ int) (int, error) {
		calls++
		if calls == 1 {
			return 0, unix.EINTR
		}
		return len(payload), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("send calls = %d, want 2", calls)
	}
}

func TestLocalPreludeReceiveRetriesEINTR(t *testing.T) {
	sender, receiver := localFiles(t)
	if err := EnableLocalCredentials(int(receiver.Fd())); err != nil {
		t.Fatal(err)
	}
	if err := SendLocalPrelude(int(sender.Fd()), LocalMetadata{CommandJail: true}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	message, err := recvLocalMessageWith(receiver, localFramePrelude, func(fd int, payload, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
		calls++
		if calls == 1 {
			return 0, 0, 0, nil, unix.EINTR
		}
		return unix.Recvmsg(fd, payload, oob, flags)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer message.Close()
	if calls != 2 {
		t.Fatalf("recv calls = %d, want 2", calls)
	}
	if message.Sender == nil || !message.Metadata.CommandJail {
		t.Fatalf("unexpected prelude: %+v", message)
	}
}

func TestLocalPayloadDescriptorOrderIsFixed(t *testing.T) {
	sender, receiver := localFiles(t)
	if err := EnableLocalCredentials(int(receiver.Fd())); err != nil {
		t.Fatal(err)
	}
	notifyR, notifyW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer notifyR.Close()
	defer notifyW.Close()
	lookupR, lookupW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer lookupR.Close()
	defer lookupW.Close()

	frame := encodeLocalFrame(localFramePayload, LocalMetadata{FileLookupReady: true})
	rights := unix.UnixRights(int(notifyR.Fd()), int(lookupR.Fd()))
	if err := unix.Sendmsg(int(sender.Fd()), frame, rights, nil, 0); err != nil {
		t.Fatal(err)
	}
	message, err := RecvLocalPayload(receiver)
	if err != nil {
		t.Fatal(err)
	}
	defer message.Close()
	if message.NotifyFD == nil || message.FileLookup == nil || !message.Metadata.FileLookupReady {
		t.Fatalf("incomplete payload message: %+v", message)
	}
}
