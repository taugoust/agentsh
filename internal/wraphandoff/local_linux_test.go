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
