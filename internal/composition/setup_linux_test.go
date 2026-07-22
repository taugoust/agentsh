//go:build linux

package composition

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReceivedSetupProvesDescendantRightsAndDeniedIdentity(t *testing.T) {
	root := t.TempDir()
	childPath := root + "/child"
	if err := os.WriteFile(childPath, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	rootFile, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer rootFile.Close()
	childFile, err := os.Open(childPath)
	if err != nil {
		t.Fatal(err)
	}
	defer childFile.Close()
	setup := &ReceivedSetup{Objects: []ReceivedSetupObject{
		{SetupObject: SetupObject{Kind: SetupObjectPolicy, Path: root, Rights: 7}, File: rootFile},
		{SetupObject: SetupObject{Kind: SetupObjectPolicyDeny, Path: childPath}, File: childFile},
	}}
	rights, matched, err := setup.PolicyRights(childFile, childPath)
	if err != nil || !matched || rights != 7 {
		t.Fatalf("descendant rights = %d matched=%v err=%v", rights, matched, err)
	}
	denied, err := setup.DeniedPolicyObject(childFile, childPath)
	if err != nil || !denied {
		t.Fatalf("denied identity = %v err=%v", denied, err)
	}
}

func TestCompositionSetupTransfersExactObjects(t *testing.T) {
	directory := t.TempDir()
	object, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	sender := os.NewFile(uintptr(fds[0]), "setup-sender")
	receiver := os.NewFile(uintptr(fds[1]), "setup-receiver")
	defer sender.Close()
	defer receiver.Close()

	if err := SendSetup(
		sender,
		Mode,
		[]SetupObjectKind{SetupObjectPolicy, SetupObjectSyntheticRoot},
		[]string{directory, directory},
		[]uint64{7, 15},
		[]*os.File{object, object},
	); err != nil {
		t.Fatal(err)
	}
	setup, err := ReceiveSetup(receiver)
	if err != nil {
		t.Fatal(err)
	}
	defer setup.Close()
	if len(setup.Objects) != 2 {
		t.Fatalf("objects = %d", len(setup.Objects))
	}
	if setup.SenderPID != os.Getpid() || setup.SenderUID != uint32(os.Geteuid()) || setup.SenderGID != uint32(os.Getegid()) {
		t.Fatalf("sender credentials = pid:%d uid:%d gid:%d", setup.SenderPID, setup.SenderUID, setup.SenderGID)
	}
	got := setup.Objects[0]
	if got.Kind != SetupObjectPolicy || got.Path != directory || got.Rights != 7 {
		t.Fatalf("object = %+v", got.SetupObject)
	}
	var sent, received unix.Stat_t
	if err := unix.Fstat(int(object.Fd()), &sent); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fstat(int(got.File.Fd()), &received); err != nil {
		t.Fatal(err)
	}
	if sent.Dev != received.Dev || sent.Ino != received.Ino {
		t.Fatalf("received object identity (%d,%d), want (%d,%d)", received.Dev, received.Ino, sent.Dev, sent.Ino)
	}
	flags, err := unix.FcntlInt(got.File.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("received descriptor flags = %#x, err=%v", flags, err)
	}
}

func setupSocketpair(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	sender := os.NewFile(uintptr(fds[0]), "raw-setup-sender")
	receiver := os.NewFile(uintptr(fds[1]), "raw-setup-receiver")
	t.Cleanup(func() { _ = sender.Close(); _ = receiver.Close() })
	return sender, receiver
}

func rawSetupPayload(t *testing.T, object *os.File) []byte {
	t.Helper()
	metadata, err := objectMetadata(SetupObjectSyntheticRoot, filepath.Clean(object.Name()), 1, object)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(SetupMessage{Version: SetupProtocolVersion, Mode: Mode, Objects: []SetupObject{metadata}})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func sendRawSetup(t *testing.T, sender *os.File, payload []byte, fds []int, seal bool) {
	t.Helper()
	oob := append(unix.UnixRights(fds...), unix.UnixCredentials(&unix.Ucred{Pid: int32(os.Getpid()), Uid: uint32(os.Geteuid()), Gid: uint32(os.Getegid())})...)
	if n, err := unix.SendmsgN(int(sender.Fd()), payload, oob, nil, unix.MSG_NOSIGNAL); err != nil || n != len(payload) {
		t.Fatalf("raw setup send = %d/%d, err=%v", n, len(payload), err)
	}
	if seal {
		if err := unix.Shutdown(int(sender.Fd()), unix.SHUT_WR); err != nil {
			t.Fatal(err)
		}
	}
}

func setupOpenFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(string(filepath.Separator), "proc", "self", "fd"))
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestCompositionSetupRejectsDuplicateJSONField(t *testing.T) {
	object, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()
	sender, receiver := setupSocketpair(t)
	payload := rawSetupPayload(t, object)
	payload = []byte(strings.Replace(string(payload), `"mode":"`+Mode+`"`, `"mode":"`+Mode+`","mode":"`+Mode+`"`, 1))
	sendRawSetup(t, sender, payload, []int{int(object.Fd())}, true)
	if setup, err := ReceiveSetup(receiver); err == nil || !strings.Contains(err.Error(), "duplicate JSON field") {
		if setup != nil {
			setup.Close()
		}
		t.Fatalf("duplicate setup JSON error = %v", err)
	}
}

func TestCompositionSetupRejectsDuplicatePacket(t *testing.T) {
	directory := t.TempDir()
	object, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()
	sender, receiver := setupSocketpair(t)
	payload := rawSetupPayload(t, object)
	sendRawSetup(t, sender, payload, []int{int(object.Fd())}, false)
	sendRawSetup(t, sender, payload, []int{int(object.Fd())}, true)
	if setup, err := ReceiveSetup(receiver); err == nil || !strings.Contains(err.Error(), "duplicate message") {
		if setup != nil {
			setup.Close()
		}
		t.Fatalf("duplicate setup error = %v", err)
	}
}

func TestCompositionSetupRejectsDescriptorIdentityMismatch(t *testing.T) {
	first, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	sender, receiver := setupSocketpair(t)
	payload := rawSetupPayload(t, first)
	sendRawSetup(t, sender, payload, []int{int(second.Fd())}, true)
	if setup, err := ReceiveSetup(receiver); err == nil || !strings.Contains(err.Error(), "identity changed") {
		if setup != nil {
			setup.Close()
		}
		t.Fatalf("identity mismatch error = %v", err)
	}
}

func TestCompositionSetupRejectsTruncatedAncillaryDataWithoutFDLeak(t *testing.T) {
	object, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()
	sender, receiver := setupSocketpair(t)
	payload := rawSetupPayload(t, object)
	fds := make([]int, maxSetupObjects+1)
	for index := range fds {
		fds[index] = int(object.Fd())
	}
	before := setupOpenFDCount(t)
	sendRawSetup(t, sender, payload, fds, true)
	if setup, err := ReceiveSetup(receiver); err == nil || !strings.Contains(err.Error(), "truncated") {
		if setup != nil {
			setup.Close()
		}
		t.Fatalf("truncated ancillary error = %v", err)
	}
	if after := setupOpenFDCount(t); after != before {
		t.Fatalf("open fd count after ancillary truncation = %d, want %d", after, before)
	}
}

func TestCompositionSetupRejectsClosedUnpublishedEndpoint(t *testing.T) {
	sender, receiver := setupSocketpair(t)
	if err := sender.Close(); err != nil {
		t.Fatal(err)
	}
	if setup, err := ReceiveSetup(receiver); err == nil || !strings.Contains(err.Error(), "closed before publication") {
		if setup != nil {
			setup.Close()
		}
		t.Fatalf("closed setup endpoint error = %v", err)
	}
}
