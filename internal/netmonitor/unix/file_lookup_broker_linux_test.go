//go:build linux && cgo

package unix

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	lookupproto "github.com/agentsh/agentsh/internal/filelookup"
	"golang.org/x/sys/unix"
)

func TestFileLookupBrokerTypedRoundTrip(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	server := os.NewFile(uintptr(fds[0]), "fake-wrapper-broker")
	endpoint := os.NewFile(uintptr(fds[1]), "supervisor-broker")
	defer server.Close()
	hello := lookupproto.EncodeHello(lookupproto.Hello{
		WrapperPID: uint32(os.Getpid()), PayloadPID: uint32(os.Getpid()),
		MaxPacketBytes: lookupproto.MaxPacketBytes, WorkerTimeoutMS: 200,
	})
	if _, err := unix.SendmsgN(int(server.Fd()), hello, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	broker, err := NewFileLookupBroker(FileLookupBrokerConfig{
		Endpoint: endpoint, ExpectedWrapperPID: os.Getpid(),
		ExpectedPayloadPID: os.Getpid(), Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()

	done := make(chan error, 1)
	go func() {
		packet := make([]byte, lookupproto.MaxPacketBytes)
		n, _, flags, _, recvErr := unix.Recvmsg(int(server.Fd()), packet, nil, 0)
		if recvErr != nil {
			done <- recvErr
			return
		}
		if flags&unix.MSG_TRUNC != 0 {
			done <- unix.EMSGSIZE
			return
		}
		request, decodeErr := lookupproto.DecodeRequest(packet[:n])
		if decodeErr != nil {
			done <- decodeErr
			return
		}
		response, encodeErr := lookupproto.EncodeResult(lookupproto.Result{
			ID: request.ID, Class: lookupproto.ClassAbsent, Reason: lookupproto.ReasonNone, Errno: int32(unix.ENOENT),
		})
		if encodeErr != nil {
			done <- encodeErr
			return
		}
		_, sendErr := unix.SendmsgN(int(server.Fd()), response, nil, nil, 0)
		done <- sendErr
	}()

	request := FileLookupRequest{
		TID: os.Getpid(), Syscall: unix.SYS_OPENAT, DirFD: int32(unix.AT_FDCWD),
		RawPath:               filepath.Join(string(filepath.Separator), "definitely-missing"),
		ResolvedPath:          filepath.Join(string(filepath.Separator), "definitely-missing"),
		PathnameNULTerminated: true,
	}
	result := broker.ProbeFileLookup(context.Background(), request)
	if result.Class != LookupAbsent || result.Errno != int32(unix.ENOENT) || result.Reason != LookupReasonNone {
		t.Fatalf("result = %+v", result)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestFileLookupBrokerRejectsIneligibleWithoutSending(t *testing.T) {
	var probe FileLookupProbe = &lineageFileLookupBroker{}
	result := probe.ProbeFileLookup(context.Background(), FileLookupRequest{})
	if result.Class != LookupUnknown || result.Reason != LookupReasonIneligible {
		t.Fatalf("result = %+v", result)
	}
}
