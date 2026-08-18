package filelookup

import (
	"strings"
	"testing"
)

func TestProtocolRequestRoundTripAndBounds(t *testing.T) {
	request := Request{
		ID: 9, HostTID: 100, NamespaceTID: 2, StartTime: 77,
		Operation: OperationOpenat2, DirFD: -100,
		OpenFlags: 1, OpenMode: 2, ResolveFlags: 3,
		LookupFlags: 4, StatMask: 5, AccessMode: 6, AccessFlags: 7,
		ReadlinkLen: 8, Path: "relative/path", ExpectedLabel: "profile (enforce)",
	}
	packet, err := EncodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRequest(packet)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != request {
		t.Fatalf("decoded request = %#v, want %#v", decoded, request)
	}

	request.Path = strings.Repeat("x", MaxPathBytes+1)
	if _, err := EncodeRequest(request); err == nil {
		t.Fatal("oversized path was accepted")
	}
}

func TestProtocolRejectsUnknownResultEnums(t *testing.T) {
	packet, err := EncodeResult(Result{ID: 1, Class: ClassAbsent, Reason: ReasonNone, Errno: 2})
	if err != nil {
		t.Fatal(err)
	}
	packet[16] = 0xff
	packet[17] = 0xff
	if _, err := DecodeResult(packet); err == nil {
		t.Fatal("unknown result class was accepted")
	}
}

func TestProtocolHelloRoundTrip(t *testing.T) {
	want := Hello{WrapperPID: 1, PayloadPID: 2, MaxPacketBytes: MaxPacketBytes, WorkerTimeoutMS: 200}
	got, err := DecodeHello(EncodeHello(want))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("hello = %#v, want %#v", got, want)
	}
}
