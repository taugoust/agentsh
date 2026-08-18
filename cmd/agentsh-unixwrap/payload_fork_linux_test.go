//go:build linux && cgo

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"github.com/agentsh/agentsh/internal/wraphandoff"
	"golang.org/x/sys/unix"
)

func TestPayloadForkInstallsNotifyOnlyInExactChild(t *testing.T) {
	if err := unixmon.DetectSupport(); err != nil {
		t.Skipf("seccomp user notification unavailable: %v", err)
	}
	before := selfSeccompFilterCount(t)
	waitKillable := false
	program, err := unixmon.PrepareFilterProgramWithConfig(unixmon.FilterConfig{
		UnixSocketEnabled: true, WaitKillable: &waitKillable,
	})
	if err != nil {
		t.Fatal(err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	supervisor := os.NewFile(uintptr(fds[0]), "test-supervisor")
	childControl := os.NewFile(uintptr(fds[1]), "test-child-control")
	defer supervisor.Close()
	defer childControl.Close()
	if err := wraphandoff.EnableLocalCredentials(int(supervisor.Fd())); err != nil {
		t.Fatal(err)
	}

	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Fatal(err)
	}
	child, err := forkPayload(payloadForkConfig{
		controlFD: int(childControl.Fd()), brokerParentFD: -1, brokerTransferFD: -1,
		baseProgram: program.BPFProgram(), waitKillable: false,
		execPath: truePath,
		argv:     []string{"true"}, env: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	_ = childControl.Close()
	attestation, err := child.readAttestation()
	if err != nil {
		t.Fatal(err)
	}
	if attestation.PID != child.pid || attestation.TID != child.pid {
		t.Fatalf("attestation = %+v, child pid = %d", attestation, child.pid)
	}
	if err := child.sendLookupReadiness(false); err != nil {
		t.Fatal(err)
	}
	handoff, err := wraphandoff.RecvLocalPayload(supervisor)
	if err != nil {
		t.Fatal(err)
	}
	defer handoff.Close()
	if handoff.Sender == nil || int(handoff.Sender.Pid) != child.pid || handoff.NotifyFD == nil || handoff.FileLookup != nil {
		t.Fatalf("handoff = %+v", handoff)
	}
	if n, err := supervisor.Write([]byte{1}); err != nil || n != 1 {
		t.Fatalf("write ACK n=%d err=%v", n, err)
	}
	if err := child.waitHandoffStatus(); err != nil {
		t.Fatal(err)
	}
	if err := child.release(); err != nil {
		t.Fatal(err)
	}
	if !waitExactChild(child.pid, 2*time.Second) {
		t.Fatal("payload child did not exit")
	}
	if after := selfSeccompFilterCount(t); after != before {
		t.Fatalf("trusted parent seccomp filter count changed from %d to %d", before, after)
	}
}

func selfSeccompFilterCount(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(string(filepath.Separator), "proc", "self", "status"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Seccomp_filters:") {
			fields := strings.Fields(line)
			value, err := strconv.Atoi(fields[len(fields)-1])
			if err != nil {
				t.Fatal(err)
			}
			return value
		}
	}
	return 0
}
