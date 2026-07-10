//go:build linux

package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/wraphandoff"
	"github.com/agentsh/agentsh/pkg/types"
	"golang.org/x/sys/unix"
)

func TestConfigureWrapCommandBoundaryAppliesFixedLinuxLaunchAttributes(t *testing.T) {
	attr := &syscall.SysProcAttr{}
	requirements := &types.LinuxCommandJailRequirements{
		Required:             true,
		UserNamespace:        true,
		MountNamespace:       true,
		PIDNamespace:         true,
		CgroupNamespace:      true,
		IPCNamespace:         true,
		MapCurrentUserToRoot: true,
		ParentDeathSignal:    "SIGKILL",
		PrivateProc:          true,
		HideCgroupFS:         true,
		HideControlPaths:     true,
		CloseNonStdioFDs:     true,
		DropCapabilities:     true,
		NoNewPrivileges:      true,
	}
	if err := configureWrapCommandBoundary(attr, requirements); err != nil {
		t.Fatalf("configure wrap command boundary: %v", err)
	}
	wantFlags := uintptr(unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWCGROUP | unix.CLONE_NEWIPC)
	if attr.Cloneflags&wantFlags != wantFlags {
		t.Fatalf("clone flags = %#x, want all %#x", attr.Cloneflags, wantFlags)
	}
	if attr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("parent-death signal = %v, want SIGKILL", attr.Pdeathsig)
	}
	if len(attr.UidMappings) != 1 || len(attr.GidMappings) != 1 || attr.GidMappingsEnableSetgroups {
		t.Fatalf("uid/gid mappings are incomplete: uid=%+v gid=%+v setgroups=%t", attr.UidMappings, attr.GidMappings, attr.GidMappingsEnableSetgroups)
	}
}

func TestStripEnvKey(t *testing.T) {
	in := []string{"A=1", "AGENTSH_WRAPPER_LOG_FD=9", "B=2", "AGENTSH_WRAPPER_LOG_FD=10"}
	out := stripEnvKey(in, "AGENTSH_WRAPPER_LOG_FD")
	want := []string{"A=1", "B=2"}
	if len(out) != len(want) || out[0] != want[0] || out[1] != want[1] {
		t.Fatalf("stripEnvKey = %v, want %v", out, want)
	}
}

func TestForwardNotifyFDWithPIDWaitsForServerOK(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "notify.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		unixConn := conn.(*net.UnixConn)
		if err := unixConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			serverDone <- err
			return
		}
		fd, meta, hasMeta, err := wraphandoff.RecvNotifyFD(unixConn)
		if err != nil {
			serverDone <- err
			return
		}
		_ = fd.Close()
		if !hasMeta || meta.WrapperPID != 2468 || !meta.CommandJail {
			serverDone <- fmt.Errorf("metadata = %+v, hasMeta=%v", meta, hasMeta)
			return
		}
		serverDone <- wraphandoff.WriteStatus(unixConn, true)
	}()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	if err := forwardNotifyFDWithPID(socketPath, int(r.Fd()), 2468, true); err != nil {
		t.Fatalf("forward: %v", err)
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for server")
	}
}

func TestForwardNotifyFDWithPIDRejectStatusReturnsError(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "notify.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		unixConn := conn.(*net.UnixConn)
		if err := unixConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			serverDone <- err
			return
		}
		fd, _, _, err := wraphandoff.RecvNotifyFD(unixConn)
		if err == nil {
			_ = fd.Close()
		}
		if err := wraphandoff.WriteStatus(unixConn, false); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	if err := forwardNotifyFDWithPID(socketPath, int(r.Fd()), 2468, false); err == nil {
		t.Fatal("expected reject status error")
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for server")
	}
}

func TestForwardNotifyFDWithPIDTimeoutReturnsError(t *testing.T) {
	origTimeout := notifySetupStatusTimeout
	notifySetupStatusTimeout = 20 * time.Millisecond
	t.Cleanup(func() { notifySetupStatusTimeout = origTimeout })

	dir := t.TempDir()
	socketPath := filepath.Join(dir, "notify.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	releaseServer := make(chan struct{})
	defer close(releaseServer)
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		unixConn := conn.(*net.UnixConn)
		if err := unixConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			serverDone <- err
			return
		}
		fd, _, _, err := wraphandoff.RecvNotifyFD(unixConn)
		if err != nil {
			serverDone <- err
			return
		}
		_ = fd.Close()
		serverDone <- nil
		<-releaseServer
	}()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	forwardDone := make(chan error, 1)
	go func() {
		forwardDone <- forwardNotifyFDWithPID(socketPath, int(r.Fd()), 2468, false)
	}()

	select {
	case err = <-forwardDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for forwardNotifyFDWithPID")
	}
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out waiting for notify setup status") {
		t.Fatalf("error = %v, want timeout status error", err)
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for server")
	}
}
