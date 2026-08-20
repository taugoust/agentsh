//go:build linux

package kernelinstall

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/wraphandoff"
	"github.com/agentsh/agentsh/internal/wrapperlog"
	"github.com/agentsh/agentsh/pkg/types"
	"golang.org/x/sys/unix"
)

// makeWrapInitHandler returns an http.HandlerFunc that serves the given
// response body and status code on POST /api/v1/sessions/.../wrap-init.
func makeWrapInitHandler(status int, resp any) (http.HandlerFunc, *int) {
	calls := new(int)
	return func(w http.ResponseWriter, r *http.Request) {
		*calls++
		if !strings.Contains(r.URL.Path, "/wrap-init") {
			http.NotFound(w, r)
			return
		}
		if status != http.StatusOK {
			http.Error(w, "server error", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}, calls
}

func baseParams(srv *httptest.Server) InstallParams {
	return InstallParams{
		ServerBaseURL: srv.URL,
		SessionID:     "test-session",
		APIKey:        "test-key",
		RealShell:     "/bin/sh",
		ShellArgs:     []string{"-c", "echo hello"},
		Env:           []string{"HOME=/tmp"},
	}
}

func serveNotifySetupStatus(ln net.Listener, okStatus bool) {
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		unixConn := conn.(*net.UnixConn)
		fd, _, _, err := wraphandoff.RecvNotifyFD(unixConn)
		if err == nil {
			_ = fd.Close()
			_ = wraphandoff.WriteStatus(unixConn, okStatus)
		}
	}()
}

// ─── Test 1: ModeOff returns ResultSkip without any HTTP call ───────────────

func TestConfigureCommandJailProcessUsesNonRootCompositionIdentity(t *testing.T) {
	attr := &syscall.SysProcAttr{}
	requirements := &types.LinuxCommandJailRequirements{
		Required:                true,
		UserNamespace:           true,
		MountNamespace:          true,
		PIDNamespace:            true,
		CgroupNamespace:         true,
		IPCNamespace:            true,
		MapCurrentUserToNonRoot: true,
		ParentDeathSignal:       "SIGKILL",
		PrivateProc:             true,
		HideCgroupFS:            true,
		HideControlPaths:        true,
		CloseNonStdioFDs:        true,
		DropCapabilities:        true,
		NoNewPrivileges:         true,
	}
	if err := configureCommandJailProcess(attr, requirements); err != nil {
		t.Fatal(err)
	}
	if attr.UidMappings[0].ContainerID != 1 || attr.GidMappings[0].ContainerID != 1 {
		t.Fatalf("non-root mappings not installed: uid=%+v gid=%+v", attr.UidMappings, attr.GidMappings)
	}
	if len(attr.AmbientCaps) != 2 || attr.AmbientCaps[0] != unix.CAP_SYS_ADMIN || attr.AmbientCaps[1] != unix.CAP_SETPCAP {
		t.Fatalf("ambient setup capabilities = %v", attr.AmbientCaps)
	}
}

func TestAssembleWrapperEnvStripsCompositionSetupFD(t *testing.T) {
	env := assembleWrapperEnv(
		[]string{"AGENTSH_COMPOSITION_SETUP_FD=91", "SAFE=1"},
		"",
		map[string]string{"AGENTSH_COMPOSITION_SETUP_FD": "92"},
		map[string]string{"AGENTSH_COMPOSITION_SETUP_FD": "93"},
	)
	for _, entry := range env {
		if strings.HasPrefix(entry, "AGENTSH_COMPOSITION_SETUP_FD=") {
			t.Fatalf("composition setup fd leaked into assembled env: %q", entry)
		}
	}
}

func TestInstall_ModeOff_ReturnsSkip(t *testing.T) {
	handler, calls := makeWrapInitHandler(200, types.WrapInitResponse{
		WrapperBinary: "/usr/bin/agentsh-unixwrap",
		NotifySocket:  "/tmp/notify.sock",
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := baseParams(srv)
	p.Mode = ModeOff

	res, err := Install(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ResultSkip {
		t.Errorf("expected ResultSkip, got %v", res.Action)
	}
	if *calls != 0 {
		t.Errorf("expected 0 HTTP calls, got %d", *calls)
	}
}

func requireUnfilteredSeccompProcess(t *testing.T) {
	t.Helper()
	if count := seccompFilterCount(); count > 0 {
		t.Skipf("requires an unfiltered process; inherited Seccomp_filters=%d (covered by the native VM check)", count)
	}
}

// ─── Test InheritedFilter: caller already has seccomp filter → ResultSkip ────

// TestInstall_AlreadyFiltered_ReturnsSkip covers the #282 root cause
// confirmed by the rc1 (commit a4de5e1) diagnostic on Runloop:
// agentsh CLI spawns unixwrap_1 (installs F1, success); unixwrap_1 execs
// the user's command which goes through the shell-shim again, and the
// shim's kernelinstall.Install is called *inside* a process tree that
// already has F1 inherited via execve. Trying to install F2 on top
// returns EFAULT on this kernel/runtime. The fix: kernelinstall must
// detect the unforgeable Seccomp:2 + Seccomp_filters>=1 signal from
// /proc/self/status and skip wrap-init entirely — the inherited filter
// is already enforcing for this process and all its descendants, so a
// second install is both redundant and harmful.
//
// We inject seccompFilterCount via a package-level var so the test can
// simulate the inherited-filter state without forking a real child
// process with a live filter installed (which would also pollute the
// Go test runner's seccomp state and break unrelated tests).
//
// The httptest handler is registered but should NOT be hit. Reaching
// it indicates the skip gate fired AFTER wrap-init was contacted, which
// would still leak server load and side-effects (notify socket creation,
// event emission) on every nested shim invocation.
func TestInstall_AlreadyFiltered_ReturnsSkip(t *testing.T) {
	handler, calls := makeWrapInitHandler(200, types.WrapInitResponse{
		WrapperBinary: "/usr/bin/agentsh-unixwrap",
		NotifySocket:  "/tmp/notify.sock",
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	orig := seccompFilterCount
	seccompFilterCount = func() int { return 1 }
	t.Cleanup(func() { seccompFilterCount = orig })

	p := baseParams(srv)
	p.Mode = ModeAuto

	res, err := Install(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ResultSkip {
		t.Errorf("expected ResultSkip, got %v (reason=%q)", res.Action, res.Reason)
	}
	if !strings.Contains(res.Reason, "already") {
		t.Errorf("expected reason to mention already-filtered state, got %q", res.Reason)
	}
	if *calls != 0 {
		t.Errorf("expected 0 HTTP calls (skip must happen before wrap-init), got %d", *calls)
	}
}

// TestInstall_AlreadyFiltered_ModeOnAlsoSkips documents that inherited-
// filter detection bypasses ModeOn's fail-closed semantics. ModeOn means
// "must install or fail" — but if a filter is *already* installed via
// inheritance, the policy intent is satisfied (the filter is
// enforcing). Treating this as fail-closed would break the entire
// nested-shim case for users who set shim_install=on, so we still skip.
func TestInstall_AlreadyFiltered_ModeOnAlsoSkips(t *testing.T) {
	handler, calls := makeWrapInitHandler(200, types.WrapInitResponse{
		WrapperBinary: "/usr/bin/agentsh-unixwrap",
		NotifySocket:  "/tmp/notify.sock",
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	orig := seccompFilterCount
	seccompFilterCount = func() int { return 1 }
	t.Cleanup(func() { seccompFilterCount = orig })

	p := baseParams(srv)
	p.Mode = ModeOn

	res, err := Install(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ResultSkip {
		t.Errorf("ModeOn must still skip when a filter is inherited; got %v", res.Action)
	}
	if *calls != 0 {
		t.Errorf("expected 0 HTTP calls, got %d", *calls)
	}
}

// TestInstall_NotFiltered_ProceedsAsBefore guards against a regression
// where the new gate accidentally fires on a clean process: when
// seccompFilterCount returns 0 (no inherited filter), the existing
// wrap-init/relay path must run — exactly the rc1 first-Load case
// (parent_comm=agentsh, caller_seccomp_state="mode=0 filter_count=0")
// that the rc1 diagnostic showed succeeding.
func TestInstall_NotFiltered_ProceedsAsBefore(t *testing.T) {
	handler, calls := makeWrapInitHandler(200, types.WrapInitResponse{}) // empty resp → ResultSkip via existing path
	srv := httptest.NewServer(handler)
	defer srv.Close()

	orig := seccompFilterCount
	seccompFilterCount = func() int { return 0 }
	t.Cleanup(func() { seccompFilterCount = orig })

	p := baseParams(srv)
	p.Mode = ModeAuto

	res, err := Install(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ResultSkip {
		t.Errorf("expected ResultSkip from empty wrap-init response, got %v", res.Action)
	}
	if *calls != 1 {
		t.Errorf("expected wrap-init to be called when no filter inherited, got %d calls", *calls)
	}
}

// ─── Test 2: ModeAuto + server 500 → ResultSkip ─────────────────────────────

func TestInstall_ModeAuto_WrapInitError_Skips(t *testing.T) {
	handler, _ := makeWrapInitHandler(500, nil)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := baseParams(srv)
	p.Mode = ModeAuto

	res, err := Install(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ResultSkip {
		t.Errorf("expected ResultSkip, got %v", res.Action)
	}
}

// ─── Test 3: ModeOn + server 500 → ResultFailClosed ─────────────────────────

func TestInstall_ModeOn_WrapInitError_FailsClosed(t *testing.T) {
	requireUnfilteredSeccompProcess(t)
	handler, _ := makeWrapInitHandler(500, nil)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := baseParams(srv)
	p.Mode = ModeOn

	res, err := Install(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ResultFailClosed {
		t.Errorf("expected ResultFailClosed, got %v", res.Action)
	}
	if res.Reason == "" {
		t.Error("expected non-empty Reason")
	}
}

// ─── Test 4: ModeAuto + empty WrapInitResponse → ResultSkip ─────────────────

func TestInstall_ModeAuto_EmptyResponse_Skips(t *testing.T) {
	handler, _ := makeWrapInitHandler(200, types.WrapInitResponse{})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := baseParams(srv)
	p.Mode = ModeAuto

	res, err := Install(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ResultSkip {
		t.Errorf("expected ResultSkip, got %v", res.Action)
	}
}

// ─── Test 5: ModeOn + empty WrapInitResponse → ResultFailClosed ─────────────

func TestInstall_ModeOn_EmptyResponse_FailsClosed(t *testing.T) {
	requireUnfilteredSeccompProcess(t)
	handler, _ := makeWrapInitHandler(200, types.WrapInitResponse{})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := baseParams(srv)
	p.Mode = ModeOn

	res, err := Install(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ResultFailClosed {
		t.Errorf("expected ResultFailClosed, got %v", res.Action)
	}
}

// ─── Test 6: AGENTSH_SIGNAL_SOCK_FD is stripped from WrapperEnv ─────────────

func TestInstall_StripsSignalSockFd(t *testing.T) {
	// Build env with signal sock fd and another var.
	env := []string{
		"AGENTSH_SIGNAL_SOCK_FD=4",
		"OTHER=x",
		"HOME=/tmp",
	}

	filtered := filterSignalSockFD(env)

	for _, e := range filtered {
		if strings.HasPrefix(e, "AGENTSH_SIGNAL_SOCK_FD=") {
			t.Errorf("AGENTSH_SIGNAL_SOCK_FD was not stripped: %q", e)
		}
	}
	found := false
	for _, e := range filtered {
		if e == "OTHER=x" {
			found = true
		}
	}
	if !found {
		t.Error("OTHER=x was unexpectedly removed")
	}
}

// ─── Test 6b: AGENTSH_SIGNAL_SOCK_FD is stripped from p.Env (not just WrapperEnv) ─

// TestInstall_StripsSignalSockFdFromPEnv verifies that a stale
// AGENTSH_SIGNAL_SOCK_FD in p.Env (inherited from a parent context) is removed
// before being passed to the wrapper, even when WrapperEnv has no such entry.
// We verify this by running the full relay with a p.Env containing a stale fd
// value and asserting the wrapper's environment (via the fake wrapper printing
// its own env) contains no AGENTSH_SIGNAL_SOCK_FD entry.
func TestFilterShimInternalEnv(t *testing.T) {
	in := []string{
		"AGENTSH_SIGNAL_SOCK_FD=4",
		"AGENTSH_UNIXWRAP_ARGV0=/bin/stale",
		"OTHER=x",
		"HOME=/tmp",
		"AGENTSH_UNIXWRAP_ARGV0_NOT_OURS=keep", // prefix-not-equal must be preserved
	}
	out := filterShimInternalEnv(in)
	for _, e := range out {
		if strings.HasPrefix(e, "AGENTSH_SIGNAL_SOCK_FD=") {
			t.Errorf("AGENTSH_SIGNAL_SOCK_FD not stripped: %q", e)
		}
		if strings.HasPrefix(e, "AGENTSH_UNIXWRAP_ARGV0=") {
			t.Errorf("AGENTSH_UNIXWRAP_ARGV0 not stripped: %q", e)
		}
	}
	want := map[string]bool{
		"OTHER=x":                              true,
		"HOME=/tmp":                            true,
		"AGENTSH_UNIXWRAP_ARGV0_NOT_OURS=keep": true,
	}
	got := map[string]bool{}
	for _, e := range out {
		got[e] = true
	}
	for w := range want {
		if !got[w] {
			t.Errorf("expected entry %q in filtered env", w)
		}
	}
}

// fakeWrapperPrintEnvSrc is a fake wrapper that writes its environment to the
// file named by FAKE_ENV_OUT, sends the notify fd, reads the ACK, and exits 0.
func TestFilterShimInternalEnv_StripsWrapperLogFD(t *testing.T) {
	in := []string{"PATH=/bin", wrapperlog.EnvKey + "=7", "HOME=/root"}
	out := filterShimInternalEnv(in)
	for _, e := range out {
		if strings.HasPrefix(e, wrapperlog.EnvKey+"=") {
			t.Fatalf("inherited %s not stripped: %v", wrapperlog.EnvKey, out)
		}
	}
	if len(out) != 2 {
		t.Fatalf("unexpected env after strip: %v", out)
	}
}

func TestAssembleWrapperEnv_DropsWrapperLogFDFromWrapperEnv(t *testing.T) {
	env := assembleWrapperEnv(
		[]string{"PATH=/bin"},
		"",
		map[string]string{
			wrapperlog.EnvKey:        "9", // must NOT pass through — the relay sets its own
			"AGENTSH_SECCOMP_CONFIG": "{}",
		},
		nil,
	)
	for _, e := range env {
		if strings.HasPrefix(e, wrapperlog.EnvKey+"=") {
			t.Fatalf("server-supplied %s leaked into wrapper env: %v", wrapperlog.EnvKey, env)
		}
	}
}

// TestInstall_PassesWrapperLogFDAndCreatesStateLogFile verifies the
// issue #415 relay wiring end-to-end: runRelay opens the state-dir log
// file, passes it as ExtraFiles[1], and exports AGENTSH_WRAPPER_LOG_FD=4
// to the wrapper. XDG_STATE_HOME is redirected to a temp dir so the test
// owns the state-dir location.
func TestAssembleWrapperEnv_EnvInjectCannotShadowWrapperLogFD(t *testing.T) {
	env := assembleWrapperEnv(
		[]string{"PATH=/bin"},
		"",
		nil,
		map[string]string{wrapperlog.EnvKey: "9"}, // operator env_inject
	)
	for _, e := range env {
		if strings.HasPrefix(e, wrapperlog.EnvKey+"=") {
			t.Fatalf("env_inject value for %s survived into wrapper env: %v", wrapperlog.EnvKey, env)
		}
	}
}

// ─── Tests for PtraceMode response handling (#416) ──────────────────────────

// TestInstall_PtraceModeACK verifies that when wrap-init returns a ptrace-mode
// response (PtraceMode=true, WrapperBinary=""), Install performs the PID socket
// handshake and runs the child shell, returning ResultExec with its exit code.
// This is the primary regression guard for #416: before the fix, Install hit
// the `WrapperBinary==""` check and returned ResultSkip, leaving the child
// without session association and command deny rules unenforced.
func TestInstall_PtraceModeACK(t *testing.T) {
	orig := seccompFilterCount
	seccompFilterCount = func() int { return 0 }
	t.Cleanup(func() { seccompFilterCount = orig })

	sockDir := t.TempDir()
	notifySockPath := filepath.Join(sockDir, "ptrace-notify.sock")

	ln, err := net.Listen("unix", notifySockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	pidCh := make(chan uint32, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		pidCh <- uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
		conn.Write([]byte{1}) // ACK
	}()

	handler, _ := makeWrapInitHandler(200, types.WrapInitResponse{
		PtraceMode:   true,
		NotifySocket: notifySockPath,
		// WrapperBinary deliberately empty — this is the ptrace-mode shape
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := baseParams(srv)
	p.Mode = ModeAuto
	p.RealShell = "/bin/sh"
	p.ShellArgs = []string{"-c", "exit 0"}

	res, err := Install(p)
	if err != nil {
		t.Fatalf("Install error: %v", err)
	}
	if res.Action != ResultExec {
		t.Fatalf("action = %v (reason=%q), want ResultExec", res.Action, res.Reason)
	}
	if res.WrapperExitCode != 0 {
		t.Errorf("WrapperExitCode = %d, want 0", res.WrapperExitCode)
	}

	select {
	case pid := <-pidCh:
		if pid == 0 {
			t.Error("received PID 0 — server should have gotten a real child PID")
		}
	case <-time.After(5 * time.Second):
		t.Error("server never received PID from Install handshake")
	}
}

// TestInstall_PtraceModeACK_ExitCode verifies that a non-zero child exit code
// is faithfully propagated through WrapperExitCode.
func TestInstall_PtraceModeACK_ExitCode(t *testing.T) {
	orig := seccompFilterCount
	seccompFilterCount = func() int { return 0 }
	t.Cleanup(func() { seccompFilterCount = orig })

	sockDir := t.TempDir()
	notifySockPath := filepath.Join(sockDir, "ptrace-notify2.sock")
	ln, err := net.Listen("unix", notifySockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		conn.Read(buf)
		conn.Write([]byte{1}) // ACK
	}()

	handler, _ := makeWrapInitHandler(200, types.WrapInitResponse{
		PtraceMode:   true,
		NotifySocket: notifySockPath,
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := baseParams(srv)
	p.Mode = ModeAuto
	p.RealShell = "/bin/sh"
	p.ShellArgs = []string{"-c", "exit 42"}

	res, err := Install(p)
	if err != nil {
		t.Fatalf("Install error: %v", err)
	}
	if res.Action != ResultExec {
		t.Fatalf("action = %v, want ResultExec", res.Action)
	}
	if res.WrapperExitCode != 42 {
		t.Errorf("WrapperExitCode = %d, want 42", res.WrapperExitCode)
	}
}

// TestInstall_PtraceModeNACK_ModeAuto verifies that when the server sends NACK
// (attach rejected), Install returns ResultSkip in ModeAuto so the command
// falls through to its existing enforcement path rather than fail-closing.
func TestInstall_PtraceModeNACK_ModeAuto(t *testing.T) {
	orig := seccompFilterCount
	seccompFilterCount = func() int { return 0 }
	t.Cleanup(func() { seccompFilterCount = orig })

	sockDir := t.TempDir()
	notifySockPath := filepath.Join(sockDir, "ptrace-nack.sock")
	ln, err := net.Listen("unix", notifySockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		conn.Read(buf)
		conn.Write([]byte{0}) // NACK
	}()

	handler, _ := makeWrapInitHandler(200, types.WrapInitResponse{
		PtraceMode:   true,
		NotifySocket: notifySockPath,
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := baseParams(srv)
	p.Mode = ModeAuto
	p.RealShell = "/bin/sh"
	p.ShellArgs = []string{"-c", "exit 0"}

	res, err := Install(p)
	if err != nil {
		t.Fatalf("Install error: %v", err)
	}
	if res.Action != ResultSkip {
		t.Errorf("action = %v (reason=%q), want ResultSkip on NACK in ModeAuto", res.Action, res.Reason)
	}
}

// TestInstall_PtraceModeNACK_ModeOn verifies fail-closed semantics on NACK
// when shim_install=on.
func TestInstall_PtraceModeNACK_ModeOn(t *testing.T) {
	orig := seccompFilterCount
	seccompFilterCount = func() int { return 0 }
	t.Cleanup(func() { seccompFilterCount = orig })

	sockDir := t.TempDir()
	notifySockPath := filepath.Join(sockDir, "ptrace-nack-on.sock")
	ln, err := net.Listen("unix", notifySockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		conn.Read(buf)
		conn.Write([]byte{0}) // NACK
	}()

	handler, _ := makeWrapInitHandler(200, types.WrapInitResponse{
		PtraceMode:   true,
		NotifySocket: notifySockPath,
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := baseParams(srv)
	p.Mode = ModeOn
	p.RealShell = "/bin/sh"
	p.ShellArgs = []string{"-c", "exit 0"}

	res, err := Install(p)
	if err != nil {
		t.Fatalf("Install error: %v", err)
	}
	if res.Action != ResultFailClosed {
		t.Errorf("action = %v (reason=%q), want ResultFailClosed on NACK in ModeOn", res.Action, res.Reason)
	}
}

// findModuleRoot walks up from the current working directory to find go.mod.
func findModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod")
		}
		dir = parent
	}
}
