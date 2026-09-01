//go:build !windows

package permissiongate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	helperEnabledEnv      = "AGENTSH_PERMISSION_GATE_TEST_HELPER"
	helperModeEnv         = "AGENTSH_PERMISSION_GATE_TEST_MODE"
	helperChildEnv        = "AGENTSH_PERMISSION_GATE_TEST_CHILD"
	helperMarkerEnv       = "AGENTSH_PERMISSION_GATE_TEST_MARKER"
	helperValueEnv        = "AGENTSH_PERMISSION_GATE_TEST_VALUE"
	helperSocketRecordEnv = "AGENTSH_PERMISSION_GATE_TEST_SOCKET_RECORD"
)

func TestPermissionGateHelperProcess(t *testing.T) {
	if os.Getenv(helperEnabledEnv) != "1" {
		return
	}
	if os.Getenv(helperChildEnv) == "delayed-writer" {
		time.Sleep(350 * time.Millisecond)
		_ = os.WriteFile(os.Getenv(helperMarkerEnv), []byte("survived\n"), 0o600)
		os.Exit(0)
	}
	mode := os.Getenv(helperModeEnv)
	socketPath := os.Getenv(EnvSocket)
	if socketPath == "" || !filepath.IsAbs(socketPath) {
		os.Exit(91)
	}
	if recordPath := os.Getenv(helperSocketRecordEnv); recordPath != "" {
		if err := os.WriteFile(recordPath, []byte(socketPath), 0o600); err != nil {
			os.Exit(92)
		}
	}
	if mode == "silent" {
		time.Sleep(5 * time.Second)
		_ = os.WriteFile(os.Getenv(helperMarkerEnv), []byte("survived\n"), 0o600)
		os.Exit(99)
	}
	if mode == "rendezvous" {
		directoryInfo, err := os.Stat(filepath.Dir(socketPath))
		if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode().Perm() != 0o700 {
			os.Exit(93)
		}
		socketInfo, err := os.Stat(socketPath)
		if err != nil || socketInfo.Mode()&os.ModeSocket == 0 {
			os.Exit(94)
		}
	}

	transport, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		os.Exit(95)
	}
	defer transport.Close()
	if mode == "connected-silent" {
		time.Sleep(5 * time.Second)
		_ = os.WriteFile(os.Getenv(helperMarkerEnv), []byte("survived\n"), 0o600)
		os.Exit(99)
	}
	if mode == "rendezvous" {
		deadline := time.Now().Add(time.Second)
		for {
			_, socketErr := os.Lstat(socketPath)
			_, directoryErr := os.Stat(filepath.Dir(socketPath))
			if os.IsNotExist(socketErr) && os.IsNotExist(directoryErr) {
				break
			}
			if time.Now().After(deadline) {
				os.Exit(96)
			}
			time.Sleep(5 * time.Millisecond)
		}
		second, secondErr := net.DialTimeout("unix", socketPath, 20*time.Millisecond)
		if secondErr == nil {
			_ = second.Close()
			os.Exit(97)
		}
	}

	reader := newFrameReader(transport)
	if err := writeFrame(transport, HelloRequest{V: ProtocolVersion, Type: messageHello, Client: "pi-permission-gate"}); err != nil {
		os.Exit(98)
	}
	frame, err := reader.read()
	if err != nil {
		os.Exit(99)
	}
	var hello HelloResponse
	if json.Unmarshal(frame, &hello) != nil || hello.Service != "agentsh-permission-gate" {
		os.Exit(100)
	}

	switch mode {
	case "rendezvous":
		os.Exit(0)
	case "normal":
		cwd, _ := os.Getwd()
		if err := writeFrame(transport, AuthorizeRequest{
			V: ProtocolVersion, Type: messageAuthorize, ID: "helper-normal", Kind: "bash",
			Command: "printf helper", CWD: cwd, ToolCallID: "helper-tool",
		}); err != nil {
			os.Exit(96)
		}
		frame, err := reader.read()
		if err != nil {
			os.Exit(97)
		}
		var decision DecisionResponse
		if json.Unmarshal(frame, &decision) != nil || decision.Decision != "allow" {
			os.Exit(98)
		}
		input, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		fmt.Fprintf(os.Stdout, "%s|%s", strings.TrimSpace(input), os.Getenv(helperValueEnv))
		fmt.Fprint(os.Stderr, "helper-stderr")
		os.Exit(23)
	case "signal":
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		time.Sleep(5 * time.Second)
		os.Exit(99)
	case "forwarded-signal":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGWINCH)
		fmt.Fprintln(os.Stdout, "ready")
		select {
		case <-signals:
			os.Exit(0)
		case <-time.After(3 * time.Second):
			os.Exit(101)
		}
	case "eof":
		_ = transport.Close()
		time.Sleep(5 * time.Second)
		_ = os.WriteFile(os.Getenv(helperMarkerEnv), []byte("survived\n"), 0o600)
		os.Exit(99)
	case "malformed-group":
		child := exec.Command(os.Args[0], "-test.run=^TestPermissionGateHelperProcess$")
		child.Env = append(os.Environ(), helperChildEnv+"=delayed-writer")
		child.Stdin = nil
		child.Stdout = nil
		child.Stderr = nil
		if err := child.Start(); err != nil {
			os.Exit(100)
		}
		time.Sleep(30 * time.Millisecond)
		_, _ = transport.Write([]byte("{malformed\n"))
		time.Sleep(5 * time.Second)
		os.Exit(99)
	default:
		os.Exit(90)
	}
}

func permissionGateHelperCommand() []string {
	return []string{os.Args[0], "-test.run=^TestPermissionGateHelperProcess$"}
}

func TestPermissionGateEnvironmentOnlyReplacesGateSocket(t *testing.T) {
	socketPath := filepath.Join("private", "gate.sock")
	input := []string{"A=one", EnvSocket + "=old", "B=two", strings.ToLower(EnvSocket) + "=older"}
	got := withPermissionGateSocket(input, socketPath)
	want := []string{"A=one", "B=two", EnvSocket + "=" + socketPath}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("environment = %q, want %q", got, want)
	}
}

func TestPermissionGateRunUsesOneShotPrivateUnixRendezvous(t *testing.T) {
	t.Setenv(helperEnabledEnv, "1")
	t.Setenv(helperModeEnv, "rendezvous")
	recordPath := filepath.Join(t.TempDir(), "socket-path")
	t.Setenv(helperSocketRecordEnv, recordPath)

	result, err := Run(t.Context(), RunOptions{
		Command: permissionGateHelperCommand(), AuditPath: filepath.Join(t.TempDir(), "audit.jsonl"),
		Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", result.ExitCode)
	}
	recorded, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	socketPath := string(recorded)
	if socketPath == "" || !filepath.IsAbs(socketPath) {
		t.Fatalf("rendezvous path = %q, want absolute path", socketPath)
	}
	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("rendezvous socket was not unlinked: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(socketPath)); !os.IsNotExist(err) {
		t.Fatalf("rendezvous directory was not removed: %v", err)
	}
}

func TestPermissionGateRunStartFailureCleansRendezvous(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	tempRoot := t.TempDir()
	t.Setenv("TMPDIR", tempRoot)

	_, err := Run(t.Context(), RunOptions{
		Command: []string{filepath.Join(tempRoot, "missing-command")}, AuditPath: auditPath,
		Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
	})
	if err == nil || !strings.Contains(err.Error(), "start permission-gated command") {
		t.Fatalf("Run() error = %v, want command start failure", err)
	}
	entries, err := os.ReadDir(tempRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("rendezvous cleanup left entries in %q: %v", tempRoot, entries)
	}
}

func TestPermissionGateRunPreservesCWDEnvironmentStdioAndExitCode(t *testing.T) {
	t.Setenv(helperEnabledEnv, "1")
	t.Setenv(helperModeEnv, "normal")
	t.Setenv(helperValueEnv, "environment-ok")
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	var stdout, stderr bytes.Buffer
	result, err := Run(t.Context(), RunOptions{
		Command: permissionGateHelperCommand(), AuditPath: auditPath,
		Stdin: strings.NewReader("stdin-ok\n"), Stdout: &stdout, Stderr: &stderr,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.ExitCode != 23 {
		t.Fatalf("exit code = %d, want 23", result.ExitCode)
	}
	if stdout.String() != "stdin-ok|environment-ok" || stderr.String() != "helper-stderr" {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if result.AuditPath != auditPath {
		t.Fatalf("audit path = %q, want %q", result.AuditPath, auditPath)
	}
	contents, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var record AuditRecord
	if err := json.Unmarshal(bytes.TrimSpace(contents), &record); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if record.CWD != cwd || record.Decision != "allow" || record.ToolCallID != "helper-tool" {
		t.Fatalf("audit record = %#v", record)
	}
}

func TestPermissionGateRunPreservesSignaledExitCode(t *testing.T) {
	t.Setenv(helperEnabledEnv, "1")
	t.Setenv(helperModeEnv, "signal")
	result, err := Run(t.Context(), RunOptions{
		Command: permissionGateHelperCommand(), AuditPath: filepath.Join(t.TempDir(), "audit.jsonl"),
		Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	want := 128 + int(syscall.SIGTERM)
	if result.ExitCode != want {
		t.Fatalf("exit code = %d, want %d", result.ExitCode, want)
	}
}

func TestPermissionGateRunForwardsSignals(t *testing.T) {
	t.Setenv(helperEnabledEnv, "1")
	t.Setenv(helperModeEnv, "forwarded-signal")
	stdoutReader, stdoutWriter := io.Pipe()
	defer stdoutReader.Close()
	defer stdoutWriter.Close()
	resultCh := make(chan struct {
		result RunResult
		err    error
	}, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	go func() {
		result, err := Run(ctx, RunOptions{
			Command: permissionGateHelperCommand(), AuditPath: auditPath,
			Stdin: strings.NewReader(""), Stdout: stdoutWriter, Stderr: &bytes.Buffer{},
		})
		resultCh <- struct {
			result RunResult
			err    error
		}{result: result, err: err}
	}()
	line, err := bufio.NewReader(stdoutReader).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("helper readiness = %q, %v", line, err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatal(err)
	}
	outcome := <-resultCh
	if outcome.err != nil || outcome.result.ExitCode != 0 {
		t.Fatalf("Run() = %#v, %v", outcome.result, outcome.err)
	}
}

func TestPermissionGateRunHandshakeFailuresFailClosed(t *testing.T) {
	for _, test := range []struct {
		name string
		mode string
	}{
		{name: "no connection", mode: "silent"},
		{name: "connected without hello", mode: "connected-silent"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(helperEnabledEnv, "1")
			t.Setenv(helperModeEnv, test.mode)
			marker := filepath.Join(t.TempDir(), "survived")
			t.Setenv(helperMarkerEnv, marker)
			started := time.Now()
			_, err := Run(t.Context(), RunOptions{
				Command: permissionGateHelperCommand(), AuditPath: filepath.Join(t.TempDir(), "audit.jsonl"),
				HandshakeTimeout: 50 * time.Millisecond,
				Stdin:            strings.NewReader(""),
				Stdout:           &bytes.Buffer{},
				Stderr:           &bytes.Buffer{},
			})
			if err == nil || !strings.Contains(err.Error(), "timeout") {
				t.Fatalf("Run() error = %v, want handshake timeout", err)
			}
			if elapsed := time.Since(started); elapsed > 2*time.Second {
				t.Fatalf("handshake failure took %s; child was not promptly killed and reaped", elapsed)
			}
			time.Sleep(100 * time.Millisecond)
			if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
				t.Fatalf("child survived missing handshake: %v", statErr)
			}
		})
	}
}

func TestPermissionGateRunUnexpectedEOFKillsAndReapsChild(t *testing.T) {
	t.Setenv(helperEnabledEnv, "1")
	t.Setenv(helperModeEnv, "eof")
	marker := filepath.Join(t.TempDir(), "survived")
	t.Setenv(helperMarkerEnv, marker)
	started := time.Now()
	_, err := Run(t.Context(), RunOptions{
		Command: permissionGateHelperCommand(), AuditPath: filepath.Join(t.TempDir(), "audit.jsonl"),
		Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
	})
	if err == nil || !errors.Is(err, ErrUnexpectedEOF) {
		t.Fatalf("Run() error = %v, want unexpected EOF", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("broker failure took %s; child was not promptly killed and reaped", elapsed)
	}
	time.Sleep(400 * time.Millisecond)
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("child survived broker EOF: %v", statErr)
	}
}

func TestPermissionGateRunBrokerFailureKillsChildProcessGroup(t *testing.T) {
	t.Setenv(helperEnabledEnv, "1")
	t.Setenv(helperModeEnv, "malformed-group")
	marker := filepath.Join(t.TempDir(), "grandchild-survived")
	t.Setenv(helperMarkerEnv, marker)
	_, err := Run(t.Context(), RunOptions{
		Command: permissionGateHelperCommand(), AuditPath: filepath.Join(t.TempDir(), "audit.jsonl"),
		Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
	})
	if err == nil || !errors.Is(err, ErrProtocol) {
		t.Fatalf("Run() error = %v, want protocol error", err)
	}
	time.Sleep(500 * time.Millisecond)
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("grandchild survived process-group kill: %v", statErr)
	}
}
