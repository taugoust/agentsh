//go:build linux

package cli

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/agentsh/agentsh/internal/envinject"
	"github.com/agentsh/agentsh/internal/wrapenv"
	"github.com/agentsh/agentsh/internal/wraphandoff"
	"github.com/agentsh/agentsh/internal/wrapperlog"
	"github.com/agentsh/agentsh/pkg/types"
	"golang.org/x/sys/unix"
)

var notifySetupStatusTimeout = 30 * time.Second

// platformSetupWrap creates a socket pair, configures the wrapper launch, and
// returns a postStart function that receives the notify fd from the wrapper and
// forwards it to the server's Unix listener socket.
func platformSetupWrap(ctx context.Context, wrapResp types.WrapInitResponse, sessID string, agentPath string, agentArgs []string, cfg *clientConfig) (*wrapLaunchConfig, error) {
	if err := validateWrapCommandJail(wrapResp); err != nil {
		return nil, err
	}
	// Ptrace mode: no wrapper binary needed. Connect to the server's socket
	// for PID handshake via SO_PEERCRED, then launch the shell directly.
	if wrapResp.PtraceMode {
		if wrapResp.CommandJail != nil {
			return nil, fmt.Errorf("strict command jail is unavailable in ptrace wrap mode")
		}
		notifySocket := wrapResp.NotifySocket

		env := buildWrapEnv(wrapenv.Filter(os.Environ(), wrapResp.EnvPolicy), sessID, cfg.serverAddr, wrapResp.SafeToBypassShellShim)
		// Overlay sandbox.env_inject so injected vars reach the command in
		// ptrace mode too, matching the seccomp/shim paths (issue #374).
		env = envinject.Apply(env, wrapResp.EnvInject)

		// connHolder stores the keepalive connection set by ptracePostStart.
		var connHolder net.Conn

		foregroundTTY := false
		sysProcAttr := func() *syscall.SysProcAttr {
			attr := &syscall.SysProcAttr{Setpgid: true}
			if isTerminal(os.Stdin.Fd()) {
				attr.Foreground = true
				attr.Ctty = int(os.Stdin.Fd())
				foregroundTTY = true
			}
			return attr
		}()

		return &wrapLaunchConfig{
			command:       agentPath,
			args:          agentArgs,
			env:           env,
			sysProcAttr:   sysProcAttr,
			foregroundTTY: foregroundTTY,
			ptracePostStart: func(childPID int) error {
				// Connect after child starts, send the child PID explicitly
				// (SO_PEERCRED would give our parent PID, not the child's).
				conn, err := net.Dial("unix", notifySocket)
				if err != nil {
					return fmt.Errorf("dial: %w", err)
				}

				// Send child PID as 4-byte little-endian
				pidBytes := make([]byte, 4)
				binary.LittleEndian.PutUint32(pidBytes, uint32(childPID))
				if _, err := conn.Write(pidBytes); err != nil {
					conn.Close()
					return fmt.Errorf("send PID: %w", err)
				}

				// Wait for server ACK/NACK
				ack := make([]byte, 1)
				if _, err := conn.Read(ack); err != nil {
					conn.Close()
					return fmt.Errorf("read ACK: %w", err)
				}
				if ack[0] != 1 {
					conn.Close()
					return fmt.Errorf("server rejected attach")
				}

				connHolder = conn
				return nil
			},
			postWait: func() {
				if connHolder != nil {
					connHolder.Close()
				}
				if isTerminal(os.Stdin.Fd()) {
					reclaimTerminal()
				}
			},
		}, nil
	}

	// Create a socket pair for the notify fd exchange between the wrapper and this CLI process.
	// The child end (fds[1]) is inherited by agentsh-unixwrap as ExtraFiles[0] (fd 3).
	// The parent end (fds[0]) receives the seccomp notify fd from the wrapper.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socketpair: %w", err)
	}

	parentFile := os.NewFile(uintptr(fds[0]), "notify-parent")
	childFile := os.NewFile(uintptr(fds[1]), "notify-child")

	// Clear CLOEXEC on the child fd so it survives exec
	if _, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fds[1]), unix.F_SETFD, 0); errno != 0 {
		parentFile.Close()
		childFile.Close()
		return nil, fmt.Errorf("fcntl clear cloexec: %w", errno)
	}

	// Create a second socket pair for the signal filter fd if the server configured one.
	// The child end is inherited as ExtraFiles[1] (fd 4).
	var signalParentFile, signalChildFile *os.File
	hasSignalSocket := wrapResp.SignalSocket != ""
	if hasSignalSocket {
		sigFds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			parentFile.Close()
			childFile.Close()
			return nil, fmt.Errorf("signal socketpair: %w", err)
		}
		signalParentFile = os.NewFile(uintptr(sigFds[0]), "signal-parent")
		signalChildFile = os.NewFile(uintptr(sigFds[1]), "signal-child")

		// Clear CLOEXEC on the child fd so it survives exec
		if _, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(sigFds[1]), unix.F_SETFD, 0); errno != 0 {
			parentFile.Close()
			childFile.Close()
			signalParentFile.Close()
			signalChildFile.Close()
			return nil, fmt.Errorf("fcntl clear cloexec signal: %w", errno)
		}
	}

	// Bound every wrapper-control receive. Raw recvmsg/read calls bypass Go's
	// netpoll deadlines, so use the socket-level timeout.
	readyTimeout := unix.NsecToTimeval(notifySetupStatusTimeout.Nanoseconds())
	_ = unix.SetsockoptTimeval(int(parentFile.Fd()), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &readyTimeout)
	if signalParentFile != nil {
		_ = unix.SetsockoptTimeval(int(signalParentFile.Fd()), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &readyTimeout)
	}

	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			_ = parentFile.Close()
			_ = childFile.Close()
			if signalParentFile != nil {
				_ = signalParentFile.Close()
			}
			if signalChildFile != nil {
				_ = signalChildFile.Close()
			}
		})
	}

	// Build env for the wrapped process. Remove every supervisor/wrapper control
	// spelling before trusted values are added; os.Getenv uses the first exact
	// entry, so append-only merging would let an inherited value bypass the jail.
	env := buildWrapEnv(wrapenv.Filter(os.Environ(), wrapResp.EnvPolicy), sessID, cfg.serverAddr, wrapResp.SafeToBypassShellShim)
	// Overlay operator-configured sandbox.env_inject (override semantics)
	// before the internal markers, matching the shim and server-spawned exec
	// paths so injected vars reach the executed command (issue #374).
	env = envinject.Apply(env, wrapResp.EnvInject)
	env = stripWrapperControlEnv(env)
	env = append(env, "AGENTSH_NOTIFY_SOCK_FD=3") // fd 3 = ExtraFiles[0]
	if strings.TrimSpace(wrapResp.ApprovalUISocket) != "" {
		env = append(env, fmt.Sprintf("AGENTSH_APPROVAL_UI_SOCKET=%s", wrapResp.ApprovalUISocket))
	}
	if hasSignalSocket {
		env = append(env, "AGENTSH_SIGNAL_SOCK_FD=4") // fd 4 = ExtraFiles[1]
	}

	// Add wrapper env vars (seccomp config, etc.)
	for k, v := range wrapResp.WrapperEnv {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	// Build command: agentsh-unixwrap -- <agent-path> <agent-args...>
	wrapperArgs := append([]string{"--", agentPath}, agentArgs...)

	notifySocket := wrapResp.NotifySocket
	signalSocket := wrapResp.SignalSocket

	extraFiles := []*os.File{childFile}
	if hasSignalSocket {
		extraFiles = append(extraFiles, signalChildFile)
	}

	// Wrapper log routing (issue #415): the CLI's stderr is the user's
	// terminal, so route wrapper diagnostics to the state-dir log file.
	// fd number = next ExtraFiles slot (4, or 5 with the signal socket).
	// Debug-level fallback note on open failure — a Warn would reintroduce
	// the exact noise this removes. wrap.go closes every extraFiles entry
	// after Start, so no extra cleanup is needed.
	// os.Getenv returns the FIRST duplicate, so drop any copy of the
	// key carried in by the inherited environment, env_inject, or
	// server WrapperEnv. Unconditional: even on open failure a stale
	// value must not survive — inside the wrapper it could name a
	// valid-but-unrelated fd (e.g. the signal socket at fd 4) and
	// receive routed diagnostics.
	env = stripEnvKey(env, wrapperlog.EnvKey)
	logFile, logErr := wrapperlog.OpenStateLogFile()
	if logErr != nil {
		// Debug, not Warn: the CLI's stderr is the user's terminal and
		// the wrapper falls back to it anyway (legacy behavior).
		slog.Debug("wrap: wrapper log file unavailable; wrapper diagnostics stay on stderr", "error", logErr)
	} else {
		env = append(env, fmt.Sprintf("%s=%d", wrapperlog.EnvKey, 3+len(extraFiles)))
		extraFiles = append(extraFiles, logFile)
	}

	foregroundTTY := false
	sysProcAttr := func() *syscall.SysProcAttr {
		attr := &syscall.SysProcAttr{Setpgid: true}
		// If stdin is a terminal, make the child the foreground process
		// group so interactive shells (bash -i) can read from the TTY.
		if isTerminal(os.Stdin.Fd()) {
			attr.Foreground = true
			attr.Ctty = int(os.Stdin.Fd())
			foregroundTTY = true
		}
		return attr
	}()
	if err := configureWrapCommandBoundary(sysProcAttr, wrapResp.CommandJail); err != nil {
		cleanup()
		if logFile != nil {
			_ = logFile.Close()
		}
		return nil, err
	}

	return &wrapLaunchConfig{
		command:       wrapResp.WrapperBinary,
		args:          wrapperArgs,
		env:           env,
		extraFiles:    extraFiles,
		sysProcAttr:   sysProcAttr,
		foregroundTTY: foregroundTTY,
		cleanup:       cleanup,
		postWait: func() {
			// Reclaim the terminal's foreground process group after the child
			// exits so the parent can continue writing to stderr.
			if isTerminal(os.Stdin.Fd()) {
				reclaimTerminal()
			}
		},
		postStart: func(childPID int) error {
			// Receive the seccomp notify fd from the wrapper.
			notifyFD, err := recvNotifyFD(parentFile)
			if err != nil {
				return fmt.Errorf("receive notify fd: %w", err)
			}
			defer func() { unix.Close(notifyFD) }()

			// A strict wrapper advertises the command-jail protocol before it
			// blocks on ACK. Consume that capability before asking the server to
			// run the centralized cgroup/helper barrier, and propagate it in the
			// authenticated child-PID handoff. Missing capability means an old or
			// mismatched wrapper and must never be papered over by sending ACK.
			commandJail := false
			if wrapResp.CommandJail != nil {
				if err := readWrapControlByte(parentFile, 'J'); err != nil {
					return fmt.Errorf("wait for command-jail capability: %w", err)
				}
				commandJail = true
			}

			// The server replies only after the centralized pre-exec barrier has
			// completed cgroup/eBPF setup and notify-handler startup. A rejection
			// or timeout leaves the wrapper ACK-blocked.
			if err := forwardNotifyFDWithPID(notifySocket, notifyFD, childPID, commandJail); err != nil {
				return fmt.Errorf("forward notify fd to server: %w", err)
			}
			if !foregroundTTY {
				slog.Info("wrap: notify fd accepted by server", "session_id", sessID, "socket", notifySocket, "wrapper_pid", childPID)
			}

			// Release trusted wrapper setup only after the server's cgroup/helper
			// setup status succeeds. Strict jails still require READY/GO below.
			if err := writeWrapControlByte(parentFile, 0x01); err != nil {
				return fmt.Errorf("release wrapper ACK barrier: %w", err)
			}

			// Forward signal filter fd if configured. This filter is installed by
			// the wrapper after the ACK, so failures remain explicitly degraded;
			// cgroup/network setup has already succeeded at this point.
			if hasSignalSocket && signalParentFile != nil {
				signalFD, signalErr := recvNotifyFD(signalParentFile)
				if signalErr != nil {
					slog.Warn("wrap: signal filter handoff unavailable after pre-exec ACK", "error", signalErr, "session_id", sessID)
				} else {
					defer func() { unix.Close(signalFD) }()
					if signalErr = forwardNotifyFD(signalSocket, signalFD); signalErr != nil {
						slog.Warn("wrap: signal filter forwarding degraded after pre-exec ACK", "error", signalErr, "session_id", sessID)
					} else {
						slog.Info("wrap: signal fd forwarded to server", "session_id", sessID)
					}
				}
			}

			if wrapResp.CommandJail != nil {
				if err := readWrapControlByte(parentFile, 'R'); err != nil {
					return fmt.Errorf("wait for command-jail READY: %w", err)
				}
				if err := writeWrapControlByte(parentFile, 'G'); err != nil {
					return fmt.Errorf("release command-jail GO barrier: %w", err)
				}
			}
			_ = parentFile.Close()
			if signalParentFile != nil {
				_ = signalParentFile.Close()
			}
			return nil
		},
	}, nil
}

// recvNotifyFD receives a file descriptor from a Unix socket using SCM_RIGHTS.
func recvNotifyFD(sock *os.File) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := unix.Recvmsg(int(sock.Fd()), buf, oob, 0)
	if err != nil {
		return -1, fmt.Errorf("recvmsg: %w", err)
	}
	if n == 0 || oobn == 0 {
		return -1, fmt.Errorf("no fd received (n=%d, oobn=%d)", n, oobn)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, fmt.Errorf("parse control message: %w", err)
	}
	for _, m := range msgs {
		fds, err := unix.ParseUnixRights(&m)
		if err != nil {
			continue
		}
		if len(fds) > 0 {
			return fds[0], nil
		}
	}
	return -1, fmt.Errorf("no fd in control message")
}

func forwardNotifyFDWithPID(socketPath string, notifyFD int, wrapperPID int, commandJail bool) error {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("dial %s: %w", socketPath, err)
	}
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix connection")
	}

	if err := wraphandoff.SendNotifyFD(unixConn, notifyFD, wraphandoff.Metadata{
		WrapperPID:  wrapperPID,
		CommandJail: commandJail,
	}); err != nil {
		return err
	}
	if err := unixConn.SetReadDeadline(time.Now().Add(notifySetupStatusTimeout)); err != nil {
		return fmt.Errorf("set notify setup status deadline: %w", err)
	}
	if err := wraphandoff.ReadStatus(unixConn); err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return fmt.Errorf("timed out waiting for notify setup status after %s: %w", notifySetupStatusTimeout, err)
		}
		return fmt.Errorf("read notify setup status: %w", err)
	}
	return nil
}

func forwardNotifyFD(socketPath string, notifyFD int) error {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("dial %s: %w", socketPath, err)
	}
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix connection")
	}

	file, err := unixConn.File()
	if err != nil {
		return fmt.Errorf("get file from connection: %w", err)
	}
	defer file.Close()

	// Send the notify fd via SCM_RIGHTS
	rights := unix.UnixRights(notifyFD)
	if err := unix.Sendmsg(int(file.Fd()), []byte{0}, rights, nil, 0); err != nil {
		return fmt.Errorf("sendmsg: %w", err)
	}

	return nil
}

func validateWrapCommandJail(resp types.WrapInitResponse) error {
	var wire struct {
		CommandJail *struct {
			Required bool `json:"required"`
		} `json:"command_jail"`
	}
	configJSON := strings.TrimSpace(resp.WrapperEnv["AGENTSH_SECCOMP_CONFIG"])
	if configJSON == "" {
		configJSON = strings.TrimSpace(resp.SeccompConfig)
	}
	if configJSON != "" {
		if err := json.Unmarshal([]byte(configJSON), &wire); err != nil {
			return fmt.Errorf("decode command-jail wrapper configuration: %w", err)
		}
	}
	configRequiresJail := wire.CommandJail != nil && wire.CommandJail.Required
	if resp.CommandJail == nil {
		if configRequiresJail {
			return fmt.Errorf("server requires a command jail but omitted Linux launch requirements")
		}
		return nil
	}
	if !resp.CommandJail.Complete() {
		return fmt.Errorf("server returned incomplete Linux command-jail requirements")
	}
	if !configRequiresJail {
		return fmt.Errorf("server returned Linux command-jail launch requirements without a required wrapper jail")
	}
	return nil
}

func configureWrapCommandBoundary(attr *syscall.SysProcAttr, requirements *types.LinuxCommandJailRequirements) error {
	if requirements == nil {
		return nil
	}
	if !requirements.Complete() || attr == nil {
		return fmt.Errorf("strict command boundary requirements are incomplete")
	}
	if len(attr.UidMappings) != 0 || len(attr.GidMappings) != 0 || attr.Credential != nil {
		return fmt.Errorf("strict command boundary cannot compose with existing credentials or mappings")
	}
	if attr.Pdeathsig != 0 && attr.Pdeathsig != syscall.SIGKILL {
		return fmt.Errorf("strict command boundary requires SIGKILL parent-death behavior")
	}
	attr.Cloneflags |= unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWCGROUP | unix.CLONE_NEWIPC
	attr.Pdeathsig = syscall.SIGKILL
	attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}}
	attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}}
	attr.GidMappingsEnableSetgroups = false
	return nil
}

func readWrapControlByte(file *os.File, expected byte) error {
	if file == nil {
		return fmt.Errorf("control socket is unavailable")
	}
	buf := []byte{0}
	for {
		n, err := file.Read(buf)
		if err != nil && errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("read %d control bytes, want 1", n)
		}
		if buf[0] != expected {
			return fmt.Errorf("unexpected control byte 0x%02x, want 0x%02x", buf[0], expected)
		}
		return nil
	}
}

func writeWrapControlByte(file *os.File, value byte) error {
	if file == nil {
		return fmt.Errorf("control socket is unavailable")
	}
	n, err := file.Write([]byte{value})
	if err != nil {
		return err
	}
	if n != 1 {
		return io.ErrShortWrite
	}
	return nil
}

// isTerminal returns true if the given file descriptor is a terminal.
func isTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	return err == nil
}

// reclaimTerminal makes the current process group the foreground group of stdin.
func reclaimTerminal() {
	// If the wrapper child owns the foreground terminal, this CLI is briefly in a
	// background process group while reclaiming it. TIOCSPGRP from a background
	// process group can deliver SIGTTOU and stop us unless the signal is ignored
	// or blocked.
	signal.Ignore(syscall.SIGTTOU)
	defer signal.Reset(syscall.SIGTTOU)
	pgid := int32(unix.Getpgrp())
	_, _, _ = unix.Syscall(unix.SYS_IOCTL, os.Stdin.Fd(), unix.TIOCSPGRP, uintptr(unsafe.Pointer(&pgid)))
}

// stripEnvKey returns env without any KEY=... entries for key.
// WARNING: filters in place via env[:0] — it mutates the input slice's
// backing array, so callers must pass a slice they exclusively own.
func stripEnvKey(env []string, key string) []string {
	return stripEnvKeysFold(env, key)
}

func stripWrapperControlEnv(env []string) []string {
	return stripEnvKeysFold(env,
		"AGENTSH_NOTIFY_SOCK_FD",
		"AGENTSH_SIGNAL_SOCK_FD",
		"AGENTSH_SECCOMP_CONFIG",
		"AGENTSH_PTRACE_SYNC",
		"AGENTSH_APPROVAL_UI_SOCKET",
		"AGENTSH_INTERNAL_COMMAND_JAIL_STAGE",
		"AGENTSH_INTERNAL_COMMAND_JAIL_MOUNTS",
		"AGENTSH_INTERNAL_COMMAND_JAIL_EXEC_PATH",
		"AGENTSH_NETHELPER_SOCKET",
		"AGENTSH_NETHELPER_INSTANCE_CREDENTIAL",
		"AGENTSH_NETHELPER_SESSION_NONCE",
		"AGENTSH_NETHELPER_CREDENTIAL_FILE",
		"AGENTSH_DETACHED_EVENT_TOKEN",
		"AGENTSH_DETACHED_EVENT_URL",
		"AGENTSH_DETACHED_NETWORK_ENFORCEMENT_REQUESTED",
		"AGENTSH_DETACHED_SUPERVISOR_LAUNCH_MODE",
	)
}

func stripEnvKeysFold(env []string, keys ...string) []string {
	out := env[:0]
	for _, entry := range env {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			out = append(out, entry)
			continue
		}
		blocked := false
		for _, key := range keys {
			if strings.EqualFold(strings.TrimSpace(name), key) {
				blocked = true
				break
			}
		}
		if !blocked {
			out = append(out, entry)
		}
	}
	return out
}
