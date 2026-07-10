//go:build linux && cgo

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

const (
	commandJailStageEnv    = "AGENTSH_INTERNAL_COMMAND_JAIL_STAGE"
	commandJailMountsEnv   = "AGENTSH_INTERNAL_COMMAND_JAIL_MOUNTS"
	commandJailExecPathEnv = "AGENTSH_INTERNAL_COMMAND_JAIL_EXEC_PATH"
)

var commandJailReservedEnv = []string{
	commandJailStageEnv,
	commandJailMountsEnv,
	commandJailExecPathEnv,
	"AGENTSH_NOTIFY_SOCK_FD",
	"AGENTSH_SIGNAL_SOCK_FD",
	"AGENTSH_SECCOMP_CONFIG",
	"AGENTSH_PTRACE_SYNC",
	"AGENTSH_UNIXWRAP_ARGV0",
	"AGENTSH_WRAPPER_LOG_FD",
	"AGENTSH_APPROVAL_UI_SOCKET",
	"AGENTSH_SERVER_PID",
	"AGENTSH_NETHELPER_SOCKET",
	"AGENTSH_NETHELPER_INSTANCE_CREDENTIAL",
	"AGENTSH_NETHELPER_SESSION_NONCE",
	"AGENTSH_NETHELPER_CREDENTIAL_FILE",
	"AGENTSH_DETACHED_EVENT_TOKEN",
	"AGENTSH_DETACHED_EVENT_URL",
	"AGENTSH_DETACHED_NETWORK_ENFORCEMENT_REQUESTED",
	"AGENTSH_DETACHED_SUPERVISOR_LAUNCH_MODE",
	"AGENTSH_API_KEY",
	"AGENTSH_SERVER",
}

type mountedFilesystem struct {
	Path   string `json:"path"`
	FSType string `json:"fs_type"`
}

// prepareCommandJail inventories sensitive mount types before the seccomp
// filter is installed. The command runner creates the wrapper directly in the
// namespace boundary; doing that here, after the cgroup ACK, would require
// post-filter uid_map writes and would place the new child outside late cgroup
// moves in the external wrap path.
func prepareCommandJail(cfg *CommandJailConfig, commandPath string) error {
	if cfg == nil || !cfg.Required {
		return errors.New("command jail configuration is not strict")
	}
	if err := validateCommandJailHideTargets(cfg); err != nil {
		return err
	}
	mounts, err := currentMounts()
	if err != nil {
		return fmt.Errorf("inventory proc/cgroup mounts: %w", err)
	}
	mountJSON, err := json.Marshal(mounts)
	if err != nil {
		return fmt.Errorf("encode mount inventory: %w", err)
	}
	if err := os.Setenv(commandJailMountsEnv, string(mountJSON)); err != nil {
		return fmt.Errorf("store mount inventory: %w", err)
	}
	if strings.TrimSpace(commandPath) == "" {
		return errors.New("resolved command path is empty")
	}
	if err := os.Setenv(commandJailExecPathEnv, commandPath); err != nil {
		return fmt.Errorf("store resolved command path: %w", err)
	}
	// The wrapper still needs its control descriptors until the ACK/READY/GO
	// handshakes complete, so mark rather than close them. The final user child
	// is started with only stdio and cannot inherit any marked descriptor.
	if err := markNonStdioCloseOnExec(); err != nil {
		return fmt.Errorf("protect wrapper descriptors: %w", err)
	}
	return nil
}

func runCommandJailStage(controlFD int) (int, error) {
	if unix.Getpid() != 1 {
		return 127, errors.New("refusing untrusted command-jail stage marker outside a new PID namespace")
	}
	// Capability state, no_new_privs, and seccomp filters are per-thread.
	// Keep all boundary setup and the final fork on this exact thread.
	runtime.LockOSThread()
	if len(os.Args) < 3 || os.Args[1] != "--" {
		return 127, errors.New("invalid command-jail arguments")
	}
	cfg, err := loadConfig()
	if err != nil {
		return 127, fmt.Errorf("load command-jail config: %w", err)
	}
	if cfg.CommandJail == nil || !cfg.CommandJail.Required {
		return 127, errors.New("command-jail stage lacks a required jail configuration")
	}
	if err := unix.Mount("", string(filepath.Separator), "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return 127, fmt.Errorf("make mount propagation private: %w", err)
	}

	cmd := os.Args[2]
	cmdPath := os.Getenv(commandJailExecPathEnv)
	if strings.TrimSpace(cmdPath) == "" {
		return 127, errors.New("command-jail stage lacks the trusted resolved command path")
	}
	args := applyArgv0Override(os.Args[2:], os.Getenv("AGENTSH_UNIXWRAP_ARGV0"))

	if err := installCommandJailMounts(cfg.CommandJail); err != nil {
		return 127, err
	}
	if err := dropCommandJailPrivileges(); err != nil {
		return 127, err
	}
	if err := installCommandJailSeccomp(); err != nil {
		return 127, err
	}
	if err := markNonStdioCloseOnExec(); err != nil {
		return 127, fmt.Errorf("protect command descriptors: %w", err)
	}
	if err := verifyCommandJailPrivileges(); err != nil {
		return 127, err
	}

	env := scrubCommandJailEnv(os.Environ())
	if err := commandJailReadyAndWaitForGO(controlFD); err != nil {
		return 127, err
	}
	_ = unix.Close(controlFD)
	sigCh := make(chan os.Signal, 8)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGWINCH)
	defer signal.Stop(sigCh)

	child, err := os.StartProcess(cmdPath, args, &os.ProcAttr{
		Env:   env,
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Sys: &syscall.SysProcAttr{
			Pdeathsig: syscall.SIGKILL,
		},
	})
	if err != nil {
		return 127, fmt.Errorf("exec %s in command jail: %w", cmd, err)
	}

	done := make(chan struct{})
	stopForwarding := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case sig := <-sigCh:
				if sig != nil {
					_ = child.Signal(sig)
				}
			case <-stopForwarding:
				return
			}
		}
	}()

	state, waitErr := child.Wait()
	signal.Stop(sigCh)
	close(stopForwarding)
	<-done
	if waitErr != nil {
		return 127, fmt.Errorf("wait jailed command: %w", waitErr)
	}
	return processExitCode(state), nil
}

func validateCommandJailHideTargets(cfg *CommandJailConfig) error {
	if cfg == nil {
		return errors.New("command jail configuration is missing")
	}
	validate := func(target string, wantDirectory bool) error {
		if err := validateMountTarget(target); err != nil {
			return err
		}
		info, err := os.Lstat(target)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symbolic-link mount targets are forbidden")
		}
		if wantDirectory != info.IsDir() {
			return fmt.Errorf("mount target directory=%t, want %t", info.IsDir(), wantDirectory)
		}
		resolved, err := filepath.EvalSymlinks(target)
		if err != nil {
			return err
		}
		if filepath.Clean(resolved) != filepath.Clean(target) {
			return fmt.Errorf("mount target traverses a symbolic link to %s", resolved)
		}
		return nil
	}
	for _, target := range cfg.HideDirectories {
		if err := validate(target, true); err != nil {
			return fmt.Errorf("invalid hidden directory %s: %w", target, err)
		}
	}
	for _, target := range cfg.HidePaths {
		if err := validate(target, false); err != nil {
			return fmt.Errorf("invalid hidden path %s: %w", target, err)
		}
	}
	return nil
}

func installCommandJailMounts(cfg *CommandJailConfig) error {
	var mounts []mountedFilesystem
	if err := json.Unmarshal([]byte(os.Getenv(commandJailMountsEnv)), &mounts); err != nil || len(mounts) == 0 {
		if err == nil {
			err = errors.New("empty mount inventory")
		}
		return fmt.Errorf("load trusted mount inventory: %w", err)
	}
	// Shallow roots first. Container runtimes often overmount proc files such
	// as /proc/sysrq-trigger; replacing the enclosing proc root removes those
	// host views, so nested proc/cgroup mountpoints must not be mounted again.
	sort.Slice(mounts, func(i, j int) bool { return len(mounts[i].Path) < len(mounts[j].Path) })
	var hiddenRoots []string
	for _, mount := range mounts {
		if pathCoveredByRoot(mount.Path, hiddenRoots) {
			continue
		}
		switch mount.FSType {
		case "proc":
			if err := replaceWithPrivateProc(mount.Path); err != nil {
				return err
			}
			hiddenRoots = append(hiddenRoots, mount.Path)
		case "cgroup", "cgroup2":
			if err := maskDirectory(mount.Path); err != nil {
				return fmt.Errorf("hide cgroupfs %s: %w", mount.Path, err)
			}
			hiddenRoots = append(hiddenRoots, mount.Path)
		}
	}

	hideDirs := append([]string(nil), cfg.HideDirectories...)
	sort.Slice(hideDirs, func(i, j int) bool { return len(hideDirs[i]) < len(hideDirs[j]) })
	for _, path := range hideDirs {
		if pathCoveredByRoot(path, hiddenRoots) {
			continue
		}
		if err := maskDirectory(path); err != nil {
			return fmt.Errorf("hide control directory %s: %w", path, err)
		}
		hiddenRoots = append(hiddenRoots, path)
	}
	for _, path := range cfg.HidePaths {
		// Credentials commonly live below the helper control directory. Once
		// that directory is masked, trying to overmount the now-absent child
		// path would incorrectly turn a stronger boundary into a setup failure.
		if pathCoveredByRoot(path, hiddenRoots) {
			continue
		}
		if err := maskPath(path); err != nil {
			return fmt.Errorf("hide control path %s: %w", path, err)
		}
	}
	return nil
}

func currentMounts() ([]mountedFilesystem, error) {
	mountInfo := filepath.Join(string(filepath.Separator), "proc", "self", "mountinfo")
	data, err := os.ReadFile(mountInfo)
	if err != nil {
		return nil, err
	}
	var out []mountedFilesystem
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if separator < 0 || separator+1 >= len(fields) {
			continue
		}
		fsType := fields[separator+1]
		if fsType != "proc" && fsType != "cgroup" && fsType != "cgroup2" {
			continue
		}
		out = append(out, mountedFilesystem{Path: unescapeMountPath(fields[4]), FSType: fsType})
	}
	return out, nil
}

func pathCoveredByRoot(path string, roots []string) bool {
	path = filepath.Clean(path)
	for _, root := range roots {
		root = filepath.Clean(root)
		if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func unescapeMountPath(path string) string {
	replacer := strings.NewReplacer(
		`\040`, " ",
		`\011`, "\t",
		`\012`, "\n",
		`\134`, `\`,
	)
	return replacer.Replace(path)
}

func replaceWithPrivateProc(target string) error {
	if err := validateMountTarget(target); err != nil {
		return fmt.Errorf("private proc target: %w", err)
	}
	// Overmount rather than unmount: proc mounts inherited into a less
	// privileged user namespace may be mount-locked, but an overmount still
	// prevents access to the host proc tree without exposing the old mount.
	flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if err := unix.Mount("proc", target, "proc", flags, ""); err != nil {
		return fmt.Errorf("mount private proc %s: %w", target, err)
	}
	return nil
}

func maskDirectory(target string) error {
	if err := validateMountTarget(target); err != nil {
		return err
	}
	flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if err := unix.Mount("tmpfs", target, "tmpfs", flags, "mode=0555,size=4096"); err != nil {
		return err
	}
	if err := unix.Mount("", target, "", flags|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("remount read-only: %w", err)
	}
	return nil
}

func maskPath(target string) error {
	if err := validateMountTarget(target); err != nil {
		return err
	}
	devNull := filepath.Join(string(filepath.Separator), "dev", "null")
	if err := unix.Mount(devNull, target, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	flags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if err := unix.Mount("", target, "", flags, ""); err != nil {
		return fmt.Errorf("remount read-only: %w", err)
	}
	return nil
}

func validateMountTarget(target string) error {
	if target == "" || !filepath.IsAbs(target) {
		return errors.New("mount target must be absolute")
	}
	if filepath.Clean(target) == string(filepath.Separator) {
		return errors.New("refusing to mask filesystem root")
	}
	return nil
}

func dropCommandJailPrivileges() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("set jail init non-dumpable: %w", err)
	}
	// Disable root's capability special cases and lock the setting before the
	// effective/permitted sets are cleared. Values are the stable Linux
	// securebits ABI: NOROOT(+LOCKED), NO_SETUID_FIXUP(+LOCKED), and
	// NO_CAP_AMBIENT_RAISE(+LOCKED).
	const commandJailSecureBits = 0xCF
	if err := unix.Prctl(unix.PR_SET_SECUREBITS, commandJailSecureBits, 0, 0, 0); err != nil {
		return fmt.Errorf("lock command-jail securebits: %w", err)
	}
	// Linux capability numbers currently fit in 0..63. EINVAL is accepted for
	// numbers above this kernel's cap_last_cap, so no post-seccomp /proc read is
	// needed during trusted jail setup.
	for capability := 0; capability <= 63; capability++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capability), 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("drop capability %d from bounding set: %w", capability, err)
		}
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("clear ambient capabilities: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if err := unix.Capset(&header, &data[0]); err != nil {
		return fmt.Errorf("clear capability sets: %w", err)
	}
	return nil
}

func verifyCommandJailPrivileges() error {
	noNewPrivileges, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("verify no_new_privs: %w", err)
	}
	if noNewPrivileges != 1 {
		return errors.New("no_new_privs was not retained")
	}
	dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("verify non-dumpable jail init: %w", err)
	}
	if dumpable != 0 {
		return errors.New("command-jail init remained dumpable")
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if err := unix.Capget(&header, &data[0]); err != nil {
		return fmt.Errorf("read command-jail capabilities: %w", err)
	}
	for i, capabilities := range data {
		if capabilities.Effective != 0 || capabilities.Permitted != 0 || capabilities.Inheritable != 0 {
			return fmt.Errorf("command-jail capability word %d was not empty", i)
		}
	}
	return nil
}

func commandJailReadyAndWaitForGO(controlFD int) error {
	if controlFD < 3 {
		return fmt.Errorf("invalid command-jail control fd %d", controlFD)
	}
	n, err := unix.Write(controlFD, []byte{'R'})
	if err != nil {
		return fmt.Errorf("send command-jail READY byte: %w", err)
	}
	if n != 1 {
		return fmt.Errorf("send command-jail READY byte: wrote %d bytes, want 1", n)
	}
	_ = unix.SetsockoptTimeval(controlFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 30})
	if err := waitForControlByte(func(b []byte) (int, error) { return unix.Read(controlFD, b) }, 'G'); err != nil {
		return fmt.Errorf("wait for command-jail GO byte: %w", err)
	}
	return nil
}

func installCommandJailSeccomp() error {
	filter, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		return fmt.Errorf("create command-jail seccomp filter: %w", err)
	}
	defer filter.Release()
	if err := filter.SetRawRC(true); err != nil {
		return fmt.Errorf("enable command-jail seccomp raw errors: %w", err)
	}

	// The mount view is complete before this filter is loaded. Deny every
	// namespace/mount API that could be used to alter that view, plus same-UID
	// process inspection and kernel control APIs that have no legitimate role in
	// an untrusted tool command. clone/clone3 remain available for normal process
	// creation; every descendant inherits this filter and the already-masked view.
	blocked := []string{
		"mount", "umount2", "pivot_root", "setns", "unshare",
		"open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr",
		"ptrace", "process_vm_readv", "process_vm_writev", "kcmp", "pidfd_getfd",
		"bpf", "perf_event_open", "userfaultfd",
		"add_key", "request_key", "keyctl",
	}
	action := seccomp.ActErrno.SetReturnCode(int16(unix.EPERM))
	for _, name := range blocked {
		syscallNumber, err := seccomp.GetSyscallFromName(name)
		if err != nil {
			return fmt.Errorf("resolve required command-jail syscall %s: %w", name, err)
		}
		if err := filter.AddRule(syscallNumber, action); err != nil {
			return fmt.Errorf("deny command-jail syscall %s: %w", name, err)
		}
	}
	if err := filter.Load(); err != nil {
		return fmt.Errorf("load command-jail seccomp filter: %w", err)
	}
	return nil
}

func markNonStdioCloseOnExec() error {
	const closeRangeCloexec = 1 << 2
	if err := unix.CloseRange(3, ^uint(0), closeRangeCloexec); err != nil {
		return fmt.Errorf("close_range(CLOEXEC) is required: %w", err)
	}
	return nil
}

func scrubCommandJailEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		reserved := false
		for _, blocked := range commandJailReservedEnv {
			if strings.EqualFold(strings.TrimSpace(key), blocked) {
				reserved = true
				break
			}
		}
		if !reserved {
			out = append(out, entry)
		}
	}
	return out
}

func processExitCode(state *os.ProcessState) int {
	if state == nil {
		return 127
	}
	if code := state.ExitCode(); code >= 0 {
		return code
	}
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return 127
}
