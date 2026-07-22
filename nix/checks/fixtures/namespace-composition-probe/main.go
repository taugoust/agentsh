//go:build linux && cgo

// namespace-composition-probe is a NixOS-VM-only fixture. It drives
// the real AgentSH Linux wrapper through its ACK/READY/GO protocol while a
// specially tagged wrapper build leaves descendant namespace/mount syscalls
// available. This isolates whether the next cumulative boundary, Landlock,
// composes with nested Bubblewrap.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/composition"
	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

const notifyFDEnv = "AGENTSH_NOTIFY_SOCK_FD"
const configEnv = "AGENTSH_SECCOMP_CONFIG"

type wrapperConfig struct {
	UnixSocketEnabled          bool        `json:"unix_socket_enabled"`
	ExecveEnabled              bool        `json:"execve_enabled"`
	FileMonitorEnabled         bool        `json:"file_monitor_enabled"`
	InterceptMetadata          bool        `json:"intercept_metadata,omitempty"`
	WriteOnlyOpens             bool        `json:"write_only_opens,omitempty"`
	BlockIOUring               bool        `json:"block_io_uring,omitempty"`
	BlockedSyscalls            []string    `json:"blocked_syscalls,omitempty"`
	OnBlock                    string      `json:"on_block,omitempty"`
	WaitKillable               *bool       `json:"wait_killable,omitempty"`
	WaitKillableSource         string      `json:"wait_killable_source,omitempty"`
	LandlockEnabled            bool        `json:"landlock_enabled,omitempty"`
	LandlockABI                int         `json:"landlock_abi,omitempty"`
	Workspace                  string      `json:"workspace,omitempty"`
	AllowExecute               []string    `json:"allow_execute,omitempty"`
	AllowRead                  []string    `json:"allow_read,omitempty"`
	AllowWrite                 []string    `json:"allow_write,omitempty"`
	AllowNetwork               bool        `json:"allow_network,omitempty"`
	AllowBind                  bool        `json:"allow_bind,omitempty"`
	SandboxComposition         string      `json:"sandbox_composition,omitempty"`
	CompositionScratchRoot     string      `json:"composition_scratch_root,omitempty"`
	CompositionSyntheticMounts int         `json:"composition_synthetic_mounts,omitempty"`
	CompositionMaxTransitions  int         `json:"composition_max_transitions,omitempty"`
	CompositionMaxDataBytes    int64       `json:"composition_max_data_bytes,omitempty"`
	CommandJail                *jailConfig `json:"command_jail,omitempty"`
}

type jailConfig struct {
	Required        bool     `json:"required"`
	HideDirectories []string `json:"hide_directories,omitempty"`
}

type feasibilityReport struct {
	SchemaVersion      int    `json:"schema_version"`
	Stage              string `json:"stage"`
	Result             string `json:"result"`
	ErrnoClass         string `json:"errno_class,omitempty"`
	LandlockABI        int    `json:"landlock_abi"`
	OuterNamespaceID   int    `json:"outer_namespace_id"`
	LandlockComposes   *bool  `json:"landlock_composes,omitempty"`
	SelectedBranch     string `json:"selected_branch,omitempty"`
	ExitCode           int    `json:"exit_code"`
	Notifications      int64  `json:"notifications"`
	ExecNotifications  int64  `json:"exec_notifications"`
	FileNotifications  int64  `json:"file_notifications"`
	MountNotifications int64  `json:"mount_notifications,omitempty"`
}

type notificationCounts struct {
	total atomic.Int64
	exec  atomic.Int64
	file  atomic.Int64
	mount atomic.Int64
}

type compositionExecPolicy struct{}

func compositionExecDecision(filename string) unixmon.PolicyDecision {
	if filepath.Base(filename) == "agentsh-composition-denied-command" {
		return unixmon.PolicyDecision{Decision: "deny", EffectiveDecision: "deny", Rule: "deny-composition-source-command"}
	}
	return unixmon.PolicyDecision{Decision: "allow", EffectiveDecision: "allow", Rule: "composition-vm-allow"}
}

func (compositionExecPolicy) CheckExecve(filename string, _ []string, _ int) unixmon.PolicyDecision {
	return compositionExecDecision(filename)
}

func (compositionExecPolicy) CheckExecveWithAliases(filename string, _ []string, _ []string, _ int) unixmon.PolicyDecision {
	return compositionExecDecision(filename)
}

type compositionFilePolicy struct{}

func (compositionFilePolicy) CheckFile(_ context.Context, path, _ string) unixmon.FilePolicyDecision {
	if path == "/etc/hosts" {
		return unixmon.FilePolicyDecision{Decision: "deny", EffectiveDecision: "deny", Rule: "deny-source-hosts"}
	}
	return unixmon.FilePolicyDecision{Decision: "allow", EffectiveDecision: "allow", Rule: "composition-vm-allow"}
}

type mountBrokerConfig struct {
	helper        string
	allowedSource string
	allowedRoot   string
	active        atomic.Bool
}

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: %s run|payload", filepath.Base(os.Args[0]))
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = runHarness(os.Args[2:])
	case "payload":
		err = runPayload(os.Args[2:])
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fatalf("%v", err)
	}
}

func runHarness(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	wrapper := fs.String("wrapper", "", "test-only agentsh-unixwrap path")
	matrix := fs.String("matrix", "", "Bubblewrap matrix executable")
	controlDir := fs.String("control-dir", "", "outer command-jail control directory to mask")
	landlockEnabled := fs.Bool("landlock", false, "apply the current AgentSH Landlock ruleset")
	outerNamespaceID := fs.Int("outer-namespace-id", 1, "outer user-namespace UID/GID mapping")
	expectBlock := fs.Bool("expect-landlock-block", false, "require a typed EPERM-class Landlock failure")
	expectUIDMapBlock := fs.Bool("expect-root-map-block", false, "require the current outer UID 0 mapping to block nested userns setup")
	mountBrokerHelper := fs.String("mount-broker-helper", "", "test-only helper used to emulate mount notifications")
	brokerSource := fs.String("broker-source", "", "only bind source accepted by the test broker")
	brokerRoot := fs.String("broker-root", "", "only destination tree accepted by the test broker")
	landlockWriteRoot := fs.String("landlock-write-root", "", "optional restricted Landlock write root")
	landlockExactReadRoot := fs.String("landlock-exact-read-root", "", "exact retained source root for composition")
	successStage := fs.String("success-stage", "", "override the successful Landlock report stage")
	successBranch := fs.String("success-branch", "", "override the successful Landlock branch label")
	compositionAdapter := fs.String("composition-adapter", "", "production semantic Bubblewrap adapter")
	compositionHelper := fs.String("composition-helper", "", "production semantic composition mount helper")
	compositionScratchRoot := fs.String("composition-scratch-root", os.TempDir(), "trusted composition staging root")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"wrapper":     *wrapper,
		"matrix":      *matrix,
		"control-dir": *controlDir,
	} {
		if strings.TrimSpace(value) == "" || !filepath.IsAbs(value) {
			return fmt.Errorf("--%s must be an absolute path", name)
		}
	}
	brokerEnabled := *mountBrokerHelper != "" || *brokerSource != "" || *brokerRoot != ""
	semanticComposition := *compositionAdapter != "" || *compositionHelper != ""
	if semanticComposition {
		if !filepath.IsAbs(*compositionAdapter) || !filepath.IsAbs(*compositionHelper) {
			return errors.New("composition adapter and helper must both be absolute")
		}
		if !filepath.IsAbs(*compositionScratchRoot) || filepath.Clean(*compositionScratchRoot) != *compositionScratchRoot {
			return errors.New("composition scratch root must be a clean absolute path")
		}
		if !*landlockEnabled || brokerEnabled || *expectBlock || *expectUIDMapBlock {
			return errors.New("semantic composition requires Landlock and is exclusive with other expected branches")
		}
	}
	if brokerEnabled {
		for name, value := range map[string]string{
			"mount-broker-helper": *mountBrokerHelper,
			"broker-source":       *brokerSource,
			"broker-root":         *brokerRoot,
		} {
			if !filepath.IsAbs(value) {
				return fmt.Errorf("--%s must be an absolute path when mount brokering is enabled", name)
			}
		}
		if !*landlockEnabled || *expectBlock || *expectUIDMapBlock {
			return errors.New("mount brokering requires Landlock without an expected direct-mount failure")
		}
	}
	if *landlockWriteRoot != "" && !filepath.IsAbs(*landlockWriteRoot) {
		return errors.New("--landlock-write-root must be absolute")
	}
	if *landlockExactReadRoot != "" && !filepath.IsAbs(*landlockExactReadRoot) {
		return errors.New("--landlock-exact-read-root must be absolute")
	}
	if (*successStage == "") != (*successBranch == "") || (*successStage != "" && (!*landlockEnabled || *expectBlock)) {
		return errors.New("success-stage and success-branch must be supplied together for a successful Landlock probe")
	}
	if *outerNamespaceID < 0 {
		return errors.New("--outer-namespace-id must be non-negative")
	}
	if *expectBlock && !*landlockEnabled {
		return errors.New("--expect-landlock-block requires --landlock")
	}
	if *expectUIDMapBlock && (*landlockEnabled || *outerNamespaceID != 0) {
		return errors.New("--expect-root-map-block requires --outer-namespace-id=0 without Landlock")
	}

	landlockResult := capabilities.DetectLandlock()
	if !landlockResult.Available || landlockResult.ABI < 1 {
		return fmt.Errorf("Landlock unavailable: %s", landlockResult.String())
	}

	root := string(filepath.Separator)
	writeRoots := []string{root}
	if *landlockWriteRoot != "" {
		writeRoots = []string{*landlockWriteRoot}
	}
	readRoots := []string{root, filepath.Join(root, "nix", "store")}
	if *landlockExactReadRoot != "" {
		readRoots = append(readRoots, *landlockExactReadRoot)
	}
	waitKillable := false
	cfg := wrapperConfig{
		UnixSocketEnabled:  true,
		ExecveEnabled:      true,
		FileMonitorEnabled: true,
		InterceptMetadata:  true,
		WriteOnlyOpens:     false,
		BlockIOUring:       true,
		WaitKillable:       &waitKillable,
		WaitKillableSource: "nested_namespace_feasibility_vm",
		LandlockEnabled:    *landlockEnabled,
		LandlockABI:        landlockResult.ABI,
		Workspace:          root,
		// Keep /nix/store as an explicit Landlock rule object. Once the broker
		// bind-mounts that tree below a detached root, the original / rule is no
		// longer in its mount ancestry; the source-root rule preserves the base
		// execute/read authority without broadening it.
		AllowExecute: []string{root, filepath.Join(root, "nix", "store")},
		AllowRead:    readRoots,
		AllowWrite:   writeRoots,
		AllowNetwork: true,
		AllowBind:    true,
		CommandJail: &jailConfig{
			Required:        true,
			HideDirectories: []string{*controlDir},
		},
	}
	if brokerEnabled {
		cfg.BlockedSyscalls = []string{"mount"}
		cfg.OnBlock = "log"
	}
	if semanticComposition {
		cfg.SandboxComposition = composition.Mode
		cfg.CompositionScratchRoot = *compositionScratchRoot
		cfg.CompositionSyntheticMounts = 16
		cfg.CompositionMaxTransitions = 16
		cfg.CompositionMaxDataBytes = 16 * 1024 * 1024
	}
	configJSON, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode wrapper config: %w", err)
	}

	socketFDs, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("create wrapper control socketpair: %w", err)
	}
	parentSocket := os.NewFile(uintptr(socketFDs[0]), "feasibility-parent-control")
	childSocket := os.NewFile(uintptr(socketFDs[1]), "feasibility-child-control")
	defer parentSocket.Close()
	var compositionParent, compositionChild *os.File
	if semanticComposition {
		compositionFDs, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			childSocket.Close()
			return fmt.Errorf("create composition setup socketpair: %w", err)
		}
		compositionParent = os.NewFile(uintptr(compositionFDs[0]), "feasibility-composition-parent")
		compositionChild = os.NewFile(uintptr(compositionFDs[1]), "feasibility-composition-child")
	}

	self, err := os.Executable()
	if err != nil {
		childSocket.Close()
		return fmt.Errorf("locate feasibility payload: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	scratchRoot := ""
	if *landlockWriteRoot != "" {
		scratchRoot = *landlockWriteRoot
	}
	cmd := exec.CommandContext(ctx, *wrapper, "--", self, "payload", "--matrix", *matrix, "--control-dir", *controlDir, "--scratch-root", scratchRoot, "--composition="+strconv.FormatBool(semanticComposition))
	cmd.Env = append(os.Environ(), notifyFDEnv+"=3", configEnv+"="+string(configJSON))
	cmd.ExtraFiles = []*os.File{childSocket}
	if compositionChild != nil {
		cmd.Env = append(cmd.Env, composition.SetupFDEnv+"=4")
		cmd.ExtraFiles = append(cmd.ExtraFiles, compositionChild)
	}
	// A capability-free namespace UID 0 cannot create a second user namespace
	// which maps its own ID on Linux 5.12+: mapping a parent-namespace UID 0
	// requires CAP_SETFCAP. Use an otherwise equivalent non-root outer identity
	// for the experiment so the Landlock stage is reachable without retaining an
	// outer capability. Production composition would need this launch-contract
	// adjustment; the ordinary command jail remains unchanged.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWCGROUP | unix.CLONE_NEWIPC,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: *outerNamespaceID, HostID: os.Geteuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: *outerNamespaceID, HostID: os.Getegid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
		// Preserve only the namespaced capabilities the trusted wrapper needs
		// across exec. completeCommandJailSetup drops and verifies them before
		// READY, so none reach the payload.
		AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_SETPCAP},
		Pdeathsig:   syscall.SIGKILL,
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		childSocket.Close()
		if compositionChild != nil {
			compositionChild.Close()
		}
		if compositionParent != nil {
			compositionParent.Close()
		}
		return fmt.Errorf("start wrapper in outer namespaces: %w", err)
	}
	childSocket.Close()
	if compositionChild != nil {
		compositionChild.Close()
	}

	_ = unix.SetsockoptTimeval(int(parentSocket.Fd()), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 30})
	notifyFile, err := unixmon.RecvFD(parentSocket)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("receive seccomp notify fd: %w; wrapper stderr: %s", err, stderr.String())
	}
	defer notifyFile.Close()
	if err := expectControlByte(parentSocket, 'J'); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("receive command-jail capability: %w", err)
	}

	handlerCtx, stopHandler := context.WithCancel(context.Background())
	counts := &notificationCounts{}
	broker := &mountBrokerConfig{
		helper:        *mountBrokerHelper,
		allowedSource: filepath.Clean(*brokerSource),
		allowedRoot:   filepath.Clean(*brokerRoot),
	}
	handlerDone := make(chan error, 1)
	if semanticComposition {
		pathRegistry := unixmon.NewCompositionPathRegistry()
		runtimeBroker, err := composition.NewBroker(composition.BrokerConfig{
			HelperPath:            *compositionHelper,
			AdapterPath:           *compositionAdapter,
			ScratchRoot:           *compositionScratchRoot,
			ReadRoots:             []string{root},
			WriteRoots:            []string{root},
			ExecuteRoots:          []string{root},
			DenyRoots:             []string{*controlDir},
			MaxPlanOperations:     256,
			MaxDataBytes:          16 * 1024 * 1024,
			RequestTimeout:        30 * time.Second,
			SetupConnection:       compositionParent,
			SetupSenderPID:        cmd.Process.Pid,
			SetupSenderExecutable: *wrapper,
			SetupSyntheticRoots:   cfg.CompositionMaxTransitions,
			SetupSyntheticRW:      cfg.CompositionSyntheticMounts,
			PublishPathMappings:   pathRegistry.Register,
		})
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return err
		}
		redirector, err := unixmon.NewManagedCompositionRedirector(
			*compositionAdapter,
			runtimeBroker.ServeOne,
			cfg.CompositionMaxTransitions,
			4,
			func() error { return errors.Join(runtimeBroker.Close(), pathRegistry.Close()) },
		)
		if err != nil {
			_ = runtimeBroker.Close()
			_ = pathRegistry.Close()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return err
		}
		execHandler := unixmon.NewExecveHandler(unixmon.ExecveHandlerConfig{MaxArgc: 512, MaxArgvBytes: 256 * 1024, OnTruncated: "deny"}, compositionExecPolicy{}, nil, nil)
		execHandler.SetComposition(composition.Mode, *compositionAdapter, redirector)
		execHandler.SetCompositionPathRegistry(pathRegistry)
		fileHandler := unixmon.NewFileHandler(compositionFilePolicy{}, nil, nil, true)
		fileHandler.SetCompositionPathRegistry(pathRegistry)
		go func() {
			unixmon.ServeNotifyWithExecve(handlerCtx, notifyFile, "composition-vm", nil, nil, execHandler, fileHandler, nil)
			handlerDone <- nil
		}()
	} else {
		go func() {
			handlerDone <- serveAllowNotifications(handlerCtx, notifyFile, counts, broker)
		}()
	}
	if _, err := parentSocket.Write([]byte{0x01}); err != nil {
		stopHandler()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("send enforcement ACK: %w", err)
	}
	if err := expectControlByte(parentSocket, 'R'); err != nil {
		stopHandler()
		_ = notifyFile.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("wait for complete outer boundary READY: %w; wrapper stderr: %s", err, stderr.String())
	}
	if brokerEnabled {
		broker.active.Store(true)
	}
	if _, err := parentSocket.Write([]byte{'G'}); err != nil {
		stopHandler()
		_ = notifyFile.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("release outer boundary GO: %w", err)
	}

	waitErr := cmd.Wait()
	stopHandler()
	_ = notifyFile.Close()
	select {
	case handlerErr := <-handlerDone:
		if handlerErr != nil {
			return handlerErr
		}
	case <-time.After(5 * time.Second):
		return errors.New("seccomp notification handler did not stop")
	}
	fmt.Print(stdout.String())
	fmt.Fprint(os.Stderr, stderr.String())

	exitCode := processExitCode(waitErr)
	report := feasibilityReport{
		SchemaVersion:      1,
		LandlockABI:        landlockResult.ABI,
		OuterNamespaceID:   *outerNamespaceID,
		ExitCode:           exitCode,
		Notifications:      counts.total.Load(),
		ExecNotifications:  counts.exec.Load(),
		FileNotifications:  counts.file.Load(),
		MountNotifications: counts.mount.Load(),
	}
	if semanticComposition {
		composes := waitErr == nil
		report.Stage = "landlock_semantic_composition_runtime"
		report.LandlockComposes = &composes
		report.SelectedBranch = "bubblewrap_semantic_adapter"
		if waitErr != nil {
			report.Result = "failed"
			_ = json.NewEncoder(os.Stdout).Encode(report)
			return fmt.Errorf("production semantic composition failed: %w", waitErr)
		}
		report.Result = "pass"
		return json.NewEncoder(os.Stdout).Encode(report)
	}

	if counts.exec.Load() == 0 || counts.file.Load() == 0 {
		report.Stage = "seccomp_monitoring"
		report.Result = "failed"
		_ = json.NewEncoder(os.Stdout).Encode(report)
		return fmt.Errorf("seccomp monitoring was not exercised: exec=%d file=%d", counts.exec.Load(), counts.file.Load())
	}

	if brokerEnabled {
		composes := waitErr == nil
		report.Stage = "landlock_brokered_mount"
		report.LandlockComposes = &composes
		report.SelectedBranch = "generic_mount_syscall_broker"
		if waitErr != nil {
			report.Result = "failed"
			_ = json.NewEncoder(os.Stdout).Encode(report)
			return fmt.Errorf("generic mount broker probe failed: %w", waitErr)
		}
		if counts.mount.Load() < 4 {
			report.Result = "failed"
			_ = json.NewEncoder(os.Stdout).Encode(report)
			return fmt.Errorf("generic mount broker saw only %d mount notifications", counts.mount.Load())
		}
		report.Result = "pass"
		return json.NewEncoder(os.Stdout).Encode(report)
	}

	if !*landlockEnabled {
		combined := strings.ToLower(stdout.String() + "\n" + stderr.String())
		if *expectUIDMapBlock {
			report.Stage = "outer_root_nested_user_namespace"
			if waitErr != nil && strings.Contains(combined, "setting up uid map") && strings.Contains(combined, "operation not permitted") {
				report.Result = "blocked"
				report.ErrnoClass = "EPERM"
				report.SelectedBranch = "nonroot_outer_identity_required"
				return json.NewEncoder(os.Stdout).Encode(report)
			}
			report.Result = "failed"
			_ = json.NewEncoder(os.Stdout).Encode(report)
			return fmt.Errorf("current outer UID 0 mapping did not produce the expected nested uid_map refusal: %v", waitErr)
		}
		report.Stage = "seccomp_without_landlock"
		if waitErr != nil {
			report.Result = "failed"
			_ = json.NewEncoder(os.Stdout).Encode(report)
			return fmt.Errorf("nested Bubblewrap failed before Landlock: %w", waitErr)
		}
		report.Result = "pass"
		return json.NewEncoder(os.Stdout).Encode(report)
	}

	composes := waitErr == nil
	report.Stage = "landlock_nested_mount"
	if *successStage != "" && composes {
		report.Stage = *successStage
	}
	report.LandlockComposes = &composes
	if composes {
		report.Result = "pass"
		report.SelectedBranch = "landlock_composes"
		if *successBranch != "" {
			report.SelectedBranch = *successBranch
		}
		_ = json.NewEncoder(os.Stdout).Encode(report)
		if *expectBlock {
			return errors.New("Landlock unexpectedly permitted nested mount construction; select the composing implementation branch")
		}
		return nil
	}

	combined := strings.ToLower(stdout.String() + "\n" + stderr.String())
	if strings.Contains(combined, "operation not permitted") || strings.Contains(combined, "permission denied") {
		report.ErrnoClass = "EPERM"
	}
	report.Result = "blocked"
	report.SelectedBranch = "alternate_backend_required"
	_ = json.NewEncoder(os.Stdout).Encode(report)
	if !*expectBlock {
		return fmt.Errorf("Landlock blocked nested mount construction: %w", waitErr)
	}
	if report.ErrnoClass != "EPERM" {
		return fmt.Errorf("Landlock failure lacked a stable EPERM-class diagnostic: %w", waitErr)
	}
	return nil
}

func verifyCloneNamespaceDenied(namespaceFlag uintptr, name string) error {
	pid, _, errno := unix.RawSyscall6(
		unix.SYS_CLONE,
		uintptr(unix.CLONE_NEWUSER)|namespaceFlag|uintptr(unix.SIGCHLD),
		0, 0, 0, 0, 0,
	)
	if errno != 0 {
		if errors.Is(errno, unix.EPERM) {
			return nil
		}
		return fmt.Errorf("clone user+%s namespace failed with %v, want EPERM", name, errno)
	}
	if pid == 0 {
		// This branch is evidence of a filter regression. Avoid returning into
		// the Go runtime after raw clone on the current stack.
		_, _, _ = unix.RawSyscall(unix.SYS_EXIT, 99, 0, 0)
		for {
		}
	}
	var status unix.WaitStatus
	_, _ = unix.Wait4(int(pid), &status, 0, nil)
	return fmt.Errorf("clone unexpectedly created a user+%s namespace", name)
}

func runPayload(args []string) error {
	fs := flag.NewFlagSet("payload", flag.ContinueOnError)
	matrix := fs.String("matrix", "", "Bubblewrap matrix executable")
	controlDir := fs.String("control-dir", "", "masked control directory")
	scratchRoot := fs.String("scratch-root", "", "optional writable root for the outer mount denial probe")
	compositionSelected := fs.Bool("composition", false, "expect composition-only namespace syscall filtering")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !filepath.IsAbs(*matrix) || !filepath.IsAbs(*controlDir) || (*scratchRoot != "" && !filepath.IsAbs(*scratchRoot)) {
		return errors.New("payload paths must be absolute")
	}

	if os.Getpid() == 1 {
		return errors.New("payload unexpectedly replaced the trusted PID-namespace init")
	}
	if nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0); err != nil || nnp != 1 {
		return fmt.Errorf("no_new_privs verification failed: value=%d error=%v", nnp, err)
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	capabilityData := [2]unix.CapUserData{}
	if err := unix.Capget(&header, &capabilityData[0]); err != nil {
		return fmt.Errorf("read payload capabilities: %w", err)
	}
	for i, capabilities := range capabilityData {
		if capabilities.Effective != 0 || capabilities.Permitted != 0 || capabilities.Inheritable != 0 {
			return fmt.Errorf("outer capability word %d was not empty", i)
		}
	}
	emitStage("outer_privileges", "pass", "", map[string]any{"no_new_privs": true})

	secret := filepath.Join(*controlDir, "secret")
	if _, err := os.Stat(secret); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("masked control path remained visible: %s: %v", secret, err)
	}
	if err := verifyNoSensitiveInheritedFDs(*controlDir); err != nil {
		return err
	}
	emitStage("hidden_control_paths_and_fds", "pass", "", nil)

	root := string(filepath.Separator)
	procRoot := filepath.Join(root, "proc")
	pidOneStatus, err := os.ReadFile(filepath.Join(procRoot, "1", "status"))
	if err != nil || !strings.Contains(string(pidOneStatus), "Name:\tagentsh-unixwra") {
		return fmt.Errorf("private proc did not expose the trusted namespace init: status=%q error=%v", string(pidOneStatus), err)
	}
	cgroupRoot := filepath.Join(root, "sys", "fs", "cgroup")
	cgroupEntries, err := os.ReadDir(cgroupRoot)
	if err != nil {
		return fmt.Errorf("read masked cgroupfs: %w", err)
	}
	if len(cgroupEntries) != 0 {
		return fmt.Errorf("masked cgroupfs was not empty: %d entries", len(cgroupEntries))
	}
	userNS, _ := os.Readlink(filepath.Join(procRoot, "self", "ns", "user"))
	mountNS, _ := os.Readlink(filepath.Join(procRoot, "self", "ns", "mnt"))
	emitStage("outer_namespaces", "pass", "", map[string]any{"user_namespace": userNS, "mount_namespace": mountNS})

	mountTarget, err := os.MkdirTemp(*scratchRoot, "agentsh-outer-mount-probe-")
	if err != nil {
		return err
	}
	defer os.Remove(mountTarget)
	mountErr := unix.Mount("tmpfs", mountTarget, "tmpfs", 0, "size=4096")
	if mountErr == nil {
		_ = unix.Unmount(mountTarget, unix.MNT_DETACH)
		return errors.New("mount unexpectedly modified the outer AgentSH mount namespace")
	}
	if !errors.Is(mountErr, unix.EPERM) {
		return fmt.Errorf("outer mount failed with %v, want EPERM", mountErr)
	}
	emitStage("outer_mount_after_capability_drop", "blocked", "EPERM", nil)

	mountNamespacePath := filepath.Join(procRoot, "self", "ns", "mnt")
	mountNamespaceFD, err := unix.Open(mountNamespacePath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open namespace probe fd: %w", err)
	}
	setnsErr := unix.Setns(mountNamespaceFD, unix.CLONE_NEWNS)
	_ = unix.Close(mountNamespaceFD)
	if !errors.Is(setnsErr, unix.EPERM) {
		return fmt.Errorf("setns result=%v, want EPERM", setnsErr)
	}
	emitStage("external_setns", "blocked", "EPERM", nil)

	if *compositionSelected {
		if err := verifyCloneNamespaceDenied(unix.CLONE_NEWNET, "network"); err != nil {
			return err
		}
		if err := verifyCloneNamespaceDenied(unix.CLONE_NEWTIME, "time"); err != nil {
			return err
		}
		emitStage("payload_network_and_time_namespaces", "blocked", "EPERM", nil)
	}

	return syscall.Exec(*matrix, []string{*matrix}, os.Environ())
}

func serveAllowNotifications(ctx context.Context, notifyFile *os.File, counts *notificationCounts, broker *mountBrokerConfig) error {
	fd := seccomp.ScmpFd(notifyFile.Fd())
	execSyscalls := resolveSyscallSet([]string{"execve", "execveat"})
	fileSyscalls := resolveSyscallSet([]string{"open", "openat", "openat2", "creat"})
	mountSyscalls := resolveSyscallSet([]string{"mount"})
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		req, err := seccomp.NotifReceive(fd)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, unix.EBADF) || errors.Is(err, unix.EINVAL) {
				return nil
			}
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.ENOENT) {
				time.Sleep(time.Millisecond)
				continue
			}
			return fmt.Errorf("receive seccomp notification: %w", err)
		}
		counts.total.Add(1)
		syscallNumber := int32(req.Data.Syscall)
		if _, ok := execSyscalls[syscallNumber]; ok {
			counts.exec.Add(1)
		}
		if _, ok := fileSyscalls[syscallNumber]; ok {
			counts.file.Add(1)
		}
		if _, ok := mountSyscalls[syscallNumber]; ok && broker.active.Load() {
			counts.mount.Add(1)
			if err := brokerMountRequest(int(req.Pid), req.Data.Args, broker); err != nil {
				if respondErr := unixmon.NotifRespondDeny(int(notifyFile.Fd()), req.ID, int32(unix.EPERM)); respondErr != nil && !errors.Is(respondErr, unix.ENOENT) {
					return fmt.Errorf("deny brokered mount after %v: %w", err, respondErr)
				}
				continue
			}
			if err := unixmon.NotifRespondValue(int(notifyFile.Fd()), req.ID, 0); err != nil && !errors.Is(err, unix.ENOENT) {
				return fmt.Errorf("complete brokered mount: %w", err)
			}
			continue
		}
		if err := unixmon.NotifRespondContinue(int(notifyFile.Fd()), req.ID); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("continue seccomp notification: %w", err)
		}
	}
}

func brokerMountRequest(pid int, args []uint64, broker *mountBrokerConfig) error {
	if len(args) < 5 {
		return errors.New("short seccomp mount argument vector")
	}
	source, err := readTraceeCString(pid, args[0])
	if err != nil {
		return fmt.Errorf("read mount source: %w", err)
	}
	target, err := readTraceeCString(pid, args[1])
	if err != nil {
		return fmt.Errorf("read mount target: %w", err)
	}
	filesystem, err := readTraceeCString(pid, args[2])
	if err != nil {
		return fmt.Errorf("read mount filesystem: %w", err)
	}
	data, err := readTraceeCString(pid, args[4])
	if err != nil {
		return fmt.Errorf("read mount data: %w", err)
	}
	target = filepath.Clean(target)
	relative, err := filepath.Rel(broker.allowedRoot, target)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return fmt.Errorf("destination %q is outside broker root", target)
	}
	flags := args[3]
	switch relative {
	case "bind":
		if filepath.Clean(source) != broker.allowedSource || filesystem != "" || flags&uint64(unix.MS_BIND) == 0 {
			return fmt.Errorf("unapproved bind source=%q filesystem=%q flags=%#x", source, filesystem, flags)
		}
		if err := runMountHelper(broker.helper, pid, source, target, "", flags, data); err != nil {
			return err
		}
		// The fixed source is read-only in the outer policy. Preserve that
		// authority even though the destination is beneath a writable rule.
		readonly := uint64(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV)
		return runMountHelper(broker.helper, pid, "", target, "", readonly, "")
	case "tmpfs":
		if source != "tmpfs" || filesystem != "tmpfs" || flags&uint64(unix.MS_BIND) != 0 {
			return fmt.Errorf("unapproved tmpfs source=%q filesystem=%q flags=%#x", source, filesystem, flags)
		}
		return runMountHelper(broker.helper, pid, source, target, filesystem, flags|uint64(unix.MS_NOSUID|unix.MS_NODEV), data)
	case "proc":
		if source != "proc" || filesystem != "proc" || flags&uint64(unix.MS_BIND) != 0 {
			return fmt.Errorf("unapproved proc source=%q filesystem=%q flags=%#x", source, filesystem, flags)
		}
		return runMountHelper(broker.helper, pid, source, target, filesystem, flags|uint64(unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC), data)
	default:
		return fmt.Errorf("unapproved broker destination %q", relative)
	}
}

func readTraceeCString(pid int, address uint64) (string, error) {
	if address == 0 {
		return "", nil
	}
	buffer := make([]byte, 4096)
	local := unix.Iovec{Base: &buffer[0], Len: uint64(len(buffer))}
	remote := unix.RemoteIovec{Base: uintptr(address), Len: len(buffer)}
	n, err := unix.ProcessVMReadv(pid, []unix.Iovec{local}, []unix.RemoteIovec{remote}, 0)
	if err != nil {
		return "", err
	}
	if nul := bytes.IndexByte(buffer[:n], 0); nul >= 0 {
		return string(buffer[:nul]), nil
	}
	return "", errors.New("unterminated or oversized string")
}

func runMountHelper(helper string, pid int, source, target, filesystem string, flags uint64, data string) error {
	namespaceFiles := make([]*os.File, 0, 3)
	for _, namespace := range []string{"user", "pid", "mnt"} {
		file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "ns", namespace))
		if err != nil {
			for _, opened := range namespaceFiles {
				_ = opened.Close()
			}
			return fmt.Errorf("open tracee %s namespace: %w", namespace, err)
		}
		namespaceFiles = append(namespaceFiles, file)
	}
	defer func() {
		for _, file := range namespaceFiles {
			_ = file.Close()
		}
	}()
	optional := func(value string) string {
		if value == "" {
			return "-"
		}
		return value
	}
	cmd := exec.Command(helper, optional(source), target, optional(filesystem), strconv.FormatUint(flags, 10), optional(data))
	cmd.ExtraFiles = namespaceFiles
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mount helper failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func resolveSyscallSet(names []string) map[int32]struct{} {
	resolved := make(map[int32]struct{}, len(names))
	for _, name := range names {
		number, err := seccomp.GetSyscallFromName(name)
		if err == nil {
			resolved[int32(number)] = struct{}{}
		}
	}
	return resolved
}

func verifyNoSensitiveInheritedFDs(controlDir string) error {
	fdRoot := filepath.Join(string(filepath.Separator), "proc", "self", "fd")
	entries, err := os.ReadDir(fdRoot)
	if err != nil {
		return fmt.Errorf("list payload descriptors: %w", err)
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil || fd <= 2 {
			continue
		}
		target, err := os.Readlink(filepath.Join(fdRoot, entry.Name()))
		if err != nil {
			continue
		}
		if strings.Contains(target, controlDir) || strings.Contains(target, string(filepath.Separator)+"ns"+string(filepath.Separator)) || strings.HasPrefix(target, "socket:") {
			return fmt.Errorf("sensitive descriptor reached payload: fd=%d target=%s", fd, target)
		}
	}
	return nil
}

func emitStage(stage, result, errnoClass string, fields map[string]any) {
	out := map[string]any{"stage": stage, "result": result}
	if errnoClass != "" {
		out["errno_class"] = errnoClass
	}
	for key, value := range fields {
		out[key] = value
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}

func expectControlByte(file *os.File, expected byte) error {
	buf := []byte{0}
	for {
		n, err := file.Read(buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("read %d bytes, want one", n)
		}
		if buf[0] != expected {
			return fmt.Errorf("got 0x%02x, want 0x%02x", buf[0], expected)
		}
		return nil
	}
}

func processExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 127
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "namespace-composition-probe: "+format+"\n", args...)
	os.Exit(1)
}
