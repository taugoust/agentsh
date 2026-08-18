//go:build linux && cgo

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	lookupproto "github.com/agentsh/agentsh/internal/filelookup"
	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	"github.com/agentsh/agentsh/internal/wraphandoff"
	"golang.org/x/sys/unix"
)

type lineageLaunch struct {
	cfg          *WrapperConfig
	command      string
	commandPath  string
	args         []string
	baseFilter   *unixmon.PreparedFilterProgram
	frozenFilter *unixmon.PreparedFilterProgram
	lookup       *lookupBrokerState
}

func main() {
	if err := runLineageMain(); err != nil {
		fatalf("%v", err)
	}
}

func runLineageMain() error {
	log.SetFlags(0)
	setupLogging()
	if len(os.Args) < 3 || os.Args[1] != "--" {
		return fmt.Errorf("usage: %s -- <command> [args...]", os.Args[0])
	}
	controlFD, err := notifySockFD()
	if err != nil {
		return fmt.Errorf("notify fd: %w", err)
	}
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if !cfg.LineageHandoff {
		// Feasibility probes and third-party callers which speak the legacy
		// one-packet protocol remain compatible. Production API-generated wrapper
		// configs explicitly opt into the authenticated two-phase topology.
		legacyMain()
		return nil
	}

	yamaActive := isYamaActive()
	if cfg.ServerPID > 0 && yamaActive {
		ptracerTarget := uintptr(cfg.ServerPID)
		if cfg.CommandJail != nil && cfg.CommandJail.Required {
			ptracerTarget = ^uintptr(0)
			_ = os.Setenv("AGENTSH_PTRACER_ANY", "1")
		}
		if err := unix.Prctl(unix.PR_SET_PTRACER, ptracerTarget, 0, 0, 0); err != nil {
			log.Printf("PR_SET_PTRACER: %v (Yama active, ProcessVMReadv may fail)", err)
		}
	}

	blockedSyscalls := cfg.BlockedSyscalls
	if cfg.CommandJail != nil && cfg.CommandJail.Required {
		blockedSyscalls = withoutCommandJailSetupSyscalls(blockedSyscalls)
	}
	blockedNumbers, skipped := seccompkg.ResolveSyscalls(blockedSyscalls)
	if len(skipped) > 0 {
		log.Printf("warning: skipped unknown syscalls: %v", skipped)
	}

	command := os.Args[2]
	commandPath, err := resolveCommandPath(command)
	if err != nil {
		return fmt.Errorf("resolve command %q: %w", command, err)
	}
	args := applyArgv0Override(os.Args[2:], os.Getenv("AGENTSH_UNIXWRAP_ARGV0"))
	setupPtracerPreload(cfg.ServerPID, yamaActive)

	// All final security setup, the raw payload fork, and every worker fork are
	// issued from this exact thread. No payload code ever runs on a Go runtime
	// thread in the trusted parent.
	runtime.LockOSThread()
	lookup := prepareLookupBroker(cfg)
	defer lookup.close()

	var preparedLandlock *preparedLandlockRuleset
	if cfg.LandlockEnabled && cfg.LandlockABI > 0 {
		preparedLandlock, err = prepareLandlock(cfg)
		if err != nil {
			log.Printf("landlock: %v (continuing without)", err)
			preparedLandlock = nil
		}
	}
	if cfg.CommandJail != nil && cfg.CommandJail.Required {
		if err := prepareCommandJail(cfg.CommandJail, commandPath); err != nil {
			return fmt.Errorf("prepare command jail: %w", err)
		}
	}

	onBlock, _ := seccompkg.ParseOnBlock(cfg.OnBlock)
	filterConfig := unixmon.FilterConfig{
		UnixSocketEnabled:  cfg.UnixSocketEnabled,
		ExecveEnabled:      cfg.ExecveEnabled,
		FileMonitorEnabled: cfg.FileMonitorEnabled,
		InterceptMetadata:  cfg.InterceptMetadata,
		WriteOnlyOpens:     cfg.WriteOnlyOpens,
		BlockIOUring:       cfg.BlockIOUring,
		BlockedSyscalls:    blockedNumbers,
		BlockedFamilies:    cfg.BlockedFamilies,
		SocketRules:        cfg.SocketRules,
		OnBlockAction:      onBlock,
		WaitKillable:       cfg.WaitKillable,
		WaitKillableSource: cfg.WaitKillableSource,
	}
	baseFilter, err := unixmon.PrepareFilterProgramWithConfig(filterConfig)
	if errors.Is(err, unixmon.ErrUnsupported) {
		if cfg.CommandJail != nil && cfg.CommandJail.Required {
			return fmt.Errorf("strict command jail requires seccomp user notification: %w", err)
		}
		log.Printf("seccomp user-notify unsupported; exiting 0 for monitor-only")
		return nil
	}
	if err != nil {
		return fmt.Errorf("prepare seccomp filter: %w", err)
	}
	if !baseFilter.NeedsNotifyFD() {
		// Current wrapper admission always supplies a notify feature. Treat a
		// mismatched configuration as a setup error rather than forking a payload
		// whose supervisor is waiting for a listener that can never arrive.
		return errors.New("wrapper configuration produced no notification capability")
	}
	var frozenFilter *unixmon.PreparedFilterProgram
	if lookup.worker != nil {
		frozenConfig := filterConfig
		frozenConfig.FreezeLookupSecurityContext = true
		frozenFilter, err = unixmon.PrepareFilterProgramWithConfig(frozenConfig)
		if err != nil {
			lookup.unsupportedReason = lookupproto.ReasonWorkerUnavailable
			frozenFilter = nil
		}
	}

	commandJail := cfg.CommandJail != nil && cfg.CommandJail.Required
	if err := wraphandoff.SendLocalPrelude(controlFD, wraphandoff.LocalMetadata{CommandJail: commandJail}); err != nil {
		return fmt.Errorf("send pre-fork lineage capability: %w", err)
	}
	_ = unix.SetsockoptTimeval(controlFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 30})
	if err := waitForControlByte(func(buffer []byte) (int, error) { return unix.Read(controlFD, buffer) }, 'G'); err != nil {
		return fmt.Errorf("pre-fork cgroup barrier failed: %w", err)
	}
	_ = unix.SetsockoptTimeval(controlFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{})

	launch := &lineageLaunch{
		cfg: cfg, command: command, commandPath: commandPath, args: args,
		baseFilter: baseFilter, frozenFilter: frozenFilter, lookup: lookup,
	}
	if commandJail {
		exitCode, err := runCommandJailStage(controlFD, preparedLandlock, launch)
		if err != nil {
			return fmt.Errorf("command jail: %w", err)
		}
		os.Exit(exitCode)
	}

	if err := lookup.pinProcRoot(); err != nil {
		lookup.unsupportedReason = lookupproto.ReasonContextUnavailable
	}
	if preparedLandlock != nil {
		enforcePreparedLandlock(preparedLandlock)
		preparedLandlock = nil
	}
	if lookup.procRoot != nil && lookup.baseline == nil && lookup.unsupportedReason == lookupproto.ReasonContextUnavailable {
		if err := lookup.finalizeContext(); err != nil {
			log.Printf("file lookup broker unavailable: %v", err)
		}
	}

	exitCode, err := runTrustedPayloadParent(controlFD, launch, payloadEnvironment(os.Environ(), false))
	if err != nil {
		return err
	}
	// os.Exit is required to preserve signal-derived shell status exactly.
	os.Exit(exitCode)
	return nil
}

func payloadEnvironment(environment []string, commandJail bool) []string {
	if commandJail {
		return scrubCommandJailEnv(environment)
	}
	blocked := map[string]bool{}
	for _, key := range append([]string(nil), commandJailReservedEnv...) {
		blocked[strings.ToUpper(key)] = true
	}
	out := make([]string, 0, len(environment))
	for _, entry := range environment {
		key, _, ok := strings.Cut(entry, "=")
		if ok && blocked[strings.ToUpper(strings.TrimSpace(key))] {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func setControlTimeout(fd int, timeout time.Duration) {
	if fd >= 0 {
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: int64(timeout / time.Second)})
	}
}
