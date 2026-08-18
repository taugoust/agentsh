//go:build linux && cgo

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	lookupproto "github.com/agentsh/agentsh/internal/filelookup"
	"golang.org/x/sys/unix"
)

func runTrustedPayloadParent(controlFD int, launch *lineageLaunch, environment []string) (int, error) {
	if launch == nil || launch.cfg == nil || launch.baseFilter == nil || launch.lookup == nil {
		return 127, errors.New("trusted payload launch is incomplete")
	}
	if err := markNonStdioCloseOnExec(); err != nil {
		return 127, fmt.Errorf("protect trusted parent descriptors: %w", err)
	}

	baseProgram := launch.baseFilter.BPFProgram()
	var frozenProgram []byte
	if launch.frozenFilter != nil {
		frozenProgram = launch.frozenFilter.BPFProgram()
	}
	child, err := forkPayload(payloadForkConfig{
		controlFD:        controlFD,
		brokerParentFD:   launch.lookup.parentFD(),
		brokerTransferFD: launch.lookup.transferFD(),
		commandJail:      launch.cfg.CommandJail != nil && launch.cfg.CommandJail.Required,
		waitKillable:     launch.baseFilter.WaitKillable(),
		baseProgram:      baseProgram,
		frozenProgram:    frozenProgram,
		execPath:         launch.commandPath,
		argv:             launch.args,
		env:              environment,
	})
	if err != nil {
		return 127, err
	}
	defer child.Close()
	if child.sync != nil {
		_ = unix.SetsockoptTimeval(int(child.sync.Fd()), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 30})
	}
	abort := func(cause error) (int, error) {
		_ = unix.Kill(child.pid, unix.SIGKILL)
		_ = waitExactChild(child.pid, 2*time.Second)
		return 127, cause
	}

	attestation, err := child.readAttestation()
	if err != nil {
		return abort(fmt.Errorf("payload context attestation: %w", err))
	}
	lookupReady := launch.frozenFilter != nil && launch.lookup.baseline != nil
	if lookupReady {
		if err := launch.lookup.attestPayload(child, attestation); err != nil {
			log.Printf("file lookup broker context parity unavailable: %v", err)
			lookupReady = false
		}
	}
	if !lookupReady {
		launch.lookup.disabled.Store(true)
		if launch.lookup.unsupportedReason == lookupproto.ReasonNone {
			launch.lookup.unsupportedReason = lookupproto.ReasonContextUnavailable
		}
		if launch.cfg.FileMonitorEnabled {
			log.Printf("file lookup broker disabled (reason=%d)", launch.lookup.unsupportedReason)
		}
	}
	// The trusted broker parent is non-dumpable before the endpoint is exposed.
	// The already-forked payload retains its inherited dumpability so existing
	// supervisor memory-access checks and file policy startup semantics do not
	// regress.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		lookupReady = false
		launch.lookup.disabled.Store(true)
	}
	if err := child.sendLookupReadiness(lookupReady); err != nil {
		return abort(fmt.Errorf("send payload lookup readiness: %w", err))
	}
	if err := child.waitHandoffStatus(); err != nil {
		return abort(fmt.Errorf("payload notify handoff: %w", err))
	}
	launch.lookup.closeTransfer()
	_ = unix.Close(controlFD)

	if launch.cfg.SignalFilterEnabled {
		// The main filter and signal filter are never admitted together by the
		// supervisor's filter-composition gate. Retain an explicit diagnostic if
		// a mismatched configuration nevertheless reaches this child-only path.
		log.Printf("signal filter unavailable: incompatible lineage handoff configuration")
		if signalFD, _ := signalSockFD(); signalFD >= 0 {
			_ = unix.Close(signalFD)
		}
	}
	if err := child.release(); err != nil {
		return abort(fmt.Errorf("release payload exec barrier: %w", err))
	}
	_ = unix.SetsockoptTimeval(int(child.sync.Fd()), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{})
	log.Printf("seccomp: payload filter loaded (child_pid=%d, lookup_broker=%t)", child.pid, lookupReady)

	return waitPayloadAndServeBroker(child.pid, launch.lookup, lookupReady)
}

func waitPayloadAndServeBroker(payloadPID int, broker *lookupBrokerState, lookupReady bool) (int, error) {
	if payloadPID <= 0 {
		return 127, errors.New("invalid payload pid")
	}
	signals := make(chan os.Signal, 16)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGWINCH)
	defer signal.Stop(signals)

	for {
		for {
			select {
			case received := <-signals:
				if received != nil {
					if value, ok := received.(syscall.Signal); ok {
						_ = unix.Kill(payloadPID, value)
					}
				}
			default:
				goto signalsDrained
			}
		}
	signalsDrained:
		var status syscall.WaitStatus
		waited, err := syscall.Wait4(payloadPID, &status, syscall.WNOHANG, nil)
		if waited == payloadPID {
			return lookupProcessExitCode(status), nil
		}
		if err != nil && !errors.Is(err, syscall.EINTR) {
			if errors.Is(err, syscall.ECHILD) {
				return 127, errors.New("payload was reaped outside the trusted parent")
			}
			return 127, fmt.Errorf("wait exact payload child: %w", err)
		}

		if !lookupReady || broker == nil || broker.brokerEndpoint == nil || broker.disabled.Load() {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		poll := []unix.PollFd{{Fd: int32(broker.brokerEndpoint.Fd()), Events: unix.POLLIN}}
		n, pollErr := unix.Poll(poll, 10)
		if errors.Is(pollErr, unix.EINTR) {
			continue
		}
		if pollErr != nil {
			broker.disabled.Store(true)
			continue
		}
		if n == 0 {
			continue
		}
		if poll[0].Revents&unix.POLLIN != 0 {
			if err := broker.serveOne(); err != nil && !errors.Is(err, unix.EAGAIN) {
				broker.disabled.Store(true)
			}
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			broker.disabled.Store(true)
		}
	}
}
