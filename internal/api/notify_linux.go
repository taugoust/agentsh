//go:build linux && cgo

package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/netmonitor"
	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/wraphandoff"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// recoverTimeout is the maximum time to spend persisting a panic event
// in the recovery path. Prevents a slow store from blocking broker delivery.
const recoverTimeout = 5 * time.Second

// This prevents blocking forever if the wrapper fails to set up seccomp.
const recvFDTimeout = 10 * time.Second

// notifyEmitterAdapter adapts the API's event store/broker to the unix handler's Emitter interface.
type notifyEmitterAdapter struct {
	store        eventStore
	broker       eventBroker
	runtimeState session.CommandRuntimeState
	sensitive    func() bool
}

func (a *notifyEmitterAdapter) redact(ev types.Event) types.Event {
	if a.runtimeState != nil {
		if ev.CommandID == "" {
			ev.CommandID = a.runtimeState.CurrentCommandID()
		}
		if ev.Fields == nil {
			ev.Fields = make(map[string]any)
		}
		a.runtimeState.InjectTraceContext(ev.Fields)
	}
	return redactSensitiveExecEvent(ev, a.sensitive != nil && a.sensitive())
}

func (a *notifyEmitterAdapter) AppendEvent(ctx context.Context, ev types.Event) error {
	return a.store.AppendEvent(ctx, a.redact(ev))
}

func (a *notifyEmitterAdapter) Publish(ev types.Event) {
	a.broker.Publish(a.redact(ev))
}

// createExecveHandler creates an ExecveHandler from the configuration.
// Returns nil if the config is not valid or policy is nil.
func createExecveHandler(cfg config.ExecveConfig, pol *policy.Engine, approvalMgr *approvals.Manager) any {
	if !cfg.Enabled {
		return nil
	}

	// Create depth tracker for process ancestry tracking
	dt := unixmon.NewDepthTracker()

	handlerCfg := unixmon.ExecveHandlerConfig{
		MaxArgc:               cfg.MaxArgc,
		MaxArgvBytes:          cfg.MaxArgvBytes,
		OnTruncated:           cfg.OnTruncated,
		ApprovalTimeout:       cfg.ApprovalTimeout,
		ApprovalTimeoutAction: cfg.ApprovalTimeoutAction,
		InternalBypass:        cfg.InternalBypass,
	}

	// Create policy checker wrapper if policy engine exists
	var policyChecker unixmon.PolicyChecker
	if pol != nil {
		policyChecker = &policyEngineWrapper{engine: pol}
	}

	h := unixmon.NewExecveHandler(handlerCfg, policyChecker, dt, nil)
	if pol != nil {
		if tc := pol.TransparentOverrides(); tc != nil {
			h.SetTransparentOverrides(&netmonitor.TransparentOverrides{
				Add:    tc.Add,
				Remove: tc.Remove,
			})
		}
	}
	if approvalMgr != nil {
		h.SetApprover(&approvalRequesterAdapter{mgr: approvalMgr})
	}
	return h
}

// policyEngineWrapper adapts policy.Engine to unixmon.PolicyChecker.
type policyEngineWrapper struct {
	engine *policy.Engine
}

func (w *policyEngineWrapper) CheckExecve(filename string, argv []string, depth int) unixmon.PolicyDecision {
	return w.toUnixPolicyDecision(w.engine.CheckExecve(filename, argv, depth))
}

func (w *policyEngineWrapper) CheckExecveWithAliases(filename string, aliases []string, argv []string, depth int) unixmon.PolicyDecision {
	return w.toUnixPolicyDecision(w.engine.CheckExecveWithAliases(filename, aliases, argv, depth))
}

func (w *policyEngineWrapper) CheckExecveWithProvenance(filename string, argv []string, depth int, provenance string) unixmon.PolicyDecision {
	return w.toUnixPolicyDecision(w.engine.CheckExecveWithAliasesProvenance(filename, nil, argv, depth, policy.CommandProvenance(provenance)))
}

func (w *policyEngineWrapper) CheckExecveWithAliasesAndProvenance(filename string, aliases []string, argv []string, depth int, provenance string) unixmon.PolicyDecision {
	return w.toUnixPolicyDecision(w.engine.CheckExecveWithAliasesProvenance(filename, aliases, argv, depth, policy.CommandProvenance(provenance)))
}

func (w *policyEngineWrapper) toUnixPolicyDecision(dec policy.Decision) unixmon.PolicyDecision {
	// Return both PolicyDecision (for logging) and EffectiveDecision (for enforcement)
	return unixmon.PolicyDecision{
		Decision:          string(dec.PolicyDecision),
		EffectiveDecision: string(dec.EffectiveDecision),
		Rule:              dec.Rule,
		Message:           dec.Message,
		Redirect:          dec.Redirect,
	}
}

// approvalRequesterAdapter adapts approvals.Manager to unixmon.ApprovalRequester.
type approvalRequesterAdapter struct {
	mgr           *approvals.Manager
	commandIDFunc func() string
	sensitive     func() bool
}

func (a *approvalRequesterAdapter) RequestExecApproval(ctx context.Context, req unixmon.ApprovalRequest) (bool, error) {
	commandID := ""
	if a.commandIDFunc != nil {
		commandID = a.commandIDFunc()
	}
	sensitive := a.sensitive != nil && a.sensitive()
	fields := map[string]any{
		"command": req.Command,
		"args":    auditArgumentValues(req.Args, sensitive),
		"source":  "execve",
	}
	if req.VisibleCommand != "" && req.VisibleCommand != req.Command {
		fields["visible_command"] = req.VisibleCommand
	}
	if req.SourceCommand != "" {
		fields["composition_source_command"] = req.SourceCommand
	}
	if scope, ok, scopeOptions := commandApprovalScopeOptions(req.Command, req.Args, req.Rule); ok {
		if cached, ok := a.mgr.CheckScoped(ctx, req.SessionID, commandID, scope); ok {
			return cached.Approved, nil
		}
		if invocation, invocationOK := approvals.NewCommandInvocationScope(req.Command, req.Args, req.Rule); invocationOK {
			if cached, ok := a.mgr.CheckScoped(ctx, req.SessionID, commandID, invocation); ok {
				return cached.Approved, nil
			}
		}
		for k, v := range approvals.ScopeFields(scope) {
			fields[k] = v
		}
		fields["scope_options"] = scopeOptions
	}

	apr := approvals.Request{
		ID:        "approval-" + uuid.NewString(),
		SessionID: req.SessionID,
		CommandID: commandID,
		Kind:      "command",
		Target:    req.Command,
		Rule:      req.Rule,
		Message:   req.Reason,
		Fields:    fields,
	}
	res, err := a.mgr.RequestApproval(ctx, apr)
	if err != nil {
		return false, err
	}
	return res.Approved, nil
}

// notifyHandlerRecover is the deferred recovery function for the notify handler
// goroutine. It logs the panic with a stack trace, persists an event to the
// store, and publishes it to the broker (both best-effort). Each sink is
// isolated so one panicking doesn't prevent the other from running. Extracted
// for testability.
func notifyHandlerRecover(sessID string, store eventStore, broker eventBroker) {
	r := recover()
	if r == nil {
		return
	}
	slog.Error("panic in notify handler", "recover", r, "session_id", sessID, "stack", string(debug.Stack()))
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      string(events.EventNotifyHandlerPanic),
		SessionID: sessID,
		Fields: map[string]any{
			"error": fmt.Sprint(r),
		},
	}
	// Run store and broker delivery concurrently so a slow/blocking store
	// cannot prevent broker publish. Both are best-effort with panic guards.
	delivered := make(chan struct{})
	if store != nil {
		go func() {
			defer func() { recover() }()
			ctx, cancel := context.WithTimeout(context.Background(), recoverTimeout)
			defer cancel()
			_ = store.AppendEvent(ctx, ev)
		}()
	}
	if broker != nil {
		go func() {
			defer close(delivered)
			defer func() { recover() }()
			broker.Publish(ev)
		}()
	} else {
		close(delivered)
	}
	// Wait for broker delivery (bounded) but don't wait for store.
	select {
	case <-delivered:
	case <-time.After(recoverTimeout):
	}
}

// startNotifyHandler receives the seccomp notify fd from the parent socket and
// starts the ServeNotify handler in a goroutine. It returns immediately.
// The handler runs until ctx is cancelled or the fd is closed.
// If execveHandler is non-nil, uses ServeNotifyWithExecve for execve interception.
// blockList carries the per-session seccomp block-list dispatch config; passed
// as `any` to keep extraProcConfig cross-platform (actual type on Linux is
// *unixmon.BlockListConfig). A nil or zero-ActionByNr value is treated as
// "no block-list notify routing needed" — safe for errno/kill modes which are
// kernel-side.
func startNotifyHandler(ctx context.Context, parentSock *os.File, sessID string, pol *policy.Engine, store eventStore, broker eventBroker, execveHandler any, fileMonitorCfg config.SandboxSeccompFileMonitorConfig, landlockEnabled bool, blockList any, ptraceReady chan<- error, commandJailRequired bool, approvalsMgr *approvals.Manager, sess *session.Session, expectedWrapperPID int, compositionControlRoot string, compositionSetup *os.File, configureComposition compositionConfigurer) <-chan struct{} {
	return startNotifyHandlerForState(ctx, parentSock, sessID, pol, store, broker, execveHandler, fileMonitorCfg, landlockEnabled, blockList, ptraceReady, commandJailRequired, approvalsMgr, sess, sess, expectedWrapperPID, compositionControlRoot, compositionSetup, configureComposition)
}

func startNotifyHandlerForState(ctx context.Context, parentSock *os.File, sessID string, pol *policy.Engine, store eventStore, broker eventBroker, execveHandler any, fileMonitorCfg config.SandboxSeccompFileMonitorConfig, landlockEnabled bool, blockList any, ptraceReady chan<- error, commandJailRequired bool, approvalsMgr *approvals.Manager, sess *session.Session, runtimeState session.CommandRuntimeState, expectedWrapperPID int, compositionControlRoot string, compositionSetup *os.File, configureComposition compositionConfigurer) <-chan struct{} {
	done := make(chan struct{})
	if parentSock == nil {
		if compositionSetup != nil {
			_ = compositionSetup.Close()
		}
		close(done)
		return done
	}

	// Run the entire receive and serve logic in a goroutine to return immediately
	go func() {
		defer close(done)
		defer notifyHandlerRecover(sessID, store, broker)
		defer parentSock.Close()
		// Ensure the pre-fork release waiter is always signaled on setup exits.
		readySignaled := false
		defer func() {
			if ptraceReady != nil && !readySignaled {
				select {
				case ptraceReady <- fmt.Errorf("notify handler exited before pre-fork lineage readiness"):
				default:
				}
			}
		}()
		slog.Debug("notify handler started", "session_id", sessID)

		// The command runner pins the exact PID returned by cmd.Start. A socketpair's
		// SO_PEERCRED reflects its creator and does not change when the child inherits
		// an endpoint, so it is only a legacy fallback when no started PID was bound.
		wrapperPID := expectedWrapperPID
		if wrapperPID <= 0 {
			ucred, err := unix.GetsockoptUcred(int(parentSock.Fd()), unix.SOL_SOCKET, unix.SO_PEERCRED)
			if err != nil {
				slog.Debug("failed to get socket peer credentials", "error", err)
			} else {
				wrapperPID = int(ucred.Pid)
			}
		}
		slog.Debug("bound notify wrapper PID", "wrapper_pid", wrapperPID, "session_id", sessID)

		// Set SO_RCVTIMEO directly on the socket. unixmon.RecvFD calls recvmsg
		// on the raw fd, bypassing Go's netpoll — so SetReadDeadline wouldn't
		// apply. SO_RCVTIMEO is a kernel-level timeout that works with raw
		// blocking recvmsg.
		tv := unix.NsecToTimeval(recvFDTimeout.Nanoseconds())
		if err := unix.SetsockoptTimeval(int(parentSock.Fd()), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			slog.Debug("failed to set SO_RCVTIMEO on notify socket", "error", err, "session_id", sessID)
			// Don't return - RecvFD will still work, just without a timeout
		}

		// Phase one authenticates the trusted wrapper parent before it forks.
		// Cgroup/eBPF and hybrid-ptrace release therefore apply to the parent
		// which every payload and lookup worker must inherit from.
		slog.Debug("waiting for pre-fork lineage handoff", "session_id", sessID)
		prelude, err := wraphandoff.RecvLocalPrelude(parentSock)
		if err != nil || prelude == nil || prelude.Sender == nil || int(prelude.Sender.Pid) != wrapperPID || prelude.Metadata.CommandJail != commandJailRequired {
			slog.Debug("invalid pre-fork lineage handoff", "error", err, "wrapper_pid", wrapperPID, "session_id", sessID)
			return
		}
		if ptraceReady != nil {
			select {
			case ptraceReady <- nil:
				readySignaled = true
			default:
			}
		} else {
			if n, releaseErr := parentSock.Write([]byte{'G'}); releaseErr != nil || n != 1 {
				slog.Debug("release pre-fork lineage barrier failed", "error", releaseErr, "bytes", n, "session_id", sessID)
				return
			}
		}

		payloadTimeout := unix.NsecToTimeval((30 * time.Second).Nanoseconds())
		_ = unix.SetsockoptTimeval(int(parentSock.Fd()), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &payloadTimeout)
		payload, err := wraphandoff.RecvLocalPayload(parentSock)
		if err != nil || payload == nil || payload.NotifyFD == nil || payload.Sender == nil {
			if payload != nil {
				payload.Close()
			}
			slog.Debug("failed to receive payload lineage handoff", "error", err, "session_id", sessID)
			return
		}
		defer payload.Close()
		payloadPID := int(payload.Sender.Pid)
		if payload.Metadata.CommandJail != commandJailRequired || !payloadLineageMatches(payloadPID, wrapperPID) {
			slog.Debug("payload lineage handoff rejected", "payload_pid", payloadPID, "wrapper_pid", wrapperPID, "session_id", sessID)
			return
		}
		notifyFD := payload.NotifyFD
		payload.NotifyFD = nil
		lookupEndpoint := payload.FileLookup
		payload.FileLookup = nil
		defer notifyFD.Close()
		defer func() {
			if lookupEndpoint != nil {
				_ = lookupEndpoint.Close()
			}
		}()
		slog.Debug("received child-owned notify fd", "fd", notifyFD.Fd(), "payload_pid", payloadPID, "wrapper_pid", wrapperPID, "session_id", sessID)
		_ = unix.SetsockoptTimeval(int(parentSock.Fd()), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{})

		var h *unixmon.ExecveHandler
		if execveHandler != nil {
			h, _ = execveHandler.(*unixmon.ExecveHandler)
		}
		if compositionSetup != nil {
			defer compositionSetup.Close()
		}
		if configureComposition != nil {
			if err := configureComposition(h, compositionSetup, wrapperPID); err != nil {
				if ptraceReady != nil {
					select {
					case ptraceReady <- err:
					default:
					}
				}
				slog.Debug("composition notify setup failed", "error", err, "wrapper_pid", wrapperPID, "session_id", sessID)
				return
			}
			if h != nil {
				defer h.CloseComposition()
			}
		} else if compositionSetup != nil {
			err := fmt.Errorf("E_COMPOSITION_BACKEND_UNAVAILABLE: composition setup channel has no bound configurer")
			if ptraceReady != nil {
				select {
				case ptraceReady <- err:
				default:
				}
			}
			return
		}

		// Close the notify FD when context is cancelled to unblock any stuck
		// NotifReceive ioctl. The done channel ensures this goroutine exits
		// if the handler returns early (error/setup failure) while context
		// is still active.
		handlerDone := make(chan struct{})
		defer close(handlerDone)
		go func() {
			select {
			case <-ctx.Done():
				notifyFD.Close()
			case <-handlerDone:
			}
		}()

		if runtimeState == nil {
			runtimeState = sess
		}
		emitter := &notifyEmitterAdapter{store: store, broker: broker, runtimeState: runtimeState}
		if runtimeState != nil {
			emitter.sensitive = runtimeState.CurrentExecutionSensitive
		}

		var fileLookupBroker unixmon.FileLookupBroker
		if lookupEndpoint != nil {
			candidate, brokerErr := unixmon.NewFileLookupBroker(unixmon.FileLookupBrokerConfig{
				Endpoint: lookupEndpoint, ExpectedWrapperPID: wrapperPID,
				ExpectedPayloadPID: payloadPID, Timeout: 250 * time.Millisecond,
			})
			if brokerErr != nil {
				slog.Debug("file lookup broker unavailable", "error", brokerErr, "session_id", sessID)
				_ = lookupEndpoint.Close()
			} else {
				fileLookupBroker = candidate
				lookupEndpoint = nil // ownership transferred to the broker
				defer fileLookupBroker.Close()
			}
		}

		// Create file handler if configured and hand off the optional probe API.
		// Handler decisions deliberately do not consume it until phase 5.
		fileHandler := createFileHandlerForState(fileMonitorCfg, pol, emitter, landlockEnabled, approvalsMgr, sess, runtimeState)
		if fileHandler != nil && fileLookupBroker != nil {
			fileHandler.SetFileLookupProbe(fileLookupBroker)
		}
		if fileHandler != nil && compositionControlRoot != "" {
			fileHandler.SetInternalControlAccess(compositionControlRoot, expectedWrapperPID)
		}

		// Configure the execve handler after composition has published its
		// source-attribution registry.
		if h != nil {
			h.SetEmitter(emitter)
			if fileHandler != nil {
				fileHandler.SetCompositionPathRegistry(h.CompositionPathRegistry())
			}
			if approvalsMgr != nil {
				var commandIDFunc func() string
				if runtimeState != nil {
					commandIDFunc = runtimeState.CurrentCommandID
				}
				adapter := &approvalRequesterAdapter{mgr: approvalsMgr, commandIDFunc: commandIDFunc}
				if runtimeState != nil {
					adapter.sensitive = runtimeState.CurrentExecutionSensitive
				}
				h.SetApprover(adapter)
			}
			// The wrapper remains the broker parent; the exact payload child is
			// the depth-zero process which installs and inherits the filter.
			if payloadPID > 0 {
				h.RegisterSession(payloadPID, sessID)
			}

			// Create stub symlink for execve redirect
			stubPath, err := exec.LookPath("agentsh-stub")
			if err == nil {
				// Normalize to absolute path in case LookPath returns relative
				if !filepath.IsAbs(stubPath) {
					if abs, err := filepath.Abs(stubPath); err == nil {
						stubPath = abs
					}
				}
				unixmon.SetStubBinaryPath(stubPath)
				symlinkPath, cleanup, symlinkErr := unixmon.CreateStubSymlink(stubPath)
				if symlinkErr == nil {
					h.SetStubSymlinkPath(symlinkPath)
					defer cleanup()
				} else {
					slog.Warn("exec: failed to create stub symlink", "error", symlinkErr, "session_id", sessID)
				}
			} else {
				slog.Warn("exec: agentsh-stub not found, redirect will deny", "error", err, "session_id", sessID)
			}
		}

		// Probe the exact pre-exec payload child, not the non-tracee broker
		// parent. A failure retains the existing fail-closed startup behavior.
		if payloadPID > 0 {
			pvrErr, memErr := probeMemoryAccess(payloadPID)
			if pvrErr != nil && memErr != nil {
				if fileHandler != nil || h != nil || pol != nil {
					slog.Error("seccomp notify: ProcessVMReadv and /proc/mem both failed — "+
						"handler cannot read tracee memory for path resolution",
						"payload_pid", payloadPID,
						"pvr_error", pvrErr, "mem_error", memErr,
						"session_id", sessID,
						"hint", "check kernel.yama.ptrace_scope, ensure CAP_SYS_PTRACE, "+
							"or set sandbox.seccomp.file_monitor.enabled: false")
					return
				}
				slog.Warn("ProcessVMReadv probe failed, monitoring may be degraded",
					"payload_pid", payloadPID, "pvr_error", pvrErr, "mem_error", memErr)
			} else if pvrErr != nil {
				if pol != nil {
					slog.Warn("ProcessVMReadv failed — socket monitoring will be degraded "+
						"(ReadSockaddr requires ProcessVMReadv), /proc/mem fallback works for file monitoring",
						"payload_pid", payloadPID, "pvr_error", pvrErr)
				} else {
					slog.Debug("ProcessVMReadv failed but /proc/mem fallback works",
						"payload_pid", payloadPID, "pvr_error", pvrErr)
				}
			}
		}

		// Start ServeNotifyWithExecve before acknowledging the child-owned
		// listener. The trusted parent cannot release payload exec until this ACK.
		serveDone := make(chan struct{})
		// Type-assert the cross-platform any back to the concrete Linux type.
		// Stub/non-Linux callers pass nil; core.go on Linux always passes a
		// non-nil *BlockListConfig (possibly with empty ActionByNr).
		bl, _ := blockList.(*unixmon.BlockListConfig)
		if bl != nil && len(bl.ActionByNr) > 0 && emitter == nil {
			slog.Warn("seccomp: on_block=log/log_and_kill selected but no event emitter wired; events will be dropped",
				"session_id", sessID)
		}
		go func() {
			defer close(serveDone)
			slog.Debug("starting ServeNotifyWithExecve", "session_id", sessID, "has_execve_handler", h != nil, "has_file_handler", fileHandler != nil, "has_policy", pol != nil)
			unixmon.ServeNotifyWithExecve(ctx, notifyFD, sessID, pol, emitter, h, fileHandler, bl)
			slog.Debug("ServeNotifyWithExecve returned", "session_id", sessID)
		}()

		n, ackErr := parentSock.Write([]byte{1})
		if ackErr != nil || n != 1 {
			if ackErr == nil {
				ackErr = io.ErrShortWrite
			}
			slog.Debug("notify: payload ACK write failed", "error", ackErr, "session_id", sessID)
			return
		}

		<-serveDone // wait for ServeNotifyWithExecve to finish
	}()
	return done
}

func payloadLineageMatches(payloadPID, wrapperPID int) bool {
	if payloadPID <= 0 || wrapperPID <= 0 || payloadPID == wrapperPID {
		return false
	}
	status, err := readWrapperProcStatus(payloadPID)
	return err == nil && status.PPid == wrapperPID
}

func readCommandJailREADY(r io.Reader) (int, error) {
	if r == nil {
		return 0, io.ErrUnexpectedEOF
	}
	buf := []byte{0}
	for {
		n, err := r.Read(buf)
		if err != nil && errors.Is(err, syscall.EINTR) {
			continue
		}
		if n == 1 {
			if buf[0] != 'R' {
				return 1, fmt.Errorf("unexpected READY byte: got 0x%02x, expected 'R'", buf[0])
			}
			return 1, nil
		}
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return n, fmt.Errorf("read READY byte: %w", err)
	}
}
