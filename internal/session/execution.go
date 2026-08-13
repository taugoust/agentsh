package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

var (
	ErrWorkspaceBusy       = errors.New("workspace has active or queued writers")
	ErrWorkspaceFinalizing = errors.New("workspace is finalizing")
	ErrWorkspaceSealed     = errors.New("workspace is sealed")
)

// ExecutionQueueFailure classifies an execution request that left admission
// before dispatch. Callers can inspect this type without parsing context error
// strings.
type ExecutionQueueFailure string

const (
	ExecutionQueueCancelled ExecutionQueueFailure = "cancelled"
	ExecutionQueueDeadline  ExecutionQueueFailure = "deadline_exceeded"
)

// ExecutionQueueError is returned only while a request is queued. Cause keeps
// both context.Canceled/context.DeadlineExceeded and a more specific
// CancelCause (for example capability revocation) available through errors.Is.
type ExecutionQueueError struct {
	Failure ExecutionQueueFailure
	Cause   error
}

func (e *ExecutionQueueError) Error() string {
	if e == nil || e.Cause == nil {
		return "execution admission cancelled"
	}
	return fmt.Sprintf("execution admission %s: %v", e.Failure, e.Cause)
}

func (e *ExecutionQueueError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// ExecutionAdmission selects either the exclusive legacy/root path or one
// authenticated child lane. SharedLimit is an aggregate session cap; LaneID is
// also a serialization key, so one child can never run two commands at once.
type ExecutionAdmission struct {
	CommandID   string
	LaneID      string
	Shared      bool
	SharedLimit int
}

// CommandRuntimeState is the command-local state consumed by execution
// enforcement. Session implements it for exclusive legacy paths. CommandRuntime
// implements it for overlapping child lanes, preventing one command from
// overwriting another command's attribution, redaction, provenance, PID, or
// trace context.
type CommandRuntimeState interface {
	SetCurrentCommandID(string)
	CurrentCommandID() string
	SetCurrentExecutionSensitive(bool)
	CurrentExecutionSensitive() bool
	SetCurrentCommandProvenance(policy.CommandProvenance)
	CurrentCommandProvenance() policy.CommandProvenance
	SetCurrentSandboxComposition(string)
	CurrentSandboxComposition() string
	SetCurrentProcessPID(int)
	CurrentProcessPID() int
	SetCurrentTraceContext(string, string, string)
	CurrentTraceContext() (string, string, string)
	InjectTraceContext(map[string]any)
}

// CommandRuntime holds state for one shared execution. It intentionally has no
// reference to its bearer capability; admission and capability lifecycles are
// independent layers and both must remain live for a command to run.
type CommandRuntime struct {
	mu sync.Mutex

	commandID          string
	processPID         int
	sensitive          bool
	provenance         policy.CommandProvenance
	sandboxComposition string
	traceID            string
	spanID             string
	traceFlags         string
}

func newCommandRuntime(commandID string) *CommandRuntime {
	return &CommandRuntime{commandID: commandID}
}

func (r *CommandRuntime) SetCurrentCommandID(commandID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	// Shared execution attribution is minted with the lease and is immutable.
	// Retain the setter for the CommandRuntimeState interface, but never let a
	// handler or overlapping command replace an established identity.
	if r.commandID == "" {
		r.commandID = commandID
	}
	r.mu.Unlock()
}

func (r *CommandRuntime) CurrentCommandID() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.commandID
}

func (r *CommandRuntime) SetCurrentExecutionSensitive(sensitive bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.sensitive = sensitive
	r.mu.Unlock()
}

func (r *CommandRuntime) CurrentExecutionSensitive() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sensitive
}

func (r *CommandRuntime) SetCurrentCommandProvenance(provenance policy.CommandProvenance) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.provenance = provenance
	r.mu.Unlock()
}

func (r *CommandRuntime) CurrentCommandProvenance() policy.CommandProvenance {
	if r == nil {
		return policy.CommandProvenanceNone
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.provenance
}

func (r *CommandRuntime) SetCurrentSandboxComposition(mode string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.sandboxComposition = mode
	r.mu.Unlock()
}

func (r *CommandRuntime) CurrentSandboxComposition() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sandboxComposition
}

func (r *CommandRuntime) SetCurrentProcessPID(pid int) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.processPID = pid
	r.mu.Unlock()
}

func (r *CommandRuntime) CurrentProcessPID() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.processPID
}

func (r *CommandRuntime) SetCurrentTraceContext(traceID, spanID, traceFlags string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.traceID = traceID
	r.spanID = spanID
	r.traceFlags = traceFlags
	r.mu.Unlock()
}

func (r *CommandRuntime) CurrentTraceContext() (traceID, spanID, traceFlags string) {
	if r == nil {
		return "", "", ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.traceID, r.spanID, r.traceFlags
}

func (r *CommandRuntime) InjectTraceContext(fields map[string]any) {
	if r == nil || fields == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.traceID != "" {
		fields["trace_id"] = r.traceID
	}
	if r.spanID != "" {
		fields["span_id"] = r.spanID
	}
	if r.traceFlags != "" {
		fields["trace_flags"] = r.traceFlags
	}
}

// ExecutionLease owns one admitted slot. Release is idempotent so cleanup paths
// can safely converge without opening an extra slot.
type ExecutionLease struct {
	once sync.Once

	session *Session
	shared  bool
	laneID  string
	state   *CommandRuntime
}

func (l *ExecutionLease) Shared() bool { return l != nil && l.shared }

func (l *ExecutionLease) Runtime() *CommandRuntime {
	if l == nil {
		return nil
	}
	return l.state
}

func (l *ExecutionLease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		if l.session != nil {
			l.session.releaseExecution(l)
		}
	})
}

func executionQueueError(ctx context.Context) *ExecutionQueueError {
	failure := ExecutionQueueCancelled
	ctxErr := ctx.Err()
	if errors.Is(ctxErr, context.DeadlineExceeded) {
		failure = ExecutionQueueDeadline
	}
	cause := context.Cause(ctx)
	if cause == nil {
		cause = ctxErr
	} else if ctxErr != nil && !errors.Is(cause, ctxErr) {
		cause = errors.Join(ctxErr, cause)
	}
	return &ExecutionQueueError{Failure: failure, Cause: cause}
}

func (s *Session) executionChangedLocked() chan struct{} {
	if s.execAdmissionChanged == nil {
		s.execAdmissionChanged = make(chan struct{})
	}
	return s.execAdmissionChanged
}

func (s *Session) notifyExecutionChangedLocked() {
	changed := s.executionChangedLocked()
	close(changed)
	s.execAdmissionChanged = make(chan struct{})
}

func (s *Session) canAdmitExecutionLocked(req ExecutionAdmission) bool {
	if s.workspaceFinalizing || s.workspaceSealed {
		return false
	}
	if !req.Shared {
		return !s.execExclusiveActive && s.execSharedActive == 0
	}
	if s.execExclusiveActive || s.execExclusiveWaiters != 0 || s.execSharedActive >= req.SharedLimit {
		return false
	}
	_, laneActive := s.execActiveLanes[req.LaneID]
	return !laneActive
}

// AcquireExecution is the context-aware admission primitive for all session
// commands. Exclusive requests wait for every child lane to drain. Shared
// requests require a non-empty authenticated lane and are bounded both per lane
// and by SharedLimit. Waiting cancellation is typed and can never acquire later.
func (s *Session) AcquireExecution(ctx context.Context, req ExecutionAdmission) (*ExecutionLease, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if req.Shared {
		if req.LaneID == "" {
			return nil, fmt.Errorf("shared execution lane id is required")
		}
		if req.SharedLimit <= 0 {
			return nil, fmt.Errorf("shared execution aggregate limit must be positive")
		}
	}

	s.execAdmissionMu.Lock()
	if s.execActiveLanes == nil {
		s.execActiveLanes = make(map[string]struct{})
	}
	if s.execActiveCommands == nil {
		s.execActiveCommands = make(map[string]*CommandRuntime)
	}
	exclusiveWaiting := !req.Shared
	sharedWaiting := req.Shared
	if exclusiveWaiting {
		s.execExclusiveWaiters++
		// Stop newly arriving shared work from extending the drain indefinitely.
		s.notifyExecutionChangedLocked()
	} else {
		s.execSharedWaiters++
	}
	s.execAdmissionMu.Unlock()

	removeWaiter := func() {
		if !exclusiveWaiting && !sharedWaiting {
			return
		}
		s.execAdmissionMu.Lock()
		switch {
		case exclusiveWaiting:
			s.execExclusiveWaiters--
			exclusiveWaiting = false
		case sharedWaiting:
			s.execSharedWaiters--
			sharedWaiting = false
		}
		s.notifyExecutionChangedLocked()
		s.execAdmissionMu.Unlock()
	}

	for {
		if ctx.Err() != nil {
			removeWaiter()
			return nil, executionQueueError(ctx)
		}

		s.execAdmissionMu.Lock()
		if s.workspaceFinalizing || s.workspaceSealed {
			sealed := s.workspaceSealed
			s.execAdmissionMu.Unlock()
			removeWaiter()
			if sealed {
				return nil, ErrWorkspaceSealed
			}
			return nil, ErrWorkspaceFinalizing
		}
		if ctx.Err() != nil {
			s.execAdmissionMu.Unlock()
			removeWaiter()
			return nil, executionQueueError(ctx)
		}
		if s.canAdmitExecutionLocked(req) {
			if exclusiveWaiting {
				s.execExclusiveWaiters--
				exclusiveWaiting = false
			} else if sharedWaiting {
				s.execSharedWaiters--
				sharedWaiting = false
			}
			state := newCommandRuntime(req.CommandID)
			lease := &ExecutionLease{session: s, shared: req.Shared, laneID: req.LaneID, state: state}
			if req.Shared {
				s.execSharedActive++
				s.execActiveLanes[req.LaneID] = struct{}{}
			} else {
				s.execExclusiveActive = true
			}
			s.execActiveCount++
			if req.CommandID != "" {
				s.execActiveCommands[req.CommandID] = state
			}
			now := time.Now().UTC()
			s.mu.Lock()
			s.State = types.SessionStateBusy
			s.LastActivity = now
			s.mu.Unlock()
			s.notifyExecutionChangedLocked()
			s.execAdmissionMu.Unlock()

			// Prefer cancellation if it raced the final admission transition. The
			// slot is synchronously returned and can never run later.
			if ctx.Err() != nil {
				lease.Release()
				return nil, executionQueueError(ctx)
			}
			return lease, nil
		}
		changed := s.executionChangedLocked()
		s.execAdmissionMu.Unlock()

		select {
		case <-ctx.Done():
			removeWaiter()
			return nil, executionQueueError(ctx)
		case <-changed:
		}
	}
}

func (s *Session) releaseExecution(lease *ExecutionLease) {
	s.execAdmissionMu.Lock()
	if lease.shared {
		if _, active := s.execActiveLanes[lease.laneID]; active {
			delete(s.execActiveLanes, lease.laneID)
			if s.execSharedActive > 0 {
				s.execSharedActive--
			}
		}
	} else {
		s.execExclusiveActive = false
	}
	if lease.state != nil {
		commandID := lease.state.CurrentCommandID()
		if current, ok := s.execActiveCommands[commandID]; ok && current == lease.state {
			delete(s.execActiveCommands, commandID)
		}
	}
	if s.execActiveCount > 0 {
		s.execActiveCount--
	}

	now := time.Now().UTC()
	s.mu.Lock()
	if !lease.shared {
		s.currentCommandID = ""
		s.currentProcPID = 0
		s.currentExecutionSensitive = false
		s.currentCommandProvenance = policy.CommandProvenanceNone
		s.currentSandboxComposition = ""
		s.currentTraceID = ""
		s.currentSpanID = ""
		s.currentTraceFlags = ""
	}
	if s.execActiveCount == 0 && s.workspaceActivities == 0 && s.State == types.SessionStateBusy {
		s.State = types.SessionStateReady
	}
	s.LastActivity = now
	s.mu.Unlock()
	s.notifyExecutionChangedLocked()
	s.execAdmissionMu.Unlock()
}

type WorkspaceActivityLease struct {
	once    sync.Once
	session *Session
}

func (l *WorkspaceActivityLease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		if l.session == nil {
			return
		}
		l.session.execAdmissionMu.Lock()
		if l.session.workspaceActivities > 0 {
			l.session.workspaceActivities--
		}
		if l.session.workspaceActivities == 0 && l.session.execActiveCount == 0 {
			l.session.mu.Lock()
			if l.session.State == types.SessionStateBusy {
				l.session.State = types.SessionStateReady
			}
			l.session.LastActivity = time.Now().UTC()
			l.session.mu.Unlock()
		}
		l.session.notifyExecutionChangedLocked()
		l.session.execAdmissionMu.Unlock()
	})
}

// BeginWorkspaceActivity registers a non-command writer such as write_file or
// an outer subagent process. It is fail-fast once review finalization starts.
func (s *Session) BeginWorkspaceActivity() (*WorkspaceActivityLease, error) {
	if s == nil {
		return nil, ErrWorkspaceSealed
	}
	s.execAdmissionMu.Lock()
	defer s.execAdmissionMu.Unlock()
	switch {
	case s.workspaceSealed:
		return nil, ErrWorkspaceSealed
	case s.workspaceFinalizing:
		return nil, ErrWorkspaceFinalizing
	default:
		s.workspaceActivities++
		s.mu.Lock()
		s.State = types.SessionStateBusy
		s.LastActivity = time.Now().UTC()
		s.mu.Unlock()
		s.notifyExecutionChangedLocked()
		return &WorkspaceActivityLease{session: s}, nil
	}
}

type WorkspaceFinalizationLease struct {
	once    sync.Once
	session *Session
}

// TryBeginWorkspaceFinalization atomically closes writer admission only when
// all command and direct-writer activity is already quiescent. It never waits,
// avoiding deadlock with subagents that need nested command calls to finish.
func (s *Session) TryBeginWorkspaceFinalization() (*WorkspaceFinalizationLease, error) {
	if s == nil {
		return nil, ErrWorkspaceSealed
	}
	s.execAdmissionMu.Lock()
	defer s.execAdmissionMu.Unlock()
	switch {
	case s.workspaceSealed:
		return nil, ErrWorkspaceSealed
	case s.workspaceFinalizing:
		return nil, ErrWorkspaceFinalizing
	case s.execActiveCount != 0 || s.execExclusiveWaiters != 0 || s.execSharedWaiters != 0 || s.workspaceActivities != 0:
		return nil, ErrWorkspaceBusy
	default:
		s.workspaceFinalizing = true
		s.notifyExecutionChangedLocked()
		return &WorkspaceFinalizationLease{session: s}, nil
	}
}

func (s *Session) WorkspaceFinalizing() bool {
	if s == nil {
		return false
	}
	s.execAdmissionMu.Lock()
	defer s.execAdmissionMu.Unlock()
	return s.workspaceFinalizing
}

func (l *WorkspaceFinalizationLease) Release(seal bool) {
	if l == nil {
		return
	}
	l.once.Do(func() {
		if l.session == nil {
			return
		}
		l.session.execAdmissionMu.Lock()
		l.session.workspaceFinalizing = false
		if seal {
			l.session.workspaceSealed = true
		}
		l.session.notifyExecutionChangedLocked()
		l.session.execAdmissionMu.Unlock()
	})
}

// ActiveExecutionCount is a synchronized observation used by lifecycle code
// and deterministic tests. Session.State remains Busy until this reaches zero.
func (s *Session) ActiveExecutionCount() int {
	if s == nil {
		return 0
	}
	s.execAdmissionMu.Lock()
	defer s.execAdmissionMu.Unlock()
	return s.execActiveCount
}

// ExecutionQueueDepth returns the number of exclusive and shared requests
// currently waiting for admission.
func (s *Session) ExecutionQueueDepth() int {
	if s == nil {
		return 0
	}
	s.execAdmissionMu.Lock()
	defer s.execAdmissionMu.Unlock()
	return s.execExclusiveWaiters + s.execSharedWaiters
}

// ActiveCommandProcesses returns each known positive command PID once. It lets
// session shutdown terminate every shared lane instead of consulting the legacy
// singleton and silently leaving sibling commands alive.
func (s *Session) ActiveCommandProcesses() []int {
	if s == nil {
		return nil
	}
	s.execAdmissionMu.Lock()
	states := make([]*CommandRuntime, 0, len(s.execActiveCommands))
	for _, state := range s.execActiveCommands {
		states = append(states, state)
	}
	s.execAdmissionMu.Unlock()

	seen := make(map[int]struct{}, len(states)+1)
	pids := make([]int, 0, len(states)+1)
	for _, state := range states {
		if state == nil {
			continue
		}
		if pid := state.CurrentProcessPID(); pid > 0 {
			if _, exists := seen[pid]; !exists {
				seen[pid] = struct{}{}
				pids = append(pids, pid)
			}
		}
	}
	s.mu.Lock()
	legacyPID := s.currentProcPID
	s.mu.Unlock()
	if legacyPID > 0 {
		if _, exists := seen[legacyPID]; !exists {
			pids = append(pids, legacyPID)
		}
	}
	return pids
}

// CommandProcess resolves a running command without relying on the historical
// singleton. Shared commands are looked up in the command registry; exclusive
// paths retain the legacy fallback.
func (s *Session) CommandProcess(commandID string) (int, bool) {
	if s == nil || commandID == "" {
		return 0, false
	}
	s.execAdmissionMu.Lock()
	state, registered := s.execActiveCommands[commandID]
	s.execAdmissionMu.Unlock()
	if registered && state != nil {
		if pid := state.CurrentProcessPID(); pid > 0 {
			return pid, true
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentCommandID == commandID {
		return s.currentProcPID, true
	}
	// A shared command can be admitted but still be in policy/pre-start setup.
	// Preserve "running, PID not yet available" for the kill API in that window.
	return 0, registered
}
