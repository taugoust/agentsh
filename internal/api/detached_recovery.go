package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

// BootstrapDetachedSession creates or rehydrates the exact session described by
// the protected recovery manifest. It runs before listeners serve requests.
func (a *App) BootstrapDetachedSession(ctx context.Context) (types.Session, *types.NetworkEnforcement, error) {
	if a == nil || a.detachedRuntime == nil {
		return types.Session{}, nil, fmt.Errorf("detached runtime is not configured")
	}
	manifest := a.detachedRuntime.Manifest()
	if manifest.SessionID == "" || manifest.Request.ID != manifest.SessionID {
		return types.Session{}, nil, fmt.Errorf("detached recovery identity is invalid")
	}
	var interrupted []detached.InflightCommand
	if a.detachedRuntime.IsRecovery() {
		interrupted = append(interrupted, manifest.Interrupted...)
		// Parent-death signaling terminates the direct child. Durably recorded
		// process groups additionally cover descendants (which do not inherit
		// Linux Pdeathsig) before the retained workspace is reopened.
		if err := terminateDetachedInterruptedProcesses(manifest.Inflight); err != nil {
			return types.Session{}, nil, fmt.Errorf("terminate interrupted detached commands: %w", err)
		}
		var err error
		newlyInterrupted, err := a.detachedRuntime.TakeInterrupted()
		if err != nil {
			return types.Session{}, nil, fmt.Errorf("persist interrupted detached commands: %w", err)
		}
		interrupted = append(interrupted, newlyInterrupted...)
	}
	nethelperGeneration := manifest.NethelperGeneration
	if manifest.Nethelper != nil {
		nethelperGeneration = manifest.Nethelper.Generation
	}
	if nethelperGeneration > 0 && a.nethelperBinding != nil {
		binding := a.nethelperBinding.snapshot()
		binding.Generation = nethelperGeneration
		a.nethelperBinding.replace(binding)
	}

	snapshot, _, err := a.createSessionCore(ctx, manifest.Request)
	if err != nil {
		return types.Session{}, nil, fmt.Errorf("bootstrap exact detached session %s: %w", manifest.SessionID, err)
	}
	sess, ok := a.sessions.Get(manifest.SessionID)
	if !ok {
		return types.Session{}, nil, fmt.Errorf("bootstrapped detached session %s is absent", manifest.SessionID)
	}
	cleanupOnError := func(cause error) (types.Session, *types.NetworkEnforcement, error) {
		a.cleanupCreatedSession(sess)
		return types.Session{}, nil, cause
	}

	engine := a.policyEngineFor(sess)
	if engine == nil || engine.Policy() == nil {
		return cleanupOnError(fmt.Errorf("detached session policy is unavailable"))
	}
	policyDigest, err := policy.HashEffectivePolicy(engine.Policy())
	if err != nil {
		return cleanupOnError(fmt.Errorf("hash detached session policy: %w", err))
	}
	if a.detachedRuntime.IsRecovery() && strings.TrimSpace(manifest.PolicyDigest) != "" && policyDigest != manifest.PolicyDigest {
		return cleanupOnError(fmt.Errorf("detached recovery refused: effective policy digest changed (expected %s, got %s)", manifest.PolicyDigest, policyDigest))
	}

	if a.detachedRuntime.IsRecovery() {
		if err := sess.RestoreOutputArtifacts(manifest.OutputArtifacts); err != nil {
			return cleanupOnError(fmt.Errorf("restore detached output artifacts: %w", err))
		}
		if !manifest.SessionCreatedAt.IsZero() {
			sess.RestoreTimestamps(manifest.SessionCreatedAt, manifest.UpdatedAt)
		}
		patch := types.SessionPatchRequest{Cwd: manifest.Mutable.Cwd, Env: manifest.Mutable.Environment}
		if patch.Cwd != "" || len(patch.Env) > 0 {
			if err := sess.ApplyPatch(patch); err != nil {
				return cleanupOnError(fmt.Errorf("restore detached mutable session state: %w", err))
			}
		}
		if len(manifest.ScopedApprovals) > 0 && a.approvals != nil {
			var decisions []approvals.ScopedDecision
			if err := json.Unmarshal(manifest.ScopedApprovals, &decisions); err != nil {
				return cleanupOnError(fmt.Errorf("decode detached scoped approvals: %w", err))
			}
			if err := a.approvals.RestoreSessionScopedDecisions(manifest.SessionID, decisions); err != nil {
				return cleanupOnError(fmt.Errorf("restore detached scoped approvals: %w", err))
			}
		}
		for _, command := range interrupted {
			terminalTypes := []string{"command_finished", "command_interrupted"}
			if command.Operation == detachedOperationSpawnSubagent {
				terminalTypes = []string{"tool_spawn_subagent_end"}
			} else if command.Operation == detachedOperationSpawnSubagentChild {
				terminalTypes = []string{"subagent_terminal"}
			}
			terminal, queryErr := a.store.QueryEvents(context.Background(), types.EventQuery{CommandID: command.CommandID, Types: terminalTypes, Limit: 1, Asc: false})
			if queryErr != nil {
				return cleanupOnError(fmt.Errorf("query interrupted operation %s terminal evidence: %w", command.CommandID, queryErr))
			}
			if len(terminal) > 0 {
				continue
			}
			if command.Operation == detachedOperationSpawnSubagent || command.Operation == detachedOperationSpawnSubagentChild {
				if err := a.emitDetachedSubagentInterrupted(command); err != nil {
					return cleanupOnError(err)
				}
			} else if err := a.emitDetachedCommandInterrupted(command); err != nil {
				return cleanupOnError(err)
			}
		}
	}
	sess.SetOutputArtifactPersistenceHook(func(paths []string) {
		if err := a.detachedRuntime.UpdateOutputArtifacts(paths); err != nil {
			_ = a.detachedRuntime.MarkFailed("persist output artifact registry: " + err.Error())
		}
	})

	report := a.runNetworkEnforcementPreflight(ctx, manifest.SessionID)
	if report == nil {
		report = a.refreshNetworkEnforcement(manifest.SessionID)
	}
	snapshot = a.sessionSnapshot(sess)
	if report != nil {
		snapshot.NetworkEnforcement = report
	}
	strict := report != nil && report.Requested == types.NetworkEnforcementRequestStrict
	if strict && !report.Ready() && !a.detachedRuntime.IsRecovery() {
		return cleanupOnError(fmt.Errorf("strict detached network startup refused: status=%s tier=%s: %s", report.Status, report.Tier, report.Detail))
	}
	if err := a.detachedRuntime.MarkReady(snapshot, policyDigest, report); err != nil {
		return cleanupOnError(fmt.Errorf("commit detached recovery readiness: %w", err))
	}
	if !a.detachedRuntime.IsRecovery() && len(manifest.Mutable.VolatileEnvironment) > 0 {
		if err := a.detachedRuntime.ScrubServiceEnvironment(manifest.Mutable.VolatileEnvironment); err != nil {
			return cleanupOnError(fmt.Errorf("scrub volatile supervisor environment after capture: %w", err))
		}
	}
	if a.detachedRuntime.IsRecovery() {
		if strict && (report == nil || !report.Ready()) {
			reason := "strict network enforcement must be rebound before commands can run"
			if report != nil && strings.TrimSpace(report.Detail) != "" {
				reason += ": " + report.Detail
			}
			if err := a.detachedRuntime.MarkDegraded(reason, report); err != nil {
				return cleanupOnError(err)
			}
		}
		if len(manifest.Mutable.VolatileEnvironment) > 0 || manifest.Mutable.DirenvRefreshRequired {
			reason := "volatile environment must be explicitly reprovisioned after supervisor recovery"
			if err := a.detachedRuntime.MarkDegraded(reason, report); err != nil {
				return cleanupOnError(err)
			}
		}
	}

	eventType := "detached_session_bootstrapped"
	if a.detachedRuntime.IsRecovery() {
		eventType = "detached_session_rehydrated"
	}
	event := types.Event{
		ID: uuid.NewString(), Timestamp: time.Now().UTC(), Type: eventType,
		SessionID: manifest.SessionID,
		Fields: map[string]any{
			"generation":         a.detachedRuntime.RuntimeStatus().Generation,
			"incarnation_id":     a.detachedRuntime.RuntimeStatus().IncarnationID,
			"policy_digest":      policyDigest,
			"workspace_reopened": a.detachedRuntime.IsRecovery() && snapshot.Shadow != nil,
		},
	}
	_ = a.store.AppendEvent(context.Background(), event)
	a.broker.Publish(event)
	return snapshot, report, nil
}

func (a *App) emitDetachedSubagentInterrupted(operation detached.InflightCommand) error {
	if a == nil || a.detachedRuntime == nil {
		return nil
	}
	status := a.detachedRuntime.RuntimeStatus()
	terminal := subagentTerminal{
		State:                      subagentStateCancelled,
		FailureKind:                subagentFailureProcess,
		CancellationCause:          subagentCancelSupervisorRestart,
		ExitCode:                   130,
		Signal:                     "killed",
		Termination:                subagentTerminationForced,
		Retryable:                  false,
		SideEffectsMayHaveOccurred: true,
		Message:                    "subagent was interrupted by a supervisor restart; side effects are unknown",
	}
	eventType := "tool_spawn_subagent_end"
	if operation.Operation == detachedOperationSpawnSubagentChild {
		eventType = "subagent_terminal"
	}
	if err := a.persistSubagentTerminalEvent(status.SessionID, eventType, operation.CommandID, operation.ParentID, terminal, map[string]any{
		"interrupted":        true,
		"termination_reason": "supervisor_restart",
		"generation":         status.Generation,
		"incarnation_id":     status.IncarnationID,
	}); err != nil {
		return fmt.Errorf("persist interrupted subagent %s terminal evidence: %w", operation.CommandID, err)
	}
	return nil
}

func (a *App) emitDetachedCommandInterrupted(command detached.InflightCommand) error {
	if a == nil || a.detachedRuntime == nil {
		return nil
	}
	status := a.detachedRuntime.RuntimeStatus()
	event := types.Event{
		ID: uuid.NewString(), Timestamp: time.Now().UTC(), Type: "command_interrupted",
		SessionID: status.SessionID, CommandID: command.CommandID,
		TerminationReason: "supervisor_restart",
		Fields: map[string]any{
			"operation":                      command.Operation,
			"admitted_at":                    command.AdmittedAt,
			"command_started":                !command.StartedAt.IsZero(),
			"started_at":                     command.StartedAt,
			"outcome":                        "unknown",
			"side_effects_may_have_occurred": true,
			"retryable":                      false,
			"generation":                     status.Generation,
			"incarnation_id":                 status.IncarnationID,
		},
	}
	terminalCtx, cancel := terminalPersistenceContext(context.Background())
	defer cancel()
	if err := a.store.AppendEvent(terminalCtx, event); err != nil {
		_ = a.detachedRuntime.MarkFailed("persist interrupted command terminal evidence: " + err.Error())
		return fmt.Errorf("persist interrupted command %s terminal evidence: %w", command.CommandID, err)
	}
	a.broker.Publish(event)
	return nil
}

func detachedEnvironmentRecoveryState(sess *session.Session) detached.MutableSessionState {
	if sess == nil {
		return detached.MutableSessionState{}
	}
	cwd, environment, _ := sess.GetCwdEnvHistory()
	safe := make(map[string]string)
	var volatile []string
	for name, value := range environment {
		if detachedEnvironmentValuePersistable(name, value) {
			safe[name] = value
		} else {
			volatile = append(volatile, name)
		}
	}
	return detached.MutableSessionState{
		Cwd: cwd, Environment: safe, VolatileEnvironment: volatile,
		DirenvRefreshRequired: len(sess.DirenvNames()) > 0,
	}
}

func (a *App) beginDetachedMutation(operation string) (func(), error) {
	if a == nil || a.detachedRuntime == nil {
		return func() {}, nil
	}
	id := "mutation-" + uuid.NewString()
	now := time.Now().UTC()
	if err := a.detachedRuntime.RecordCommand(detached.InflightCommand{CommandID: id, Operation: operation, AdmittedAt: now, StartedAt: now}); err != nil {
		_ = a.detachedRuntime.MarkFailed("persist mutation admission: " + err.Error())
		return nil, fmt.Errorf("durable mutation admission failed; operation was not executed")
	}
	return func() { _ = a.detachedRuntime.CompleteCommand(id) }, nil
}

func (a *App) detachedMutationReady() error {
	if a == nil || a.detachedRuntime == nil {
		return nil
	}
	status := a.detachedRuntime.RuntimeStatus()
	if status.LifecycleState == detached.LifecycleReady {
		return nil
	}
	if status.LastError != "" {
		return fmt.Errorf("detached supervisor lifecycle is %s: %s", status.LifecycleState, status.LastError)
	}
	return fmt.Errorf("detached supervisor lifecycle is %s", status.LifecycleState)
}

func (a *App) persistDetachedDirenvState(sess *session.Session, acknowledge bool) error {
	if a == nil || a.detachedRuntime == nil || sess == nil {
		return nil
	}
	if err := a.detachedRuntime.UpdateMutable(detachedEnvironmentRecoveryState(sess)); err != nil {
		return err
	}
	if acknowledge {
		return a.detachedRuntime.AcknowledgeEnvironment(nil, true)
	}
	return nil
}

func detachedEnvironmentValuePersistable(name, value string) bool {
	if len(value) > 16*1024 || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	return detached.RestartSafeEnvironmentName(name)
}
