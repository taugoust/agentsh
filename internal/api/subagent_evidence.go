package api

import (
	"context"
	"fmt"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

const (
	detachedOperationSpawnSubagent      = "spawn_subagent"
	detachedOperationSpawnSubagentChild = "spawn_subagent_child"
)

func (a *App) beginDetachedSubagentOperation(operationID, operation, parentID string) error {
	if a == nil || a.detachedRuntime == nil {
		return nil
	}
	now := time.Now().UTC()
	entry := detached.InflightCommand{
		CommandID:  operationID,
		Operation:  operation,
		ParentID:   parentID,
		AdmittedAt: now,
		StartedAt:  now,
	}
	if err := a.detachedRuntime.RecordCommand(entry); err != nil {
		_ = a.detachedRuntime.MarkFailed("persist subagent admission: " + err.Error())
		return fmt.Errorf("durable subagent admission failed; operation was not executed")
	}
	return nil
}

func (a *App) markDetachedSubagentProcess(operationID string, pid, processGroupID int) error {
	if a == nil || a.detachedRuntime == nil {
		return nil
	}
	if err := a.detachedRuntime.MarkCommandProcess(operationID, pid, processGroupID); err != nil {
		_ = a.detachedRuntime.MarkFailed("persist subagent process identity: " + err.Error())
		return fmt.Errorf("durable subagent process identity failed: %w", err)
	}
	return nil
}

func subagentTerminalEventFields(terminal subagentTerminal) map[string]any {
	return map[string]any{
		"terminal":                       terminal,
		"terminal_state":                 terminal.State,
		"failure_kind":                   terminal.FailureKind,
		"cancellation_cause":             terminal.CancellationCause,
		"exit_code":                      terminal.ExitCode,
		"signal":                         terminal.Signal,
		"termination":                    terminal.Termination,
		"retryable":                      terminal.Retryable,
		"side_effects_may_have_occurred": terminal.SideEffectsMayHaveOccurred,
		"message":                        terminal.Message,
	}
}

func (a *App) persistSubagentTerminalEvent(sessionID, eventType, operationID, parentID string, terminal subagentTerminal, extra map[string]any) error {
	if a == nil {
		return nil
	}
	fields := subagentTerminalEventFields(terminal)
	for key, value := range extra {
		fields[key] = value
	}
	if parentID != "" {
		fields["parent_request_id"] = parentID
	}
	event := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      eventType,
		SessionID: sessionID,
		CommandID: operationID,
		Operation: detachedOperationSpawnSubagent,
		Fields:    fields,
	}
	terminalCtx, cancel := terminalPersistenceContext(context.Background())
	defer cancel()
	if a.store == nil && a.detachedRuntime != nil {
		err := fmt.Errorf("detached terminal event store is unavailable")
		_ = a.detachedRuntime.MarkFailed(err.Error())
		return err
	}
	if a.store != nil {
		if err := a.store.AppendEvent(terminalCtx, event); err != nil {
			if a.detachedRuntime != nil {
				_ = a.detachedRuntime.MarkFailed("persist subagent terminal evidence: " + err.Error())
			}
			return fmt.Errorf("persist subagent terminal evidence: %w", err)
		}
	}
	if a.broker != nil {
		a.broker.Publish(event)
	}
	if a.detachedRuntime != nil {
		if err := a.detachedRuntime.CompleteCommand(operationID); err != nil {
			_ = a.detachedRuntime.MarkFailed("complete subagent admission journal: " + err.Error())
			return fmt.Errorf("complete subagent admission journal: %w", err)
		}
	}
	return nil
}
