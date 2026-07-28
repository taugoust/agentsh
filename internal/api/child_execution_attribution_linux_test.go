//go:build linux && cgo

package api

import (
	"context"
	"testing"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestChildExecutionLanes_NotifyEventsUseCommandLocalAttribution(t *testing.T) {
	manager := session.NewManager(1)
	sess, err := manager.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := sess.AcquireExecution(context.Background(), session.ExecutionAdmission{
		CommandID: "cmd-child", LaneID: "subagent-a", Shared: true, SharedLimit: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	runtimeState := lease.Runtime()
	runtimeState.SetCurrentExecutionSensitive(true)
	runtimeState.SetCurrentTraceContext("0123456789abcdef0123456789abcdef", "0123456789abcdef", "01")

	emitter := &notifyEmitterAdapter{runtimeState: runtimeState, sensitive: runtimeState.CurrentExecutionSensitive}
	event := emitter.redact(types.Event{Fields: map[string]any{"argv": []string{"secret"}}})
	if event.CommandID != "cmd-child" {
		t.Fatalf("command id = %q, want command-local id", event.CommandID)
	}
	if event.Fields["trace_id"] != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("trace id = %#v", event.Fields["trace_id"])
	}
	args, ok := event.Fields["argv"].([]string)
	if !ok || len(args) != 1 || args[0] != sensitiveArgumentRedaction {
		t.Fatalf("sensitive argv = %#v", event.Fields["argv"])
	}
	if current := sess.CurrentCommandID(); current != "" {
		t.Fatalf("command-local notify attribution touched singleton %q", current)
	}
}
