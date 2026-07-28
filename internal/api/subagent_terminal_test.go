package api

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSubagentTerminalDistinguishesTimeoutAndCancellation(t *testing.T) {
	timeoutCtx, timeoutCancel := context.WithTimeoutCause(context.Background(), time.Millisecond, errSubagentRequestTimeout)
	defer timeoutCancel()
	<-timeoutCtx.Done()
	timedOut := cancelledSubagentTerminal(timeoutCtx, 124, "terminated", subagentTerminationGraceful, true)
	if timedOut.State != subagentStateTimedOut || timedOut.CancellationCause != subagentCancelRequestTimeout || timedOut.ExitCode != 124 || timedOut.Retryable || !timedOut.SideEffectsMayHaveOccurred {
		t.Fatalf("timeout terminal = %+v", timedOut)
	}

	for _, tc := range []struct {
		name  string
		cause error
		want  subagentCancellationCause
	}{
		{name: "user", cause: errSubagentUserCancelled, want: subagentCancelUser},
		{name: "parent", cause: errSubagentParentCancelled, want: subagentCancelParent},
		{name: "disconnect", cause: errSubagentClientDisconnected, want: subagentCancelClientDisconnected},
		{name: "shutdown", cause: errSubagentSupervisorShutdown, want: subagentCancelSupervisorShutdown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cancelCtx, cancel := context.WithCancelCause(context.Background())
			cancel(tc.cause)
			terminal := cancelledSubagentTerminal(cancelCtx, 130, "terminated", subagentTerminationGraceful, true)
			if terminal.State != subagentStateCancelled || terminal.CancellationCause != tc.want || terminal.ExitCode != 130 || terminal.Retryable || !terminal.SideEffectsMayHaveOccurred {
				t.Fatalf("cancelled terminal = %+v", terminal)
			}
		})
	}
}

func TestSubagentRequestContextExposesExecutionDeadline(t *testing.T) {
	app := &App{}
	started := time.Now()
	ctx, _, cleanup := app.newSubagentRequestContext(context.Background(), time.Hour)
	defer cleanup()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("subagent request context has no authoritative deadline")
	}
	if remaining := deadline.Sub(started); remaining < 59*time.Minute || remaining > 61*time.Minute {
		t.Fatalf("subagent deadline remaining = %s, want approximately 1h", remaining)
	}
}

func TestSubagentRequestContextPropagatesSupervisorShutdown(t *testing.T) {
	app := &App{}
	ctx, _, cleanup := app.newSubagentRequestContext(context.Background(), time.Hour)
	defer cleanup()
	app.BeginShutdown()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("subagent context did not observe supervisor shutdown")
	}
	if !errors.Is(context.Cause(ctx), errSubagentSupervisorShutdown) {
		t.Fatalf("cancellation cause = %v", context.Cause(ctx))
	}
}

func TestSubagentTerminalAggregatePreservesStrongestFailure(t *testing.T) {
	completed := subagentResult{Terminal: completedSubagentTerminal(0, subagentTerminationNatural)}
	failed := subagentResult{Terminal: failedSubagentTerminal(subagentFailureModel, 1, "", subagentTerminationNatural, false, "model failed")}
	timedOut := subagentResult{Terminal: subagentTerminal{State: subagentStateTimedOut, CancellationCause: subagentCancelRequestTimeout, ExitCode: 124}}

	got := aggregateSubagentTerminal([]subagentResult{completed, failed, timedOut}, nil)
	if got.State != subagentStateTimedOut || got.CancellationCause != subagentCancelRequestTimeout {
		t.Fatalf("aggregate terminal = %+v", got)
	}
}

func TestSubagentTerminalSanitizesDiagnosticCredentials(t *testing.T) {
	terminal := failedSubagentTerminal(subagentFailureAuth, 1, "", subagentTerminationNatural, false, "authorization=secret-value Bearer abc.def")
	if strings.Contains(terminal.Message, "secret-value") || strings.Contains(terminal.Message, "abc.def") {
		t.Fatalf("terminal diagnostic leaked credential-like values: %q", terminal.Message)
	}
}

func TestSubagentPiJSONOutcomeExcludesThinking(t *testing.T) {
	stdout := `{"type":"message_end","message":{"role":"assistant","content":[{"type":"thinking","thinking":"hidden-chain-sentinel"},{"type":"text","text":"visible answer"}],"stopReason":"stop"}}` + "\n" +
		`{"type":"agent_settled"}` + "\n"
	outcome := parseSubagentProtocolOutcome("pi-json", stdout)
	if !outcome.Completed || outcome.Final != "visible answer" || outcome.StopReason != "stop" {
		t.Fatalf("Pi outcome = %+v", outcome)
	}
	if strings.Contains(outcome.Final, "hidden-chain-sentinel") {
		t.Fatalf("Pi final leaked thinking: %q", outcome.Final)
	}
}

func TestSubagentPiJSONOutcomeClassifiesFailedCompaction(t *testing.T) {
	stdout := `{"type":"compaction_end","reason":"overflow","aborted":true,"willRetry":false,"errorMessage":"compaction failed"}` + "\n"
	outcome := parseSubagentProtocolOutcome("pi-json", stdout)
	if outcome.FailureKind != subagentFailureCompaction || outcome.ErrorMessage != "compaction failed" {
		t.Fatalf("Pi compaction outcome = %+v", outcome)
	}
}

func TestSubagentProtocolAllowsPiRecoveryAfterCompactionFailure(t *testing.T) {
	stdout := `{"type":"compaction_end","reason":"overflow","aborted":true,"willRetry":false,"errorMessage":"compaction failed"}` + "\n" +
		`{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"recovered"}],"stopReason":"stop"}}` + "\n" +
		`{"type":"agent_settled"}` + "\n"
	outcome := parseSubagentProtocolOutcome("pi-json", stdout)
	if !outcome.Completed || outcome.Failed() || outcome.Final != "recovered" {
		t.Fatalf("recovered protocol outcome = %+v", outcome)
	}
}

func TestSubagentPiJSONPreservesModelErrorWithoutSettledLifecycle(t *testing.T) {
	stdout := `{"type":"message_end","message":{"role":"assistant","content":[],"stopReason":"error","errorMessage":"provider failed"}}` + "\n"
	outcome := parseSubagentProtocolOutcome("pi-json", stdout)
	if outcome.Completed || outcome.FailureKind != subagentFailureModel || outcome.ErrorMessage != "provider failed" {
		t.Fatalf("model error protocol outcome = %+v", outcome)
	}
}

func TestSubagentPiJSONRejectsSettledToolUseTurn(t *testing.T) {
	stdout := `{"type":"message_end","message":{"role":"assistant","content":[{"type":"toolCall","name":"grep"}],"stopReason":"toolUse"}}` + "\n" +
		`{"type":"agent_settled"}` + "\n"
	outcome := parseSubagentProtocolOutcome("pi-json", stdout)
	if outcome.Completed || outcome.FailureKind != subagentFailureProtocol || !strings.Contains(outcome.ErrorMessage, "tool-use") {
		t.Fatalf("tool-use protocol outcome = %+v", outcome)
	}
}

func TestSubagentPiJSONRejectsEmptySettledResponse(t *testing.T) {
	stdout := `{"type":"message_end","message":{"role":"assistant","content":[],"stopReason":"stop"}}` + "\n" +
		`{"type":"agent_settled"}` + "\n"
	outcome := parseSubagentProtocolOutcome("pi-json", stdout)
	if outcome.Completed || outcome.FailureKind != subagentFailureProtocol || !strings.Contains(outcome.ErrorMessage, "visible final") {
		t.Fatalf("empty protocol outcome = %+v", outcome)
	}
}

func TestSubagentPiJSONRequiresSettledLifecycle(t *testing.T) {
	stdout := `{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"not settled"}],"stopReason":"stop"}}` + "\n"
	outcome := parseSubagentProtocolOutcome("pi-json", stdout)
	if outcome.Completed || outcome.FailureKind != subagentFailureProtocol || !strings.Contains(outcome.ErrorMessage, "agent_settled") {
		t.Fatalf("unsettled protocol outcome = %+v", outcome)
	}
}

func TestSubagentPiJSONReducerRetainsFinalAcrossLargeProgressAndAggregateEvents(t *testing.T) {
	reducer := newPiProtocolReducer()
	progress := []byte(`{"type":"message_update","padding":"` + strings.Repeat("p", 8192) + `"}` + "\n")
	for range 320 {
		if _, err := reducer.Write(progress); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := reducer.Write([]byte(`{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"durable final sentinel"}],"stopReason":"stop"}}` + "\n")); err != nil {
		t.Fatal(err)
	}
	// agent_end repeats the complete transcript and may be much larger than
	// the diagnostic ring. It is irrelevant once message_end was reduced.
	if _, err := reducer.Write([]byte(`{"type":"agent_end","messages":"` + strings.Repeat("a", 5*1024*1024) + `"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := reducer.Write([]byte(`{"type":"agent_settled"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	outcome := reducer.outcome()
	if !outcome.Completed || outcome.Failed() || outcome.Final != "durable final sentinel" || !outcome.Settled {
		t.Fatalf("large-stream protocol outcome = %+v", outcome)
	}
}

func TestSubagentPiJSONReducerReportsOversizedRelevantEvent(t *testing.T) {
	reducer := newPiProtocolReducer()
	oversized := []byte(`{"type":"message_end","padding":"` + strings.Repeat("x", maxPiProtocolRelevantLineBytes) + `"}` + "\n")
	if _, err := reducer.Write(oversized); err != nil {
		t.Fatal(err)
	}
	if _, err := reducer.Write([]byte(`{"type":"agent_settled"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	outcome := reducer.outcome()
	if outcome.Completed || outcome.FailureKind != subagentFailureProtocol {
		t.Fatalf("oversized relevant outcome = %+v", outcome)
	}
	if len(outcome.Diagnostics) != 1 || outcome.Diagnostics[0].Kind != "oversized_line" || outcome.Diagnostics[0].Event != "message_end" {
		t.Fatalf("oversized relevant diagnostics = %+v", outcome.Diagnostics)
	}
}

func TestSubagentTextProtocolStaysGeneric(t *testing.T) {
	outcome := parseSubagentProtocolOutcome("text", "  generic child output  \n")
	if !outcome.Completed || outcome.Failed() || outcome.Final != "generic child output" {
		t.Fatalf("text protocol outcome = %+v", outcome)
	}
}

func TestSubagentTextProtocolRejectsTerminalControlOnlyOutput(t *testing.T) {
	outcome := parseSubagentProtocolOutcome("text", "\x1bP$q q\x1b\\\x1b[6 q")
	if outcome.Completed || outcome.FailureKind != subagentFailureProtocol || outcome.Final != "" {
		t.Fatalf("terminal-control-only outcome = %+v", outcome)
	}
}

func TestSubagentTextProtocolStripsTerminalControlsFromVisibleOutput(t *testing.T) {
	outcome := parseSubagentProtocolOutcome("text", "\x1bP$q q\x1b\\\x1b[31mvisible result\x1b[0m\x1b[6 q")
	if !outcome.Completed || outcome.Failed() || outcome.Final != "visible result" {
		t.Fatalf("visible terminal output outcome = %+v", outcome)
	}
}
