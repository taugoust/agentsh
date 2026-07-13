package api

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSubagentTerminalDistinguishesTimeoutAndCancellation(t *testing.T) {
	timeoutCtx, timeoutCancel := context.WithTimeoutCause(context.Background(), time.Millisecond, errSubagentRequestTimeout)
	defer timeoutCancel()
	<-timeoutCtx.Done()
	timedOut := cancelledSubagentTerminal(timeoutCtx, 124, "terminated", subagentTerminationGraceful)
	if timedOut.State != subagentStateTimedOut || timedOut.CancellationCause != subagentCancelRequestTimeout || timedOut.ExitCode != 124 {
		t.Fatalf("timeout terminal = %+v", timedOut)
	}

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled := cancelledSubagentTerminal(cancelCtx, 130, "terminated", subagentTerminationGraceful)
	if cancelled.State != subagentStateCancelled || cancelled.CancellationCause != subagentCancelClientDisconnected || cancelled.ExitCode != 130 {
		t.Fatalf("cancelled terminal = %+v", cancelled)
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
	stdout := `{"type":"message_end","message":{"role":"assistant","content":[{"type":"thinking","thinking":"hidden-chain-sentinel"},{"type":"text","text":"visible answer"}],"stopReason":"stop"}}` + "\n"
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
		`{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"recovered"}],"stopReason":"stop"}}` + "\n"
	outcome := parseSubagentProtocolOutcome("pi-json", stdout)
	if !outcome.Completed || outcome.Failed() || outcome.Final != "recovered" {
		t.Fatalf("recovered protocol outcome = %+v", outcome)
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
