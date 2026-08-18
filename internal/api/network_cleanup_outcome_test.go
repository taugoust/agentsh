package api

import (
	"errors"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestCleanedNetworkSetupRefusalIsNotRecordedAgainByCaller(t *testing.T) {
	refusal := newNetworkSetupRefusalError(errors.New("interrupted system call"))
	wrapped := markPreExecEnforcementError("E_PRE_EXEC_ENFORCEMENT", refusal)
	if !shouldRecordNetworkEnforcementFailure(wrapped) {
		t.Fatal("uncleaned setup refusal was not sticky")
	}
	refusal.markCleanupComplete()
	if shouldRecordNetworkEnforcementFailure(wrapped) {
		t.Fatal("cleaned setup refusal would be recorded again by the command caller")
	}
}

func TestCleanedNetworkSetupRefusalRestoresPreflightReadiness(t *testing.T) {
	manager := session.NewManager(1)
	sess, err := manager.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	sess.SetNetworkEnforcementBaseline(provenRebindReport(time.Now().UTC()))
	app := &App{sessions: manager}
	commandID := "cmd-setup-refused"
	app.recordNetworkEnforcementFailure(sess.ID, commandID, errors.New("interrupted system call"))
	if failed := sess.NetworkEnforcement(); failed == nil || failed.Status != types.NetworkEnforcementStatusFailed {
		t.Fatalf("setup refusal was not recorded: %+v", failed)
	}

	app.recordNetworkSetupRefusalCleaned(sess.ID, commandID)
	got := sess.NetworkEnforcement()
	if got == nil || got.Status != types.NetworkEnforcementStatusReady || got.Readiness != types.NetworkEnforcementStatusReady || got.Attachment != nil {
		t.Fatalf("cleaned refusal did not restore preflight readiness: %+v", got)
	}
}

func TestNetworkCleanupFailureCannotBeOverwrittenByInactiveSuccess(t *testing.T) {
	manager := session.NewManager(1)
	sess, err := manager.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	app := &App{sessions: manager}
	commandID := "cmd-cleanup-failed"
	app.recordNetworkCleanupFailure(sess.ID, commandID, errors.New("helper registration disappeared"))

	failed := sess.NetworkEnforcement()
	if failed == nil || failed.Status != types.NetworkEnforcementStatusFailed || failed.Attachment == nil || failed.Attachment.Status != types.NetworkEnforcementStatusFailed {
		t.Fatalf("cleanup failure was not sticky: %+v", failed)
	}
	failedAt := failed.Attachment.CheckedAt
	failedDetail := failed.Detail

	// Simulate a stale or reordered cgroup-success callback. It must not erase
	// the earlier kernel/helper cleanup failure or attest successful inactivity.
	time.Sleep(time.Millisecond)
	app.recordNetworkAttachmentEnded(sess.ID, commandID)
	got := sess.NetworkEnforcement()
	if got == nil || got.Status != types.NetworkEnforcementStatusFailed || got.Attachment == nil || got.Attachment.Status != types.NetworkEnforcementStatusFailed {
		t.Fatalf("inactive callback overwrote cleanup failure: %+v", got)
	}
	if !got.Attachment.CheckedAt.Equal(failedAt) || got.Detail != failedDetail {
		t.Fatalf("inactive callback mutated sticky failure: before=%+v after=%+v", failed, got)
	}
}
