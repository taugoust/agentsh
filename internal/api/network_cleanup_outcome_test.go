package api

import (
	"errors"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

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
