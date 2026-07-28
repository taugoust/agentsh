package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func newExecutionTestSession(t *testing.T) *Session {
	t.Helper()
	manager := NewManager(1)
	sess, err := manager.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

func acquireExecutionForTest(t *testing.T, sess *Session, req ExecutionAdmission) *ExecutionLease {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lease, err := sess.AcquireExecution(ctx, req)
	if err != nil {
		t.Fatalf("AcquireExecution(%+v): %v", req, err)
	}
	return lease
}

func waitForExecutionWaiters(t *testing.T, sess *Session, exclusive, shared int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		sess.execAdmissionMu.Lock()
		gotExclusive, gotShared := sess.execExclusiveWaiters, sess.execSharedWaiters
		sess.execAdmissionMu.Unlock()
		if gotExclusive == exclusive && gotShared == shared {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("execution waiters = exclusive:%d shared:%d, want exclusive:%d shared:%d", gotExclusive, gotShared, exclusive, shared)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestExecutionLanes_DifferentChildrenOverlapAndBusyTracksAll(t *testing.T) {
	sess := newExecutionTestSession(t)
	first := acquireExecutionForTest(t, sess, ExecutionAdmission{CommandID: "cmd-a", LaneID: "child-a", Shared: true, SharedLimit: 2})
	second := acquireExecutionForTest(t, sess, ExecutionAdmission{CommandID: "cmd-b", LaneID: "child-b", Shared: true, SharedLimit: 2})
	first.Runtime().SetCurrentProcessPID(101)
	second.Runtime().SetCurrentProcessPID(202)

	if got := sess.ActiveExecutionCount(); got != 2 {
		t.Fatalf("active executions = %d, want 2", got)
	}
	if got := sess.Snapshot().State; got != types.SessionStateBusy {
		t.Fatalf("session state = %q, want busy", got)
	}
	if pids := sess.ActiveCommandProcesses(); len(pids) != 2 {
		t.Fatalf("active command processes = %v, want both shared lanes", pids)
	}
	first.Release()
	if got := sess.Snapshot().State; got != types.SessionStateBusy {
		t.Fatalf("state after first release = %q, want busy", got)
	}
	second.Release()
	if got := sess.Snapshot().State; got != types.SessionStateReady {
		t.Fatalf("state after final release = %q, want ready", got)
	}
}

func TestExecutionLanes_SameChildSerializes(t *testing.T) {
	sess := newExecutionTestSession(t)
	first := acquireExecutionForTest(t, sess, ExecutionAdmission{CommandID: "cmd-a", LaneID: "child-a", Shared: true, SharedLimit: 2})

	acquired := make(chan *ExecutionLease, 1)
	errCh := make(chan error, 1)
	go func() {
		lease, err := sess.AcquireExecution(context.Background(), ExecutionAdmission{CommandID: "cmd-b", LaneID: "child-a", Shared: true, SharedLimit: 2})
		if err != nil {
			errCh <- err
			return
		}
		acquired <- lease
	}()

	waitForExecutionWaiters(t, sess, 0, 1)
	select {
	case lease := <-acquired:
		lease.Release()
		t.Fatal("same lane acquired while its first command was active")
	case err := <-errCh:
		t.Fatalf("same-lane waiter failed: %v", err)
	default:
	}
	first.Release()

	select {
	case lease := <-acquired:
		lease.Release()
	case err := <-errCh:
		t.Fatalf("same-lane waiter failed after release: %v", err)
	case <-time.After(time.Second):
		t.Fatal("same-lane waiter did not acquire after release")
	}
}

func TestExecutionLanes_AggregateCap(t *testing.T) {
	sess := newExecutionTestSession(t)
	first := acquireExecutionForTest(t, sess, ExecutionAdmission{CommandID: "cmd-a", LaneID: "child-a", Shared: true, SharedLimit: 2})
	second := acquireExecutionForTest(t, sess, ExecutionAdmission{CommandID: "cmd-b", LaneID: "child-b", Shared: true, SharedLimit: 2})

	acquired := make(chan *ExecutionLease, 1)
	go func() {
		lease, _ := sess.AcquireExecution(context.Background(), ExecutionAdmission{CommandID: "cmd-c", LaneID: "child-c", Shared: true, SharedLimit: 2})
		acquired <- lease
	}()
	waitForExecutionWaiters(t, sess, 0, 1)
	select {
	case lease := <-acquired:
		lease.Release()
		t.Fatal("third lane exceeded aggregate cap")
	default:
	}

	first.Release()
	select {
	case lease := <-acquired:
		if lease == nil {
			t.Fatal("third lane returned a nil lease")
		}
		lease.Release()
	case <-time.After(time.Second):
		t.Fatal("third lane did not acquire after aggregate slot opened")
	}
	second.Release()
}

func TestExecutionLanes_ExclusiveWaiterDrainsAndBlocksNewSharedWork(t *testing.T) {
	sess := newExecutionTestSession(t)
	first := acquireExecutionForTest(t, sess, ExecutionAdmission{CommandID: "cmd-a", LaneID: "child-a", Shared: true, SharedLimit: 2})

	exclusive := make(chan *ExecutionLease, 1)
	go func() {
		lease, _ := sess.AcquireExecution(context.Background(), ExecutionAdmission{CommandID: "root"})
		exclusive <- lease
	}()
	// Wait until the exclusive request has registered itself as a waiter.
	waitForExecutionWaiters(t, sess, 1, 0)

	shared := make(chan *ExecutionLease, 1)
	go func() {
		lease, _ := sess.AcquireExecution(context.Background(), ExecutionAdmission{CommandID: "cmd-b", LaneID: "child-b", Shared: true, SharedLimit: 2})
		shared <- lease
	}()
	waitForExecutionWaiters(t, sess, 1, 1)
	first.Release()
	root := <-exclusive
	select {
	case lease := <-shared:
		lease.Release()
		t.Fatal("shared work bypassed an active exclusive request")
	default:
	}
	root.Release()
	select {
	case lease := <-shared:
		lease.Release()
	case <-time.After(time.Second):
		t.Fatal("shared work did not resume after exclusive release")
	}
}

func TestExecutionLanes_SharedCommandAttributionIsImmutable(t *testing.T) {
	sess := newExecutionTestSession(t)
	lease := acquireExecutionForTest(t, sess, ExecutionAdmission{CommandID: "cmd-original", LaneID: "child-a", Shared: true, SharedLimit: 2})
	defer lease.Release()
	lease.Runtime().SetCurrentCommandID("cmd-overwrite-attempt")
	if got := lease.Runtime().CurrentCommandID(); got != "cmd-original" {
		t.Fatalf("shared command attribution = %q, want immutable cmd-original", got)
	}
}

func TestExecutionLanes_CommandProcessResolvesSharedAndExclusiveState(t *testing.T) {
	sess := newExecutionTestSession(t)
	exclusive := acquireExecutionForTest(t, sess, ExecutionAdmission{CommandID: "root"})
	sess.SetCurrentCommandID("root")
	sess.SetCurrentProcessPID(101)
	if pid, running := sess.CommandProcess("root"); !running || pid != 101 {
		t.Fatalf("exclusive process = (%d, %t), want (101, true)", pid, running)
	}
	if pids := sess.ActiveCommandProcesses(); len(pids) != 1 || pids[0] != 101 {
		t.Fatalf("exclusive active processes = %v, want [101]", pids)
	}
	exclusive.Release()

	shared := acquireExecutionForTest(t, sess, ExecutionAdmission{CommandID: "child", LaneID: "child-a", Shared: true, SharedLimit: 2})
	shared.Runtime().SetCurrentProcessPID(202)
	if pid, running := sess.CommandProcess("child"); !running || pid != 202 {
		t.Fatalf("shared process = (%d, %t), want (202, true)", pid, running)
	}
	if pids := sess.ActiveCommandProcesses(); len(pids) != 1 || pids[0] != 202 {
		t.Fatalf("shared active processes = %v, want [202]", pids)
	}
	shared.Release()
}

func TestExecutionLanes_CancelledQueueIsTypedAndNeverAcquires(t *testing.T) {
	sess := newExecutionTestSession(t)
	first := acquireExecutionForTest(t, sess, ExecutionAdmission{CommandID: "cmd-a", LaneID: "child-a", Shared: true, SharedLimit: 1})

	ctx, cancel := context.WithCancelCause(context.Background())
	marker := errors.New("child capability revoked")
	result := make(chan error, 1)
	go func() {
		lease, err := sess.AcquireExecution(ctx, ExecutionAdmission{CommandID: "cmd-b", LaneID: "child-b", Shared: true, SharedLimit: 1})
		if lease != nil {
			lease.Release()
		}
		result <- err
	}()
	waitForExecutionWaiters(t, sess, 0, 1)
	cancel(marker)
	err := <-result
	var queueErr *ExecutionQueueError
	if !errors.As(err, &queueErr) || queueErr.Failure != ExecutionQueueCancelled {
		t.Fatalf("queue error = %#v, want typed cancellation", err)
	}
	if !errors.Is(err, context.Canceled) || !errors.Is(err, marker) {
		t.Fatalf("queue error lost cancellation causes: %v", err)
	}
	first.Release()

	fresh := acquireExecutionForTest(t, sess, ExecutionAdmission{CommandID: "cmd-c", LaneID: "child-b", Shared: true, SharedLimit: 1})
	fresh.Release()
	if got := sess.ActiveExecutionCount(); got != 0 {
		t.Fatalf("cancelled waiter acquired later; active = %d", got)
	}
}
