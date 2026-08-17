//go:build linux

package api

import (
	"context"
	"errors"
	"testing"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestReservedWorkspaceFinalizationExcludesTeardown(t *testing.T) {
	manager := session.NewManager(1)
	sess, err := manager.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	app := &App{sessions: manager}
	reserved, lease, err := app.reserveWorkspaceFinalization(sess.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if reserved != sess || sess.WorkspaceTeardownAllowed() {
		t.Fatal("finalization reservation did not atomically exclude teardown")
	}
	lease.MarkPending()
	lease.Release(false)
	if sess.WorkspaceTeardownAllowed() {
		t.Fatal("pending finalization allowed teardown")
	}
}

func TestGRPCDestroyRefusesWorkspaceFinalization(t *testing.T) {
	manager := session.NewManager(1)
	sess, err := manager.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}
	app := &App{sessions: manager}
	lease, err := sess.TryBeginWorkspaceFinalization()
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release(false)
	request, err := structpb.NewStruct(map[string]any{"id": sess.ID})
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&grpcServer{app: app}).DestroySession(context.Background(), request)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("DestroySession error=%v", err)
	}
	if _, ok := manager.Get(sess.ID); !ok {
		t.Fatal("gRPC destroy removed finalizing session")
	}
}

func TestWorkspacePendingFinalizationRejectsExecution(t *testing.T) {
	sess := &session.Session{ID: "pending", State: types.SessionStateReady}
	lease, err := sess.TryBeginWorkspaceFinalization()
	if err != nil {
		t.Fatal(err)
	}
	lease.MarkPending()
	lease.Release(false)
	_, err = sess.AcquireExecution(context.Background(), session.ExecutionAdmission{})
	if !errors.Is(err, session.ErrWorkspaceFinalizing) {
		t.Fatalf("execution error=%v", err)
	}
}
