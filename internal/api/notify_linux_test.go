//go:build linux && cgo

package api

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"github.com/agentsh/agentsh/pkg/types"
	"golang.org/x/sys/unix"
)

type commandJailREADYReader struct {
	n   int
	b   byte
	err error
}

func (r commandJailREADYReader) Read(p []byte) (int, error) {
	if r.n > 0 && len(p) > 0 {
		p[0] = r.b
	}
	return r.n, r.err
}

func TestReadCommandJailREADYStrictFraming(t *testing.T) {
	tests := []struct {
		name      string
		reader    io.Reader
		wantBytes int
		wantErr   error
	}{
		{name: "ready", reader: strings.NewReader("R"), wantBytes: 1},
		{name: "ready with terminal EOF", reader: commandJailREADYReader{n: 1, b: 'R', err: io.EOF}, wantBytes: 1},
		{name: "EOF", reader: strings.NewReader(""), wantBytes: 0, wantErr: io.EOF},
		{name: "zero without error", reader: commandJailREADYReader{}, wantBytes: 0, wantErr: io.ErrUnexpectedEOF},
		{name: "unexpected byte", reader: strings.NewReader("X"), wantBytes: 1, wantErr: errors.New("unexpected READY byte")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, err := readCommandJailREADY(tc.reader)
			if n != tc.wantBytes {
				t.Fatalf("bytes = %d, want %d", n, tc.wantBytes)
			}
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if tc.wantErr == io.EOF || tc.wantErr == io.ErrUnexpectedEOF {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr.Error()) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestApprovalRequesterAdapter_ExecutableSessionScopeAllowsDifferentArgs(t *testing.T) {
	mgr := approvals.New("api", time.Minute, nil)
	adapter := &approvalRequesterAdapter{mgr: mgr}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	command := "/nix/store/abc-sqlite-3.45/bin/sqlite3"
	rule := "approve-unknown-nix-store-executables"
	done := make(chan struct {
		approved bool
		err      error
	}, 1)
	go func() {
		approved, err := adapter.RequestExecApproval(ctx, unixmon.ApprovalRequest{
			SessionID: "s1",
			Command:   command,
			Args:      []string{"sqlite3", "events.db", "select * from events limit 10"},
			Reason:    "approval required",
			Rule:      rule,
		})
		done <- struct {
			approved bool
			err      error
		}{approved: approved, err: err}
	}()

	req := waitPendingCommandApproval(t, ctx, mgr, "s1")
	if req.Fields["scope_path"] != command || req.Fields["scope_label"] != command {
		t.Fatalf("default scope should be executable path, fields=%#v", req.Fields)
	}
	if key, _ := req.Fields["scope_key"].(string); !strings.HasPrefix(key, "command-executable:") {
		t.Fatalf("scope_key = %q, want executable scope", key)
	}
	if !mgr.ResolveForSessionWithScope("s1", req.ID, true, "ok", approvals.ScopeSession) {
		t.Fatal("ResolveForSessionWithScope returned false")
	}
	select {
	case res := <-done:
		if res.err != nil || !res.approved {
			t.Fatalf("first approval result approved=%v err=%v", res.approved, res.err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for first approval: %v", ctx.Err())
	}

	approved, err := adapter.RequestExecApproval(ctx, unixmon.ApprovalRequest{
		SessionID: "s1",
		Command:   command,
		Args:      []string{"sqlite3", "-readonly", "events.db", "select * from events limit 50"},
		Reason:    "approval required",
		Rule:      rule,
	})
	if err != nil || !approved {
		t.Fatalf("second approval result approved=%v err=%v", approved, err)
	}
	if pending := mgr.ListPendingForSession("s1"); len(pending) != 0 {
		t.Fatalf("unexpected pending approval for same executable: %+v", pending)
	}

	differentDone := make(chan error, 1)
	go func() {
		_, err := adapter.RequestExecApproval(ctx, unixmon.ApprovalRequest{
			SessionID: "s1",
			Command:   "/nix/store/def-postgresql/bin/psql",
			Args:      []string{"psql", "events.db", "select 1"},
			Reason:    "approval required",
			Rule:      rule,
		})
		differentDone <- err
	}()
	differentReq := waitPendingCommandApproval(t, ctx, mgr, "s1")
	if differentReq.Target == command {
		t.Fatalf("different executable did not prompt separately: %+v", differentReq)
	}
	if !mgr.ResolveForSession("s1", differentReq.ID, false, "no") {
		t.Fatal("ResolveForSession returned false")
	}
	select {
	case err := <-differentDone:
		if err != nil {
			t.Fatalf("different approval returned error: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for different approval: %v", ctx.Err())
	}
}

func TestStartNotifyHandler_GracefulErrorExit(t *testing.T) {
	// Create a unix socketpair so RecvFD can be attempted.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	parentSock := os.NewFile(uintptr(fds[0]), "parent")
	writeSock := os.NewFile(uintptr(fds[1]), "child")

	store := &notifyMockEventStore{}
	broker := &notifyMockEventBroker{}

	// Close write end immediately so RecvFD returns an error.
	writeSock.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := startNotifyHandler(ctx, parentSock, "test-graceful", nil, store, broker, nil, config.SandboxSeccompFileMonitorConfig{}, false, nil, nil, false, nil, nil, 0, "", nil, nil)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for goroutine to finish")
	}

	// No panic event should be published for a clean error exit.
	evs := broker.getEvents()
	for _, ev := range evs {
		if ev.Type == string(events.EventNotifyHandlerPanic) {
			t.Error("unexpected panic event for clean error exit")
		}
	}
}

func TestNotifyHandlerRecover_PublishesPanicEvent(t *testing.T) {
	// Test the real notifyHandlerRecover function (used by startNotifyHandler)
	// by triggering a panic in a goroutine guarded by it.
	store := &notifyMockEventStore{}
	broker := &notifyMockEventBroker{}
	sessID := "test-recover-panic"

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer notifyHandlerRecover(sessID, store, broker)
		panic("injected test panic")
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for panic recovery")
	}

	// Verify broker received the event.
	evs := broker.getEvents()
	if len(evs) != 1 {
		t.Fatalf("expected 1 broker event, got %d", len(evs))
	}
	ev := evs[0]
	if ev.Type != string(events.EventNotifyHandlerPanic) {
		t.Errorf("event type = %q, want %q", ev.Type, string(events.EventNotifyHandlerPanic))
	}
	if ev.SessionID != sessID {
		t.Errorf("session_id = %q, want %q", ev.SessionID, sessID)
	}
	if ev.Fields["error"] != "injected test panic" {
		t.Errorf("error field = %q, want %q", ev.Fields["error"], "injected test panic")
	}
	if ev.ID == "" {
		t.Error("event ID should be set")
	}
	if ev.Timestamp.IsZero() {
		t.Error("event Timestamp should be set")
	}

	// Verify store also received the event (store runs in a background
	// goroutine, so poll briefly).
	deadline2 := time.After(2 * time.Second)
	for {
		store.mu.Lock()
		n := len(store.events)
		store.mu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-deadline2:
			t.Fatal("timed out waiting for store event")
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	store.mu.Lock()
	storeEvs := store.events
	store.mu.Unlock()
	if storeEvs[0].Type != string(events.EventNotifyHandlerPanic) {
		t.Errorf("store event type = %q, want %q", storeEvs[0].Type, string(events.EventNotifyHandlerPanic))
	}
}

func TestNotifyHandlerRecover_NilBrokerAndStore_NoPanic(t *testing.T) {
	// Verify that nil broker and store don't cause a secondary panic
	// in the recovery path.
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer notifyHandlerRecover("test-nil-deps", nil, nil)
		panic("injected test panic")
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for panic recovery with nil broker/store")
	}
	// Reaching here without crashing proves the nil guards work.
}

func TestNotifyHandlerRecover_NoPanic_NoOp(t *testing.T) {
	// Verify notifyHandlerRecover is a no-op when no panic occurred.
	store := &notifyMockEventStore{}
	broker := &notifyMockEventBroker{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer notifyHandlerRecover("test-no-panic", store, broker)
		// no panic
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}

	evs := broker.getEvents()
	if len(evs) != 0 {
		t.Errorf("expected 0 events, got %d", len(evs))
	}
}

// panickingBroker is an eventBroker whose Publish method always panics,
// used to test the nested recover() in notifyHandlerRecover.
type panickingBroker struct{}

func (b *panickingBroker) Publish(ev types.Event) {
	panic("broker panic")
}

func TestNotifyHandlerRecover_BrokerPanic_NoCrash(t *testing.T) {
	// Verify the nested recover() catches panics from broker.Publish
	// so a faulty broker doesn't crash the process.
	store := &notifyMockEventStore{}
	broker := &panickingBroker{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer notifyHandlerRecover("test-broker-panic", store, broker)
		panic("original panic")
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out — broker panic likely crashed the goroutine")
	}

	// The store should still have received the event (store runs in a
	// background goroutine, so poll briefly).
	deadline := time.After(2 * time.Second)
	for {
		store.mu.Lock()
		n := len(store.events)
		store.mu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for store event")
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	store.mu.Lock()
	storeEvs := store.events
	store.mu.Unlock()
	if len(storeEvs) != 1 {
		t.Fatalf("expected 1 store event, got %d", len(storeEvs))
	}
	if storeEvs[0].Fields["error"] != "original panic" {
		t.Errorf("store error = %q, want %q", storeEvs[0].Fields["error"], "original panic")
	}
}

// panickingStore is an eventStore whose AppendEvent always panics,
// used to test that a store panic doesn't prevent broker.Publish.
type panickingStore struct{}

func (s *panickingStore) AppendEvent(ctx context.Context, ev types.Event) error {
	panic("store panic")
}

func TestNotifyHandlerRecover_StorePanic_BrokerStillReceives(t *testing.T) {
	// Verify that a panicking store doesn't prevent broker.Publish
	// from being called.
	store := &panickingStore{}
	broker := &notifyMockEventBroker{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer notifyHandlerRecover("test-store-panic", store, broker)
		panic("original panic")
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out — store panic likely crashed the goroutine")
	}

	// Broker should still have received the event despite the store panicking.
	evs := broker.getEvents()
	if len(evs) != 1 {
		t.Fatalf("expected 1 broker event, got %d", len(evs))
	}
	if evs[0].Fields["error"] != "original panic" {
		t.Errorf("broker error = %q, want %q", evs[0].Fields["error"], "original panic")
	}
}

// blockingStore is an eventStore whose AppendEvent blocks forever,
// ignoring context cancellation. Used to test that broker delivery
// is not blocked by a slow store.
type blockingStore struct {
	blocked chan struct{} // closed when AppendEvent is entered
}

func (s *blockingStore) AppendEvent(ctx context.Context, ev types.Event) error {
	if s.blocked != nil {
		close(s.blocked)
	}
	select {} // block forever
}

func TestNotifyHandlerRecover_BlockingStore_BrokerStillReceives(t *testing.T) {
	// Verify that a store that blocks forever (ignoring context) doesn't
	// prevent broker.Publish from being called.
	store := &blockingStore{blocked: make(chan struct{})}
	broker := &notifyMockEventBroker{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer notifyHandlerRecover("test-blocking-store", store, broker)
		panic("original panic")
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out — blocking store prevented recovery from completing")
	}

	// Broker should have received the event despite the store blocking.
	evs := broker.getEvents()
	if len(evs) != 1 {
		t.Fatalf("expected 1 broker event, got %d", len(evs))
	}
	if evs[0].Fields["error"] != "original panic" {
		t.Errorf("broker error = %q, want %q", evs[0].Fields["error"], "original panic")
	}
}

// blockingBroker is an eventBroker whose Publish blocks forever,
// used to test that the recovery timeout prevents hanging.
type blockingBroker struct{}

func (b *blockingBroker) Publish(ev types.Event) {
	select {} // block forever
}

func TestNotifyHandlerRecover_BlockingBroker_BoundedReturn(t *testing.T) {
	// Verify that a blocking broker doesn't prevent notifyHandlerRecover
	// from returning within the recoverTimeout bound.
	store := &notifyMockEventStore{}
	broker := &blockingBroker{}

	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		defer notifyHandlerRecover("test-blocking-broker", store, broker)
		panic("original panic")
	}()

	select {
	case <-done:
	case <-time.After(recoverTimeout + 2*time.Second):
		t.Fatal("timed out — blocking broker prevented recovery from returning")
	}

	elapsed := time.Since(start)
	if elapsed > recoverTimeout+time.Second {
		t.Errorf("recovery took %v, expected within %v", elapsed, recoverTimeout+time.Second)
	}

	// Store should still have received the event (runs in separate goroutine).
	deadline := time.After(2 * time.Second)
	for {
		store.mu.Lock()
		n := len(store.events)
		store.mu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for store event")
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNotifyHandler_CancellationGoroutineExitsOnEarlyReturn(t *testing.T) {
	// Verify that the cancellation goroutine (which closes the notify FD on
	// ctx.Done) doesn't leak when the handler exits early (e.g., RecvFD fails).
	// The handlerDone channel should signal the cancellation goroutine to exit
	// even though the context is never cancelled.

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	parentSock := os.NewFile(uintptr(fds[0]), "parent")
	writeSock := os.NewFile(uintptr(fds[1]), "child")

	store := &notifyMockEventStore{}
	broker := &notifyMockEventBroker{}

	// Close write end immediately so RecvFD fails → handler exits early.
	writeSock.Close()

	// Use a context that is NEVER cancelled — the cancellation goroutine
	// must exit via the handlerDone channel, not ctx.Done().
	ctx := context.Background()

	goroutinesBefore := runtime.NumGoroutine()

	done := startNotifyHandler(ctx, parentSock, "test-cancel-goroutine", nil, store, broker, nil, config.SandboxSeccompFileMonitorConfig{}, false, nil, nil, false, nil, nil, 0, "", nil, nil)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handler goroutine to exit")
	}

	// Allow goroutines to settle.
	time.Sleep(50 * time.Millisecond)

	goroutinesAfter := runtime.NumGoroutine()
	// Tolerate ±2 for GC/runtime goroutines.
	if goroutinesAfter > goroutinesBefore+2 {
		t.Errorf("goroutine leak: before=%d after=%d (expected ≤%d)",
			goroutinesBefore, goroutinesAfter, goroutinesBefore+2)
	}
}

func TestNotifyHandler_ContextCancelCleansUpFDs(t *testing.T) {
	// Verify that handler goroutine cleans up (closes parent socket) after
	// the serve loop exits. We send a pipe FD so RecvFD succeeds, then
	// NotifReceive fails immediately (wrong ioctl type). The handler exits
	// and defer-closes the parent socket.
	//
	// Note: with pipe FDs, the handler exits via ioctl error, not via
	// ctx.Done(). Testing cancellation-driven FD cleanup requires real
	// seccomp notify FDs (integration test with CAP_SYS_ADMIN).

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	parentSock := os.NewFile(uintptr(fds[0]), "parent")
	childSock := os.NewFile(uintptr(fds[1]), "child")

	store := &notifyMockEventStore{}
	broker := &notifyMockEventBroker{}

	// Send a pipe FD through the socketpair so RecvFD succeeds.
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer pipeW.Close()

	rights := unix.UnixRights(int(pipeR.Fd()))
	if err := unix.Sendmsg(int(childSock.Fd()), []byte{0}, rights, nil, 0); err != nil {
		pipeR.Close()
		childSock.Close()
		parentSock.Close()
		t.Fatalf("sendmsg: %v", err)
	}
	pipeR.Close()
	childSock.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := startNotifyHandler(ctx, parentSock, "test-fd-cleanup", nil, store, broker, nil, config.SandboxSeccompFileMonitorConfig{}, false, nil, nil, false, nil, nil, 0, "", nil, nil)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out: handler didn't clean up parent socket")
	}
}
