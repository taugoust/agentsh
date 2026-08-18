//go:build linux && cgo

package unix

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type notificationLookupPolicy struct {
	resolveCalls atomic.Int32
	block        bool
}

func (p *notificationLookupPolicy) CheckFile(context.Context, string, string) FilePolicyDecision {
	return FilePolicyDecision{
		Decision: "approve", EffectiveDecision: "approve", Rule: "approve-read",
		CacheOutcome: FileApprovalCacheMiss, ApprovalScopeKey: "file:test", ApprovalCommandID: "cmd-test",
	}
}

func (p *notificationLookupPolicy) ResolveFileApproval(ctx context.Context, _, _ string, decision FilePolicyDecision) (FilePolicyDecision, error) {
	p.resolveCalls.Add(1)
	if p.block {
		<-ctx.Done()
		decision.EffectiveDecision = "deny"
		return decision, ctx.Err()
	}
	decision.EffectiveDecision = "allow"
	return decision, nil
}

type fixedFileLookupProbe struct {
	result FileLookupResult
	calls  atomic.Int32
}

func (p *fixedFileLookupProbe) ProbeFileLookup(context.Context, FileLookupRequest) FileLookupResult {
	p.calls.Add(1)
	return p.result
}

func lookupNotificationRequest(t *testing.T) (FileRequest, []byte) {
	t.Helper()
	path := []byte("/missing-optional-file\x00")
	pointer := uint64(uintptr(unsafe.Pointer(&path[0])))
	lookup := &FileLookupRequest{
		TID: osGetpid(), Syscall: int32(unix.SYS_OPENAT), DirFD: int32(unix.AT_FDCWD),
		PathPtr: pointer, RawPath: "/missing-optional-file", ResolvedPath: "/missing-optional-file",
		OpenFlags: uint64(unix.O_RDONLY), PathnameNULTerminated: true,
	}
	return FileRequest{
		PID: osGetpid(), Syscall: int32(unix.SYS_OPENAT), Path: lookup.ResolvedPath,
		Operation: "open", Lookup: lookup, SessionID: "session-test",
	}, path
}

func osGetpid() int { return unix.Getpid() }

func TestEvaluateFileNotificationConfirmedAbsentCompletesENOENTWithoutApproval(t *testing.T) {
	policy := &notificationLookupPolicy{}
	handler := NewFileHandler(policy, NewMountRegistry(), &mockFileEmitter{}, true)
	probe := &fixedFileLookupProbe{result: FileLookupResult{Class: LookupAbsent, Reason: LookupReasonNone, Errno: int32(unix.ENOENT)}}
	handler.SetFileLookupProbe(probe)
	request, pathname := lookupNotificationRequest(t)

	var responded atomic.Int32
	evaluation := evaluateFileNotificationWithOps(context.Background(), 99, 7, handler, request, fileNotificationOps{
		validate: func(int, uint64) error { return nil },
		respondErrno: func(_ int, id uint64, errno int32) error {
			if id != 7 || errno != int32(unix.ENOENT) {
				t.Fatalf("response id=%d errno=%d", id, errno)
			}
			responded.Add(1)
			return nil
		},
	})
	runtime.KeepAlive(pathname)

	if !evaluation.completed || evaluation.stale || responded.Load() != 1 {
		t.Fatalf("evaluation=%+v responses=%d", evaluation, responded.Load())
	}
	if policy.resolveCalls.Load() != 0 {
		t.Fatalf("absence entered approval resolver %d times", policy.resolveCalls.Load())
	}
	if evaluation.event == nil || evaluation.event.EffectiveAction != "not_found" {
		t.Fatalf("missing not_found audit event: %+v", evaluation.event)
	}
	if got := evaluation.event.Fields["approval_suppressed"]; got != true {
		t.Fatalf("approval_suppressed=%v", got)
	}
}

func TestEvaluateFileNotificationExistingStillResolvesApproval(t *testing.T) {
	policy := &notificationLookupPolicy{}
	handler := NewFileHandler(policy, NewMountRegistry(), &mockFileEmitter{}, true)
	probe := &fixedFileLookupProbe{result: FileLookupResult{Class: LookupExists, Reason: LookupReasonNone}}
	handler.SetFileLookupProbe(probe)
	request, pathname := lookupNotificationRequest(t)

	evaluation := evaluateFileNotificationWithOps(context.Background(), 99, 8, handler, request, fileNotificationOps{
		validate: func(int, uint64) error { return nil },
		respondErrno: func(int, uint64, int32) error {
			t.Fatal("existing lookup received direct errno")
			return nil
		},
	})
	runtime.KeepAlive(pathname)

	if evaluation.completed || evaluation.stale || evaluation.result.Action != ActionContinue {
		t.Fatalf("evaluation=%+v", evaluation)
	}
	if policy.resolveCalls.Load() != 1 {
		t.Fatalf("approval resolver calls=%d", policy.resolveCalls.Load())
	}
	if got := evaluation.event.Fields["lookup_probe_result"]; got != string(LookupExists) {
		t.Fatalf("lookup_probe_result=%v", got)
	}
}

func TestEvaluateFileNotificationStaleAfterProbeNeverApprovesOrResponds(t *testing.T) {
	policy := &notificationLookupPolicy{}
	handler := NewFileHandler(policy, NewMountRegistry(), nil, true)
	handler.SetFileLookupProbe(&fixedFileLookupProbe{result: FileLookupResult{Class: LookupAbsent, Reason: LookupReasonNone, Errno: int32(unix.ENOENT)}})
	request, pathname := lookupNotificationRequest(t)
	var validations atomic.Int32

	evaluation := evaluateFileNotificationWithOps(context.Background(), 99, 9, handler, request, fileNotificationOps{
		validate: func(int, uint64) error {
			if validations.Add(1) >= 2 {
				return unix.ENOENT
			}
			return nil
		},
		respondErrno: func(int, uint64, int32) error {
			t.Fatal("stale notification received response")
			return nil
		},
	})
	runtime.KeepAlive(pathname)
	if !evaluation.stale || policy.resolveCalls.Load() != 0 {
		t.Fatalf("evaluation=%+v resolver=%d", evaluation, policy.resolveCalls.Load())
	}
}

func TestEvaluateFileNotificationStalenessCancelsPendingResolution(t *testing.T) {
	policy := &notificationLookupPolicy{block: true}
	handler := NewFileHandler(policy, NewMountRegistry(), nil, true)
	handler.SetFileLookupProbe(&fixedFileLookupProbe{result: FileLookupResult{Class: LookupExists, Reason: LookupReasonNone}})
	request, pathname := lookupNotificationRequest(t)
	var validations atomic.Int32
	started := time.Now()

	evaluation := evaluateFileNotificationWithOps(context.Background(), 99, 10, handler, request, fileNotificationOps{
		validate: func(int, uint64) error {
			if validations.Add(1) >= 3 {
				return unix.ENOENT
			}
			return nil
		},
		respondErrno: func(int, uint64, int32) error { return nil },
	})
	runtime.KeepAlive(pathname)
	if !evaluation.stale || policy.resolveCalls.Load() != 1 {
		t.Fatalf("evaluation=%+v resolver=%d", evaluation, policy.resolveCalls.Load())
	}
	if time.Since(started) > time.Second {
		t.Fatal("stale approval cancellation exceeded bound")
	}
}
