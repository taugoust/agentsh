//go:build linux && cgo

package unix

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCompositionExecutableIdentityRequiresPinnedNixBubblewrap0112(t *testing.T) {
	valid := "/nix/store/zp6rsi809fx5h7dccn7aidg1mj8zgn52-bubblewrap-0.11.2/bin/bwrap"
	if !isNixBubblewrap0112Executable(valid) {
		t.Fatalf("rejected captured Bubblewrap identity %q", valid)
	}
	for _, invalid := range []string{
		"/usr/bin/bwrap",
		"/tmp/bubblewrap-0.11.2/bin/bwrap",
		"/nix/store/zp6rsi809fx5h7dccn7aidg1mj8zgn52-bubblewrap-0.11.3/bin/bwrap",
		"/nix/store/!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!-bubblewrap-0.11.2/bin/bwrap",
		"/nix/store/zp6rsi809fx5h7dccn7aidg1mj8zgn52-bubblewrap-0.11.2/bin/not-bwrap",
	} {
		if isNixBubblewrap0112Executable(invalid) {
			t.Fatalf("accepted unpinned Bubblewrap identity %q", invalid)
		}
	}
}

func TestCompositionRedirectorTransitionLimit(t *testing.T) {
	redirector := &compositionRedirector{
		maxTransitions: 2,
		maxDepth:       4,
		processes:      make(map[int]compositionProcess),
	}
	if _, err := redirector.reserveTransition(os.Getpid()); err != nil {
		t.Fatal(err)
	}
	if _, err := redirector.reserveTransition(os.Getpid()); err != nil {
		t.Fatal(err)
	}
	if _, err := redirector.reserveTransition(os.Getpid()); err == nil || !strings.Contains(err.Error(), "E_COMPOSITION_LIMIT_EXCEEDED") {
		t.Fatalf("third transition error = %v", err)
	}
}

func TestCompositionRedirectorCloseWaitsForActiveBrokerAndCleansOnce(t *testing.T) {
	cleanupErr := errors.New("cleanup sentinel")
	cleanupCalls := 0
	redirectorInterface, err := NewManagedCompositionRedirector("/adapter", func(*os.File, int) {}, 4, 4, func() error {
		cleanupCalls++
		return cleanupErr
	})
	if err != nil {
		t.Fatal(err)
	}
	redirector := redirectorInterface.(*compositionRedirector)
	if err := redirector.beginRedirect(); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- redirector.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("close returned before active broker completed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	redirector.active.Done()
	select {
	case err := <-closed:
		if !errors.Is(err, cleanupErr) {
			t.Fatalf("close error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not finish after active broker completed")
	}
	if cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d", cleanupCalls)
	}
	if _, err := redirector.reserveTransition(os.Getpid()); err == nil || !strings.Contains(err.Error(), "redirector is closed") {
		t.Fatalf("post-close reservation error = %v", err)
	}
	if err := redirector.Close(); !errors.Is(err, cleanupErr) || cleanupCalls != 1 {
		t.Fatalf("second close error=%v cleanup calls=%d", err, cleanupCalls)
	}
}

func TestCompositionRedirectorDropsTrackingWhenPidfdPinFails(t *testing.T) {
	redirector := &compositionRedirector{processes: make(map[int]compositionProcess)}
	entry := compositionProcess{depth: 1, token: 9}
	const missingPID = int(^uint32(0) >> 1)
	redirector.trackProcess(missingPID, entry)
	redirector.mu.Lock()
	_, retained := redirector.processes[missingPID]
	redirector.mu.Unlock()
	if retained {
		t.Fatal("failed pidfd pin left stale process tracking")
	}
}

func TestCompositionRedirectorNestedDepthLimit(t *testing.T) {
	parent, err := processParent(os.Getpid())
	if err != nil || parent <= 0 {
		t.Fatalf("read parent: pid=%d err=%v", parent, err)
	}
	redirector := &compositionRedirector{
		maxTransitions: 4,
		maxDepth:       2,
		processes: map[int]compositionProcess{
			parent: {depth: 2, token: 1},
		},
	}
	if _, err := redirector.reserveTransition(os.Getpid()); err == nil || !strings.Contains(err.Error(), "namespace depth 3") {
		t.Fatalf("nested depth error = %v", err)
	}
}
