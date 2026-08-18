//go:build linux && cgo

package unix

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/composition"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// mockFilePolicy implements FilePolicyChecker for testing.
type mockFilePolicy struct {
	decisions map[string]FilePolicyDecision // path -> decision
}

func (m *mockFilePolicy) CheckFile(_ context.Context, path, operation string) FilePolicyDecision {
	if dec, ok := m.decisions[path]; ok {
		return dec
	}
	// Default: allow if path not found
	return FilePolicyDecision{
		Decision:          "allow",
		EffectiveDecision: "allow",
		Rule:              "default_allow",
	}
}

type mockApprovalFilePolicy struct {
	policy       *mockFilePolicy
	resolutions  map[string]FilePolicyDecision
	resolveCalls []string
}

func (m *mockApprovalFilePolicy) CheckFile(ctx context.Context, path, operation string) FilePolicyDecision {
	return m.policy.CheckFile(ctx, path, operation)
}

func (m *mockApprovalFilePolicy) ResolveFileApproval(_ context.Context, target, _ string, prepared FilePolicyDecision) (FilePolicyDecision, error) {
	m.resolveCalls = append(m.resolveCalls, target)
	if resolved, ok := m.resolutions[target]; ok {
		return resolved, nil
	}
	prepared.EffectiveDecision = "deny"
	return prepared, nil
}

type cancelBlockingApprovalFilePolicy struct {
	policy       *mockFilePolicy
	resolveCalls []string
	entered      chan string
}

func (m *cancelBlockingApprovalFilePolicy) CheckFile(ctx context.Context, path, operation string) FilePolicyDecision {
	return m.policy.CheckFile(ctx, path, operation)
}

func (m *cancelBlockingApprovalFilePolicy) ResolveFileApproval(ctx context.Context, target, _ string, prepared FilePolicyDecision) (FilePolicyDecision, error) {
	m.resolveCalls = append(m.resolveCalls, target)
	m.entered <- target
	<-ctx.Done()
	prepared.EffectiveDecision = "deny"
	return prepared, ctx.Err()
}

// mockFileEmitter captures events for verification.
type mockFileEmitter struct {
	events []types.Event
}

func (m *mockFileEmitter) AppendEvent(_ context.Context, ev types.Event) error {
	m.events = append(m.events, ev)
	return nil
}

func (m *mockFileEmitter) Publish(ev types.Event) {}

func requirePolicyObligationAuditFields(t *testing.T, event *types.Event, count int) []map[string]any {
	t.Helper()
	if event == nil || event.Fields == nil {
		t.Fatalf("event has no audit fields: %+v", event)
	}
	obligations, ok := event.Fields["policy_obligations"].([]map[string]any)
	if !ok {
		t.Fatalf("policy_obligations has type %T, want []map[string]any", event.Fields["policy_obligations"])
	}
	if len(obligations) != count {
		t.Fatalf("policy obligation count = %d, want %d: %+v", len(obligations), count, obligations)
	}
	return obligations
}

func TestFileHandler_PreparePreservesAllObligationsAndDenyDominates(t *testing.T) {
	policy := &mockApprovalFilePolicy{
		policy: &mockFilePolicy{decisions: map[string]FilePolicyDecision{
			"/visible/one": {
				Decision: "allow", EffectiveDecision: "allow", Rule: "allow-visible",
			},
			"/visible/two": {
				Decision: "approve", EffectiveDecision: "approve", Rule: "approve-secondary", CacheOutcome: FileApprovalCacheMiss,
			},
			"/source/one": {
				Decision: "deny", EffectiveDecision: "deny", Rule: "deny-source",
			},
			"/source/two": {
				Decision: "approve", EffectiveDecision: "allow", Rule: "approve-source-two", CacheOutcome: FileApprovalCacheAllow,
			},
		}},
		resolutions: map[string]FilePolicyDecision{
			"/visible/two": {Decision: "approve", EffectiveDecision: "allow"},
		},
	}
	handler := NewFileHandler(policy, NewMountRegistry(), &mockFileEmitter{}, true)
	prepared := handler.Prepare(context.Background(), FileRequest{
		PID: os.Getpid(), Syscall: int32(unix.SYS_RENAMEAT),
		Path: "/visible/one", Path2: "/visible/two",
		SourcePath: "/source/one", SourcePath2: "/source/two",
		Operation: "rename", SessionID: "prepare-test",
	})

	if len(policy.resolveCalls) != 0 {
		t.Fatalf("Prepare invoked approval resolver: %v", policy.resolveCalls)
	}
	if len(prepared.Obligations) != 4 {
		t.Fatalf("obligations = %+v, want four independent paths", prepared.Obligations)
	}
	want := []struct {
		target      string
		attribution FilePolicyAttribution
		cache       FileApprovalCacheOutcome
	}{
		{"/visible/one", FilePolicyVisiblePath, FileApprovalCacheNotApplicable},
		{"/visible/two", FilePolicySecondPath, FileApprovalCacheMiss},
		{"/source/one", FilePolicyCompositionSource, FileApprovalCacheNotApplicable},
		{"/source/two", FilePolicyCompositionSourceSecond, FileApprovalCacheAllow},
	}
	for i, expected := range want {
		got := prepared.Obligations[i]
		if got.Target != expected.target || got.Attribution != expected.attribution || got.CacheOutcome != expected.cache {
			t.Fatalf("obligation[%d] = %+v, want target=%q attribution=%q cache=%q", i, got, expected.target, expected.attribution, expected.cache)
		}
	}
	if prepared.HasUnresolvedApprovals() {
		t.Fatal("explicit source deny should terminalize Prepare despite another cache miss")
	}

	result, event, err := handler.Resolve(context.Background(), prepared)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if result.Action != ActionDeny || len(policy.resolveCalls) != 0 {
		t.Fatalf("deny-dominant Resolve result=%+v calls=%v", result, policy.resolveCalls)
	}
	if event == nil || event.Policy == nil || event.Policy.Rule != "deny-source" {
		t.Fatalf("deny-dominant event = %+v", event)
	}
	auditObligations := requirePolicyObligationAuditFields(t, event, 4)
	for i, expected := range want {
		if auditObligations[i]["target"] != expected.target ||
			auditObligations[i]["attribution"] != string(expected.attribution) ||
			auditObligations[i]["cache_outcome"] != string(expected.cache) {
			t.Fatalf("audit obligation[%d] = %+v, want target=%q attribution=%q cache=%q", i, auditObligations[i], expected.target, expected.attribution, expected.cache)
		}
	}
	if auditObligations[1]["decision"] != "approve" || auditObligations[1]["rule"] != "approve-secondary" {
		t.Fatalf("secondary approval attribution was hidden: %+v", auditObligations[1])
	}
	if auditObligations[3]["decision"] != "approve" || auditObligations[3]["effective_decision"] != "allow" {
		t.Fatalf("composition-source cached approval attribution was hidden: %+v", auditObligations[3])
	}
}

func TestFileHandler_AuditEventIncludesApprovedSecondaryAndCompositionSourceObligations(t *testing.T) {
	policy := &mockApprovalFilePolicy{
		policy: &mockFilePolicy{decisions: map[string]FilePolicyDecision{
			"/visible/one": {
				Decision: "allow", EffectiveDecision: "allow", Rule: "allow-primary",
			},
			"/visible/two": {
				Decision: "approve", EffectiveDecision: "approve", Rule: "approve-secondary", CacheOutcome: FileApprovalCacheMiss,
			},
			"/source/one": {
				Decision: "approve", EffectiveDecision: "approve", Rule: "approve-source", CacheOutcome: FileApprovalCacheMiss,
			},
		}},
		resolutions: map[string]FilePolicyDecision{},
	}
	handler := NewFileHandler(policy, NewMountRegistry(), &mockFileEmitter{}, false)
	result, event := handler.Handle(context.Background(), FileRequest{
		PID: os.Getpid(), Syscall: int32(unix.SYS_RENAMEAT),
		Path: "/visible/one", Path2: "/visible/two", SourcePath: "/source/one",
		Operation: "rename", SessionID: "audit-attribution-test",
	})
	if result.Action != ActionContinue || len(policy.resolveCalls) != 0 {
		t.Fatalf("audit-only result=%+v resolver calls=%v", result, policy.resolveCalls)
	}
	obligations := requirePolicyObligationAuditFields(t, event, 3)
	if obligations[1]["attribution"] != string(FilePolicySecondPath) ||
		obligations[1]["decision"] != "approve" || obligations[1]["rule"] != "approve-secondary" {
		t.Fatalf("secondary approval obligation = %+v", obligations[1])
	}
	if obligations[2]["attribution"] != string(FilePolicyCompositionSource) ||
		obligations[2]["decision"] != "approve" || obligations[2]["rule"] != "approve-source" {
		t.Fatalf("composition-source approval obligation = %+v", obligations[2])
	}
}

func TestFileHandler_ResolveCancellationInterleavings(t *testing.T) {
	newHandler := func() (*FileHandler, *cancelBlockingApprovalFilePolicy, PreparedFileDecision) {
		policy := &cancelBlockingApprovalFilePolicy{
			policy: &mockFilePolicy{decisions: map[string]FilePolicyDecision{
				"/visible/one": {
					Decision: "approve", EffectiveDecision: "approve", Rule: "approve-one", CacheOutcome: FileApprovalCacheMiss,
				},
				"/visible/two": {
					Decision: "approve", EffectiveDecision: "approve", Rule: "approve-two", CacheOutcome: FileApprovalCacheMiss,
				},
			}},
			entered: make(chan string, 2),
		}
		handler := NewFileHandler(policy, NewMountRegistry(), &mockFileEmitter{}, true)
		prepared := handler.Prepare(context.Background(), FileRequest{
			PID: os.Getpid(), Syscall: int32(unix.SYS_RENAMEAT),
			Path: "/visible/one", Path2: "/visible/two",
			Operation: "rename", SessionID: "resolve-cancellation-test",
		})
		return handler, policy, prepared
	}

	t.Run("pre-canceled context never invokes resolver", func(t *testing.T) {
		handler, policy, prepared := newHandler()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		result, event, err := handler.Resolve(ctx, prepared)
		if !errors.Is(err, context.Canceled) || result.Action != ActionDeny {
			t.Fatalf("pre-canceled Resolve result=%+v err=%v", result, err)
		}
		if len(policy.resolveCalls) != 0 {
			t.Fatalf("pre-canceled Resolve invoked resolver: %v", policy.resolveCalls)
		}
		obligations := requirePolicyObligationAuditFields(t, event, 2)
		if obligations[0]["resolution_error"] != context.Canceled.Error() {
			t.Fatalf("cancellation was not attributed: %+v", obligations[0])
		}
	})

	t.Run("cancellation during first obligation skips second", func(t *testing.T) {
		handler, policy, prepared := newHandler()
		ctx, cancel := context.WithCancel(context.Background())
		type result struct {
			fileResult FileResult
			event      *types.Event
			err        error
		}
		done := make(chan result, 1)
		go func() {
			fileResult, event, err := handler.Resolve(ctx, prepared)
			done <- result{fileResult: fileResult, event: event, err: err}
		}()

		select {
		case target := <-policy.entered:
			if target != "/visible/one" {
				t.Fatalf("first resolver target = %q", target)
			}
		case <-time.After(time.Second):
			t.Fatal("first approval resolver was not entered")
		}
		cancel()

		select {
		case got := <-done:
			if !errors.Is(got.err, context.Canceled) || got.fileResult.Action != ActionDeny {
				t.Fatalf("canceled Resolve result=%+v err=%v", got.fileResult, got.err)
			}
			if len(policy.resolveCalls) != 1 || policy.resolveCalls[0] != "/visible/one" {
				t.Fatalf("resolver calls after cancellation = %v", policy.resolveCalls)
			}
			obligations := requirePolicyObligationAuditFields(t, got.event, 2)
			if obligations[0]["resolution_error"] != context.Canceled.Error() ||
				obligations[1]["effective_decision"] != "approve" {
				t.Fatalf("canceled obligation attribution = %+v", obligations)
			}
		case <-time.After(time.Second):
			t.Fatal("Resolve did not return after cancellation")
		}
	})
}

func TestFileHandler_PrepareCachedDenyDominatesUnresolvedApprovals(t *testing.T) {
	policy := &mockApprovalFilePolicy{
		policy: &mockFilePolicy{decisions: map[string]FilePolicyDecision{
			"/visible/one": {
				Decision: "approve", EffectiveDecision: "approve", Rule: "approve-primary", CacheOutcome: FileApprovalCacheMiss,
			},
			"/visible/two": {
				Decision: "approve", EffectiveDecision: "deny", Rule: "approve-secondary", CacheOutcome: FileApprovalCacheDeny,
			},
			"/source/one": {
				Decision: "allow", EffectiveDecision: "allow", Rule: "allow-source",
			},
			"/source/two": {
				Decision: "approve", EffectiveDecision: "approve", Rule: "approve-source", CacheOutcome: FileApprovalCacheMiss,
			},
		}},
		resolutions: map[string]FilePolicyDecision{
			"/visible/one": {Decision: "approve", EffectiveDecision: "allow"},
			"/source/two":  {Decision: "approve", EffectiveDecision: "allow"},
		},
	}
	handler := NewFileHandler(policy, NewMountRegistry(), &mockFileEmitter{}, true)
	prepared := handler.Prepare(context.Background(), FileRequest{
		PID: os.Getpid(), Syscall: int32(unix.SYS_RENAMEAT),
		Path: "/visible/one", Path2: "/visible/two",
		SourcePath: "/source/one", SourcePath2: "/source/two",
		Operation: "rename", SessionID: "cached-deny-test",
	})
	if prepared.HasUnresolvedApprovals() {
		t.Fatal("cached denial must terminalize the combined decision")
	}
	result, event, err := handler.Resolve(context.Background(), prepared)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if result.Action != ActionDeny || len(policy.resolveCalls) != 0 {
		t.Fatalf("cached-deny result=%+v resolver calls=%v", result, policy.resolveCalls)
	}
	if event == nil || event.Policy == nil || event.Policy.Rule != "approve-secondary" || event.Policy.EffectiveDecision != "deny" {
		t.Fatalf("cached-deny event = %+v", event)
	}
}

func TestFileHandler_ResolveProcessesEveryUnresolvedObligation(t *testing.T) {
	policy := &mockApprovalFilePolicy{
		policy: &mockFilePolicy{decisions: map[string]FilePolicyDecision{
			"/visible/one": {
				Decision: "approve", EffectiveDecision: "approve", Rule: "approve-one", CacheOutcome: FileApprovalCacheMiss,
			},
			"/visible/two": {
				Decision: "approve", EffectiveDecision: "allow", Rule: "approve-two", CacheOutcome: FileApprovalCacheAllow,
			},
			"/source/one": {
				Decision: "allow", EffectiveDecision: "allow", Rule: "allow-source-one",
			},
			"/source/two": {
				Decision: "approve", EffectiveDecision: "approve", Rule: "approve-source-two", CacheOutcome: FileApprovalCacheMiss,
			},
		}},
		resolutions: map[string]FilePolicyDecision{
			"/visible/one": {Decision: "approve", EffectiveDecision: "deny"},
			"/source/two":  {Decision: "approve", EffectiveDecision: "allow"},
		},
	}
	handler := NewFileHandler(policy, NewMountRegistry(), &mockFileEmitter{}, true)
	request := FileRequest{
		PID: os.Getpid(), Syscall: int32(unix.SYS_RENAMEAT),
		Path: "/visible/one", Path2: "/visible/two",
		SourcePath: "/source/one", SourcePath2: "/source/two",
		Operation: "rename", SessionID: "resolve-test",
	}
	prepared := handler.Prepare(context.Background(), request)
	if !prepared.HasUnresolvedApprovals() {
		t.Fatal("Prepare did not retain unresolved approval obligations")
	}
	if len(policy.resolveCalls) != 0 {
		t.Fatalf("Prepare invoked approval resolver: %v", policy.resolveCalls)
	}

	result, _, err := handler.Resolve(context.Background(), prepared)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if result.Action != ActionDeny {
		t.Fatalf("one failed approval must deny, got %+v", result)
	}
	if got, want := policy.resolveCalls, []string{"/visible/one", "/source/two"}; !assert.ObjectsAreEqual(got, want) {
		t.Fatalf("resolved obligations = %v, want %v", got, want)
	}

	// Handle remains a Prepare+Resolve compatibility wrapper and therefore
	// resolves the same two obligations in the same stable order.
	policy.resolveCalls = nil
	result, _ = handler.Handle(context.Background(), request)
	if result.Action != ActionDeny {
		t.Fatalf("Handle result = %+v, want deny", result)
	}
	if got, want := policy.resolveCalls, []string{"/visible/one", "/source/two"}; !assert.ObjectsAreEqual(got, want) {
		t.Fatalf("Handle resolved obligations = %v, want %v", got, want)
	}
}

func TestFileHandler_InternalCompositionControlAccessIsWrapperOnly(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runtime")
	path := filepath.Join(root, "pool")
	policy := &mockFilePolicy{decisions: map[string]FilePolicyDecision{
		path: {Decision: "deny", EffectiveDecision: "deny", Rule: "deny-project-control"},
	}}
	handler := NewFileHandler(policy, NewMountRegistry(), &mockFileEmitter{}, true)
	handler.SetInternalControlAccess(root, os.Getpid())

	result, event := handler.Handle(context.Background(), FileRequest{
		PID: os.Getpid(), Syscall: int32(unix.SYS_MKDIRAT), Path: path,
		Operation: "mkdir", SessionID: "composition-test",
	})
	if result.Action != ActionContinue || event == nil || event.Policy == nil || event.Policy.Rule != "allow-agentsh-composition-control" {
		t.Fatalf("trusted wrapper result=%+v event=%+v", result, event)
	}

	result, _ = handler.Handle(context.Background(), FileRequest{
		PID: os.Getpid() + 100000, Syscall: int32(unix.SYS_MKDIRAT), Path: path,
		Operation: "mkdir", SessionID: "composition-test",
	})
	if result.Action != ActionDeny {
		t.Fatalf("untrusted process received internal control access: %+v", result)
	}

	outside := filepath.Join(t.TempDir(), "outside")
	policy.decisions[outside] = FilePolicyDecision{Decision: "deny", EffectiveDecision: "deny", Rule: "deny-outside"}
	result, _ = handler.Handle(context.Background(), FileRequest{
		PID: os.Getpid(), Syscall: int32(unix.SYS_RENAMEAT), Path: path, Path2: outside,
		Operation: "rename", SessionID: "composition-test",
	})
	if result.Action != ActionDeny {
		t.Fatalf("cross-boundary operation received internal control access: %+v", result)
	}
}

func TestFileHandler_ComposedAliasUsesMostRestrictiveSourceDecision(t *testing.T) {
	policy := &mockFilePolicy{decisions: map[string]FilePolicyDecision{
		"/visible/allowed": {
			Decision: "allow", EffectiveDecision: "allow", Rule: "allow-visible",
		},
		"/source/secret": {
			Decision: "deny", EffectiveDecision: "deny", Rule: "deny-source",
		},
	}}
	emitter := &mockFileEmitter{}
	handler := NewFileHandler(policy, NewMountRegistry(), emitter, true)
	result, event := handler.Handle(context.Background(), FileRequest{
		PID: os.Getpid(), Syscall: int32(unix.SYS_OPENAT),
		Path: "/visible/allowed", SourcePath: "/source/secret",
		Operation: "open", SessionID: "composition-test",
	})
	if result.Action != ActionDeny || event == nil || event.Policy == nil || event.Policy.Rule != "deny-source" {
		t.Fatalf("result=%+v event=%+v", result, event)
	}
	if got := event.Fields["composition_source_path"]; got != "/source/secret" {
		t.Fatalf("composition source audit field = %#v", got)
	}
}

func TestFileHandler_ComposedFreshWritableBypassesHostPathPolicy(t *testing.T) {
	registry := NewCompositionPathRegistry()
	t.Cleanup(func() { _ = registry.Close() })
	pid := os.Getpid()
	if err := registry.Register(pid, pid, composition.PathMappings{
		Aliases: []composition.PathAlias{
			{Target: "/", Source: ""},
			{Target: "/etc", Source: "", FreshWritable: true},
			{Target: "/readonly", Source: ""},
			{Target: "/identity", Source: "/identity"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	deny := FilePolicyDecision{Decision: "deny", EffectiveDecision: "deny", Rule: "deny-host-write"}
	policy := &mockFilePolicy{decisions: map[string]FilePolicyDecision{
		"/etc/ld.so.conf": deny,
		"/readonly/file":  deny,
		"/identity/file":  deny,
	}}
	handler := NewFileHandler(policy, NewMountRegistry(), &mockFileEmitter{}, true)
	handler.SetCompositionPathRegistry(registry)

	result, event := handler.Handle(context.Background(), FileRequest{
		PID: pid, Syscall: int32(unix.SYS_OPENAT), Flags: uint32(unix.O_WRONLY | unix.O_CREAT),
		Path: "/etc/ld.so.conf", Operation: "write", SessionID: "composition-test",
	})
	if result.Action != ActionContinue || event == nil || event.Policy == nil ||
		event.Policy.Rule != "allow-composition-fresh-writable" {
		t.Fatalf("fresh writable result=%+v event=%+v", result, event)
	}
	if got := event.Fields["composition_fresh_writable"]; got != true {
		t.Fatalf("fresh writable audit field = %#v", got)
	}

	for _, path := range []string{"/readonly/file", "/identity/file"} {
		result, _ := handler.Handle(context.Background(), FileRequest{
			PID: pid, Syscall: int32(unix.SYS_OPENAT), Flags: uint32(unix.O_WRONLY),
			Path: path, Operation: "write", SessionID: "composition-test",
		})
		if result.Action != ActionDeny {
			t.Fatalf("non-writable composition path %q bypassed policy: %+v", path, result)
		}
	}

	result, _ = handler.Handle(context.Background(), FileRequest{
		PID: pid, Syscall: int32(unix.SYS_RENAMEAT),
		Path: "/etc/ld.so.conf", Path2: "/identity/file",
		Operation: "rename", SessionID: "composition-test",
	})
	if result.Action != ActionDeny {
		t.Fatalf("rename from fresh tmpfs to source-backed path bypassed policy: %+v", result)
	}
}

func TestFileHandler_ComposedSourceDenyIsNotLoaderSafeOverridden(t *testing.T) {
	for _, visible := range []string{"/usr/lib/allowed-looking", "/etc"} {
		t.Run(visible, func(t *testing.T) {
			policy := &mockFilePolicy{decisions: map[string]FilePolicyDecision{
				visible:          {Decision: "allow", EffectiveDecision: "allow", Rule: "allow-visible"},
				"/source/secret": {Decision: "deny", EffectiveDecision: "deny", Rule: "default-deny-files"},
			}}
			handler := NewFileHandler(policy, NewMountRegistry(), nil, true)
			result, _ := handler.Handle(context.Background(), FileRequest{
				PID: os.Getpid(), Syscall: int32(unix.SYS_OPENAT), Path: visible,
				SourcePath: "/source/secret", Operation: "open", SessionID: "composition-test",
			})
			if result.Action != ActionDeny {
				t.Fatalf("source deny at loader-safe destination %q produced %+v", visible, result)
			}
		})
	}
}

func TestFileHandler_AllowWithoutFUSE(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/home/user/file.txt": {
				Decision:          "allow",
				EffectiveDecision: "allow",
				Rule:              "allow_home",
			},
		},
	}
	emitter := &mockFileEmitter{}
	registry := NewMountRegistry()
	handler := NewFileHandler(policy, registry, emitter, true)

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/home/user/file.txt",
		Operation: "open",
		SessionID: "sess-1",
	}

	result, ev := handler.Handle(context.Background(), req)
	if ev != nil {
		_ = emitter.AppendEvent(context.Background(), *ev)
	}

	if result.Action != ActionContinue {
		t.Errorf("expected ActionContinue, got %s", result.Action)
	}
	if result.Errno != 0 {
		t.Errorf("expected Errno 0, got %d", result.Errno)
	}
	if len(emitter.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitter.events))
	}
	ev0 := emitter.events[0]
	if ev0.Source != "seccomp" {
		t.Errorf("expected Source 'seccomp', got %q", ev0.Source)
	}
	if ev0.Type != "file_open" {
		t.Errorf("expected Type 'file_open', got %q", ev0.Type)
	}
	if ev0.Path != "/home/user/file.txt" {
		t.Errorf("expected Path '/home/user/file.txt', got %q", ev0.Path)
	}
	if ev0.SessionID != "sess-1" {
		t.Errorf("expected SessionID 'sess-1', got %q", ev0.SessionID)
	}
	if ev0.Policy == nil {
		t.Fatal("expected non-nil Policy")
	}
	if ev0.Policy.Decision != "allow" {
		t.Errorf("expected policy decision 'allow', got %q", ev0.Policy.Decision)
	}
}

func TestFileHandler_DenyWithoutFUSE(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/etc/shadow": {
				Decision:          "deny",
				EffectiveDecision: "deny",
				Rule:              "deny_etc",
				Message:           "access denied",
			},
		},
	}
	emitter := &mockFileEmitter{}
	registry := NewMountRegistry()
	handler := NewFileHandler(policy, registry, emitter, true) // enforce=true

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/etc/shadow",
		Operation: "open",
		SessionID: "sess-1",
	}

	result, ev := handler.Handle(context.Background(), req)
	if ev != nil {
		_ = emitter.AppendEvent(context.Background(), *ev)
	}

	if result.Action != ActionDeny {
		t.Errorf("expected ActionDeny, got %s", result.Action)
	}
	if result.Errno != int32(unix.EACCES) {
		t.Errorf("expected Errno EACCES (%d), got %d", unix.EACCES, result.Errno)
	}
	if len(emitter.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitter.events))
	}
	ev0 := emitter.events[0]
	if ev0.EffectiveAction != "blocked" {
		t.Errorf("expected EffectiveAction 'blocked', got %q", ev0.EffectiveAction)
	}
}

func TestFileHandler_AuditOnlyUnderFUSE(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/home/user/project/secret.key": {
				Decision:          "deny",
				EffectiveDecision: "deny",
				Rule:              "deny_secrets",
				Message:           "secrets blocked",
			},
		},
	}
	emitter := &mockFileEmitter{}
	registry := NewMountRegistry()
	registry.Register("sess-1", "/home/user/project")
	handler := NewFileHandler(policy, registry, emitter, true) // enforce=true

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/home/user/project/secret.key",
		Operation: "open",
		SessionID: "sess-1",
	}

	result, ev := handler.Handle(context.Background(), req)
	if ev != nil {
		_ = emitter.AppendEvent(context.Background(), *ev)
	}

	// Under FUSE: always continue, let FUSE handle enforcement
	if result.Action != ActionContinue {
		t.Errorf("expected ActionContinue under FUSE, got %s", result.Action)
	}
	if result.Errno != 0 {
		t.Errorf("expected Errno 0 under FUSE, got %d", result.Errno)
	}
	if len(emitter.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitter.events))
	}
	ev0 := emitter.events[0]
	// Should have shadow_deny=true in Fields
	if ev0.Fields == nil {
		t.Fatal("expected non-nil Fields")
	}
	shadowDeny, ok := ev0.Fields["shadow_deny"]
	if !ok {
		t.Fatal("expected shadow_deny in Fields")
	}
	if shadowDeny != true {
		t.Errorf("expected shadow_deny=true, got %v", shadowDeny)
	}
}

func TestFileHandler_EnforceDisabled(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/etc/passwd": {
				Decision:          "deny",
				EffectiveDecision: "deny",
				Rule:              "deny_etc",
				Message:           "access denied",
			},
		},
	}
	emitter := &mockFileEmitter{}
	registry := NewMountRegistry()
	handler := NewFileHandler(policy, registry, emitter, false) // enforce=false

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/etc/passwd",
		Operation: "open",
		SessionID: "sess-1",
	}

	result, ev := handler.Handle(context.Background(), req)
	if ev != nil {
		_ = emitter.AppendEvent(context.Background(), *ev)
	}

	// Audit-only: allow even though policy says deny
	if result.Action != ActionContinue {
		t.Errorf("expected ActionContinue (audit-only), got %s", result.Action)
	}
	if result.Errno != 0 {
		t.Errorf("expected Errno 0 (audit-only), got %d", result.Errno)
	}
	if len(emitter.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitter.events))
	}
	ev0 := emitter.events[0]
	// Event should still reflect the deny decision
	if ev0.Policy == nil || ev0.Policy.Decision != "deny" {
		t.Errorf("expected policy decision 'deny' in audit-only event, got %v", ev0.Policy)
	}
}

func TestFileHandler_Rename(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/home/user/old.txt": {
				Decision:          "allow",
				EffectiveDecision: "allow",
				Rule:              "allow_home",
			},
			"/home/user/new.txt": {
				Decision:          "allow",
				EffectiveDecision: "allow",
				Rule:              "allow_home",
			},
		},
	}
	emitter := &mockFileEmitter{}
	registry := NewMountRegistry()
	handler := NewFileHandler(policy, registry, emitter, true)

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_RENAMEAT2),
		Path:      "/home/user/old.txt",
		Path2:     "/home/user/new.txt",
		Operation: "rename",
		SessionID: "sess-1",
	}

	result, ev := handler.Handle(context.Background(), req)
	if ev != nil {
		_ = emitter.AppendEvent(context.Background(), *ev)
	}

	if result.Action != ActionContinue {
		t.Errorf("expected ActionContinue, got %s", result.Action)
	}
	if len(emitter.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitter.events))
	}
	ev0 := emitter.events[0]
	if ev0.Type != "file_rename" {
		t.Errorf("expected Type 'file_rename', got %q", ev0.Type)
	}
	// Check path2 is in Fields
	if ev0.Fields == nil {
		t.Fatal("expected non-nil Fields for rename")
	}
	if p2, ok := ev0.Fields["path2"]; !ok || p2 != "/home/user/new.txt" {
		t.Errorf("expected Fields[path2]='/home/user/new.txt', got %v", ev0.Fields["path2"])
	}
}

func TestFileHandler_RenameDenyOnSecondPath(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/home/user/old.txt": {
				Decision:          "allow",
				EffectiveDecision: "allow",
				Rule:              "allow_home",
			},
			"/etc/important": {
				Decision:          "deny",
				EffectiveDecision: "deny",
				Rule:              "deny_etc",
				Message:           "cannot write to /etc",
			},
		},
	}
	emitter := &mockFileEmitter{}
	registry := NewMountRegistry()
	handler := NewFileHandler(policy, registry, emitter, true) // enforce=true

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_RENAMEAT2),
		Path:      "/home/user/old.txt",
		Path2:     "/etc/important",
		Operation: "rename",
		SessionID: "sess-1",
	}

	result, _ := handler.Handle(context.Background(), req)

	if result.Action != ActionDeny {
		t.Errorf("expected ActionDeny (second path denied), got %s", result.Action)
	}
	if result.Errno != int32(unix.EACCES) {
		t.Errorf("expected Errno EACCES, got %d", result.Errno)
	}
}

func TestFileHandler_NilPolicy(t *testing.T) {
	emitter := &mockFileEmitter{}
	registry := NewMountRegistry()
	handler := NewFileHandler(nil, registry, emitter, true) // nil policy

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/any/path",
		Operation: "open",
		SessionID: "sess-1",
	}

	result, ev := handler.Handle(context.Background(), req)
	if ev != nil {
		_ = emitter.AppendEvent(context.Background(), *ev)
	}

	if result.Action != ActionContinue {
		t.Errorf("expected ActionContinue (nil policy), got %s", result.Action)
	}
	if len(emitter.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitter.events))
	}
	ev0 := emitter.events[0]
	if ev0.Policy == nil {
		t.Fatal("expected non-nil Policy in event")
	}
	if ev0.Policy.Rule != "no_policy" {
		t.Errorf("expected rule 'no_policy', got %q", ev0.Policy.Rule)
	}
}

func TestFileHandler_NilEmitter(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/some/path": {
				Decision:          "allow",
				EffectiveDecision: "allow",
				Rule:              "allow_all",
			},
		},
	}
	registry := NewMountRegistry()
	// nil emitter - should not panic
	handler := NewFileHandler(policy, registry, nil, true)

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/some/path",
		Operation: "open",
		SessionID: "sess-1",
	}

	// Should not panic
	result, _ := handler.Handle(context.Background(), req)
	assert.Equal(t, ActionContinue, result.Action)
}

func TestFileHandler_NilEmitterDeny(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/secret/path": {
				Decision:          "deny",
				EffectiveDecision: "deny",
				Rule:              "deny_secret",
				Message:           "no matching rule",
			},
		},
	}
	registry := NewMountRegistry()
	handler := NewFileHandler(policy, registry, nil, true) // enforce=true, nil emitter

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/secret/path",
		Operation: "open",
		SessionID: "sess-1",
	}

	result, _ := handler.Handle(context.Background(), req)
	assert.Equal(t, ActionDeny, result.Action)
	assert.Equal(t, int32(unix.EACCES), result.Errno)
}

func TestFileHandler_NilRegistry(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/home/user/file.txt": {
				Decision:          "deny",
				EffectiveDecision: "deny",
				Rule:              "deny_all",
			},
		},
	}
	emitter := &mockFileEmitter{}
	// nil registry - should not panic, paths won't match FUSE
	handler := NewFileHandler(policy, nil, emitter, true)

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/home/user/file.txt",
		Operation: "open",
		SessionID: "sess-1",
	}

	result, _ := handler.Handle(context.Background(), req)
	// Should deny (not treated as FUSE path)
	assert.Equal(t, ActionDeny, result.Action)
	assert.Equal(t, int32(unix.EACCES), result.Errno)
}

func TestFileHandler_NilPolicyAndEmitter(t *testing.T) {
	handler := NewFileHandler(nil, nil, nil, true)

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/any/path",
		Operation: "open",
		SessionID: "sess-1",
	}

	// Should not panic, should allow
	result, _ := handler.Handle(context.Background(), req)
	assert.Equal(t, ActionContinue, result.Action)
}

func TestFileHandler_ProcSelfFD_ResolvesToTarget(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/root/.ssh/id_rsa": {
				Decision:          "deny",
				EffectiveDecision: "deny",
				Rule:              "deny_ssh_keys",
				Message:           "access denied",
			},
		},
	}
	emitter := &mockFileEmitter{}
	registry := NewMountRegistry()
	handler := NewFileHandler(policy, registry, emitter, true)

	tmpFile, err := os.CreateTemp("", "procfd-test")
	if err != nil {
		t.Skip("cannot create temp file")
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	pid := os.Getpid()
	procPath := fmt.Sprintf("/proc/%d/fd/%d", pid, tmpFile.Fd())
	req := FileRequest{
		PID:       pid,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      procPath,
		Operation: "open",
		SessionID: "sess-1",
	}

	result, _ := handler.Handle(context.Background(), req)
	// Resolved to temp file path (not in deny list) → allowed
	assert.Equal(t, ActionContinue, result.Action)
}

func TestFileHandler_EmulateOpen_Field(t *testing.T) {
	handler := NewFileHandler(nil, nil, nil, true)
	assert.False(t, handler.emulateOpen, "emulateOpen should default to false")

	handler.SetEmulateOpen(true)
	assert.True(t, handler.emulateOpen)
}

func TestFileHandler_PseudoPath_AllowedUnconditionally(t *testing.T) {
	// Even if a pseudo-path somehow ended up in the deny map,
	// Handle should short-circuit before reaching policy evaluation.
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"pipe:[12345]": {
				Decision:          "deny",
				EffectiveDecision: "deny",
				Rule:              "deny_all",
			},
		},
	}
	emitter := &mockFileEmitter{}
	registry := NewMountRegistry()
	handler := NewFileHandler(policy, registry, emitter, true)

	pseudoPaths := []string{
		"pipe:[12345]",
		"socket:[67890]",
		"anon_inode:[eventpoll]",
	}
	for _, pp := range pseudoPaths {
		req := FileRequest{
			PID:       1234,
			Syscall:   int32(unix.SYS_NEWFSTATAT),
			Path:      pp,
			Operation: "stat",
			SessionID: "sess-1",
		}
		result, _ := handler.Handle(context.Background(), req)
		assert.Equal(t, ActionContinue, result.Action, "pseudo-path %q should be allowed", pp)
	}
}

func TestFileHandler_ReadOnlyOpen_SkipsEmulation(t *testing.T) {
	// Validates that Handle() returns ActionContinue for allowed read-only opens.
	// This tests the policy layer; the emulation guard in handleFileNotificationEmulated
	// is validated by TestEmulationPath_ReadOnlyOpenat_CaughtByGuard (decision chain)
	// and cannot be directly tested without real seccomp notification fds.
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/lib/x86_64-linux-gnu/libtinfo.so.6": {
				Decision:          "allow",
				EffectiveDecision: "allow",
				Rule:              "system-allow",
			},
		},
	}
	emitter := &mockFileEmitter{}
	handler := NewFileHandler(policy, NewMountRegistry(), emitter, true)
	handler.SetEmulateOpen(true)

	// A read-only open — like the dynamic linker loading a shared library.
	req := FileRequest{
		PID:       500,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/lib/x86_64-linux-gnu/libtinfo.so.6",
		Operation: "open",
		Flags:     uint32(unix.O_RDONLY | unix.O_CLOEXEC),
		SessionID: "sess-test",
	}
	result, _ := handler.Handle(context.Background(), req)
	assert.Equal(t, ActionContinue, result.Action,
		"read-only open must get ActionContinue even with emulation enabled")
}

func TestEmulationPath_ReadOnlyOpenat_CaughtByGuard(t *testing.T) {
	// Validate the full decision chain in handleFileNotificationEmulated:
	// A read-only openat is an open syscall (isOpenSyscall=true) that does
	// NOT trigger shouldFallbackToContinue (no O_TMPFILE, no unemulable flags),
	// so it enters the emulation branch (!forceContinue). The isReadOnlyOpen
	// guard must catch it before emulateOpenat runs.
	flags := uint32(unix.O_RDONLY | unix.O_CLOEXEC)

	// Step 1: It IS an open syscall — would be routed to emulation path.
	assert.True(t, isOpenSyscall(unix.SYS_OPENAT), "openat must be an open syscall")

	// Step 2: It does NOT fall back to CONTINUE — enters emulation branch.
	assert.False(t, shouldFallbackToContinue(unix.SYS_OPENAT, flags, 0),
		"read-only openat must not trigger fallback (enters emulation branch)")
	assert.False(t, shouldUseContinuePathForFileNotify(unix.SYS_OPENAT, flags, 0),
		"read-only openat still takes the emulation branch so explicit policy denies can be enforced")

	// Step 3: The read-only guard catches it before emulateOpenat.
	assert.True(t, isReadOnlyOpen(flags),
		"read-only flags must be caught by isReadOnlyOpen guard")

	// Combined: a read-only openat enters the emulation branch but is
	// intercepted by isReadOnlyOpen → CONTINUE (never emulated via AddFD).
}

func TestEmulationPath_ResolvePathAtFailure_ReadVsWrite(t *testing.T) {
	// Validates behavior when resolvePathAt fails (e.g., Yama ptrace_scope=1,
	// server is not an ancestor of the tracee — common in `agentsh wrap` path
	// because PR_SET_PTRACER does not inherit across fork()).
	//
	// When resolution fails, the emulated handler falls back to CONTINUE for
	// ALL operations. If we can't resolve the path, we can't evaluate policy
	// either way. Reads are obviously safe; writes are also allowed because
	// the alternative (denying ALL child-process writes) makes the environment
	// unusable while providing no real enforcement (reads are equally
	// unmonitored). Other layers (Landlock, FUSE) handle enforcement when
	// seccomp path resolution is unavailable.

	t.Run("read_only_flags_fail_open", func(t *testing.T) {
		// Typical read-only flags from dynamic linker / cat / ls
		readFlags := []uint32{
			uint32(unix.O_RDONLY),                    // plain read
			uint32(unix.O_RDONLY | unix.O_CLOEXEC),   // shared library load
			uint32(unix.O_RDONLY | unix.O_NONBLOCK),  // nonblocking read
			uint32(unix.O_RDONLY | unix.O_DIRECTORY), // directory listing
		}
		for _, flags := range readFlags {
			assert.True(t, isReadOnlyOpen(flags),
				"flags 0x%x should be read-only", flags)
			// forceContinue is false for these (not O_TMPFILE, emulable flags)
			assert.False(t, shouldFallbackToContinue(unix.SYS_OPENAT, flags, 0),
				"flags 0x%x: forceContinue should be false (enters emulation branch)", flags)
		}
	})

	t.Run("write_flags_detected", func(t *testing.T) {
		// Write-flagged opens are correctly classified as non-read-only.
		// On resolvePathAt failure these also fall back to CONTINUE (not deny),
		// because the handler can't evaluate policy without a resolved path.
		writeFlags := []uint32{
			uint32(unix.O_WRONLY), // write only
			uint32(unix.O_RDWR),   // read-write
			uint32(unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC), // truncating write
			uint32(unix.O_WRONLY | unix.O_APPEND),               // append
		}
		for _, flags := range writeFlags {
			assert.False(t, isReadOnlyOpen(flags),
				"flags 0x%x should NOT be read-only", flags)
			assert.True(t, shouldUseContinuePathForFileNotify(unix.SYS_OPENAT, flags, 0),
				"flags 0x%x should use CONTINUE so writes happen as the tracee", flags)
		}
	})
}

func TestFileHandler_RestrictiveNonDenyDecisionDeniesWhenEnforced(t *testing.T) {
	policy := &mockFilePolicy{decisions: map[string]FilePolicyDecision{
		"/workspace/.env": {Decision: "approve", EffectiveDecision: "approve", Rule: "approve-env"},
	}}
	handler := NewFileHandler(policy, NewMountRegistry(), &mockFileEmitter{}, true)
	result, _ := handler.Handle(context.Background(), FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/workspace/.env",
		Operation: "open",
		Flags:     unix.O_RDONLY,
		SessionID: "sess-1",
	})
	if result.Action != ActionDeny || result.Errno != int32(unix.EACCES) {
		t.Fatalf("approve effective decision should fail closed without approval adapter, got action=%s errno=%d", result.Action, result.Errno)
	}
}
