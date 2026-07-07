package approvals

import "testing"

func TestNewCommandScope_ExactInvocation(t *testing.T) {
	scope, ok := NewCommandScope("git", []string{"status", "--short"}, "approve-git")
	if !ok {
		t.Fatal("NewCommandScope returned !ok")
	}
	if scope.Kind != "command" || scope.Operation != "exec" || scope.Rule != "approve-git" {
		t.Fatalf("unexpected scope metadata: %+v", scope)
	}
	if scope.Key == "" || scope.Key[:8] != "command:" {
		t.Fatalf("unexpected key: %q", scope.Key)
	}
	if scope.Label != "git status --short" {
		t.Fatalf("label = %q", scope.Label)
	}

	same, ok := NewCommandScope("git", []string{"status", "--short"}, "approve-git")
	if !ok {
		t.Fatal("same NewCommandScope returned !ok")
	}
	if same.Key != scope.Key {
		t.Fatalf("same invocation key mismatch: %q != %q", same.Key, scope.Key)
	}

	different, ok := NewCommandScope("git", []string{"status"}, "approve-git")
	if !ok {
		t.Fatal("different NewCommandScope returned !ok")
	}
	if different.Key == scope.Key {
		t.Fatalf("different args should produce different scope key %q", scope.Key)
	}
}
