package approvals

import (
	"context"
	"testing"
)

func TestFileTreeScopedDecisionMatchesSubtreeAndRule(t *testing.T) {
	m := New("api", 0, nil)
	tree, ok := NewFileTreeScope("read", "/workspace/../workspace/vendor", "outside-read")
	if !ok {
		t.Fatal("NewFileTreeScope returned !ok")
	}
	m.SetScoped(context.Background(), "s1", "cmd1", tree, true, "ok", "outside-read")

	file, ok := NewFileScopeWithRule("open", "/workspace/vendor/README.md", "outside-read")
	if !ok {
		t.Fatal("NewFileScopeWithRule returned !ok")
	}
	dec, ok := m.CheckScoped(context.Background(), "s1", "cmd2", file)
	if !ok || !dec.Approved {
		t.Fatalf("tree approval did not match subtree: ok=%v dec=%+v", ok, dec)
	}

	sensitive, ok := NewFileScopeWithRule("read", "/workspace/vendor/.env", "approve-env-files")
	if !ok {
		t.Fatal("NewFileScopeWithRule sensitive returned !ok")
	}
	if _, ok := m.CheckScoped(context.Background(), "s1", "cmd3", sensitive); ok {
		t.Fatal("tree approval with one rule must not satisfy a different rule")
	}

	outside, ok := NewFileScopeWithRule("read", "/workspace/other/README.md", "outside-read")
	if !ok {
		t.Fatal("NewFileScopeWithRule outside returned !ok")
	}
	if _, ok := m.CheckScoped(context.Background(), "s1", "cmd4", outside); ok {
		t.Fatal("tree approval must not match sibling directories")
	}
}
