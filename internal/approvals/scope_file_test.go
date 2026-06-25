package approvals

import "testing"

func TestNewFileScope_NormalizesReadLikeOperations(t *testing.T) {
	ops := []string{"open", "read", "stat", "list", "readlink", "access"}
	var first Scope
	for i, op := range ops {
		scope, ok := NewFileScope(op, "/workspace/../workspace/.env")
		if !ok {
			t.Fatalf("NewFileScope(%q) returned !ok", op)
		}
		if scope.Kind != "file" {
			t.Fatalf("Kind = %q, want file", scope.Kind)
		}
		if scope.Key != "file:read:/workspace/.env" {
			t.Fatalf("Key = %q", scope.Key)
		}
		if i == 0 {
			first = scope
		} else if scope != first {
			t.Fatalf("scope for %q = %#v, want %#v", op, scope, first)
		}
	}
}

func TestScopeFields_ExportsScopeFields(t *testing.T) {
	scope, ok := NewFileScope("write", "/workspace/out.txt")
	if !ok {
		t.Fatal("NewFileScope returned !ok")
	}
	fields := ScopeFields(scope)
	if fields["scope_kind"] != "file" || fields["scope_key"] != "file:write:/workspace/out.txt" || fields["scope_label"] != "write /workspace/out.txt" {
		t.Fatalf("unexpected fields: %#v", fields)
	}
}
