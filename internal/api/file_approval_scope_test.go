package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/approvals"
)

func TestFileApprovalScopeOptions_IncludesImmediateParentTree(t *testing.T) {
	root := t.TempDir()
	subdir := filepath.Join(root, "dir", "subdir")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}

	_, ok, options := fileApprovalScopeOptions("read", subdir, "outside-read")
	if !ok {
		t.Fatal("fileApprovalScopeOptions returned !ok")
	}

	parent := filepath.ToSlash(filepath.Join(root, "dir"))
	parentTree, ok := approvals.NewFileTreeScope("read", parent, "outside-read")
	if !ok {
		t.Fatal("NewFileTreeScope returned !ok")
	}
	if !scopeOptionKeys(options)[parentTree.Key] {
		t.Fatalf("parent tree option %q missing from %#v", parentTree.Key, options)
	}
}

func TestFileApprovalScopeOptions_DoesNotIncludeGrandparentTree(t *testing.T) {
	root := t.TempDir()
	subdir := filepath.Join(root, "dir", "subdir")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}

	_, ok, options := fileApprovalScopeOptions("read", subdir, "outside-read")
	if !ok {
		t.Fatal("fileApprovalScopeOptions returned !ok")
	}

	grandparent := filepath.ToSlash(root)
	grandparentTree, ok := approvals.NewFileTreeScope("read", grandparent, "outside-read")
	if !ok {
		t.Fatal("NewFileTreeScope returned !ok")
	}
	if scopeOptionKeys(options)[grandparentTree.Key] {
		t.Fatalf("grandparent tree option %q should not be offered by default: %#v", grandparentTree.Key, options)
	}
}

func TestFileApprovalScopeOptions_ParentTreeUsesSameRule(t *testing.T) {
	root := t.TempDir()
	filePath := filepath.Join(root, "dir", "subdir", "file.txt")

	_, ok, options := fileApprovalScopeOptions("open", filePath, "approve-sensitive")
	if !ok {
		t.Fatal("fileApprovalScopeOptions returned !ok")
	}

	parent := filepath.ToSlash(filepath.Join(root, "dir"))
	parentTree, ok := approvals.NewFileTreeScope("open", parent, "approve-sensitive")
	if !ok {
		t.Fatal("NewFileTreeScope returned !ok")
	}
	matched := false
	for _, option := range options {
		if option["scope_key"] == parentTree.Key {
			matched = true
			if option["scope_rule"] != "approve-sensitive" {
				t.Fatalf("parent tree rule = %v, want approve-sensitive", option["scope_rule"])
			}
		}
	}
	if !matched {
		t.Fatalf("parent tree option %q missing from %#v", parentTree.Key, options)
	}
}

func scopeOptionKeys(options []map[string]any) map[string]bool {
	keys := make(map[string]bool, len(options))
	for _, option := range options {
		key, _ := option["scope_key"].(string)
		if key != "" {
			keys[key] = true
		}
	}
	return keys
}

