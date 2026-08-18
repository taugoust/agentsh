package api

import (
	"os"
	"path"
	"path/filepath"

	"github.com/agentsh/agentsh/internal/approvals"
)

func fileApprovalScope(operation, filePath, rule string) (approvals.Scope, bool) {
	cleanPath := filepath.ToSlash(filepath.Clean(filePath))
	return approvals.NewFileScopeWithRule(operation, cleanPath, rule)
}

func fileApprovalScopeOptions(operation, filePath, rule string) (approvals.Scope, bool, []map[string]any) {
	cleanPath := filepath.ToSlash(filepath.Clean(filePath))
	exact, ok := fileApprovalScope(operation, cleanPath, rule)
	if !ok {
		return approvals.Scope{}, false, nil
	}

	dirPath := cleanPath
	if info, err := os.Stat(filepath.FromSlash(cleanPath)); err != nil || !info.IsDir() {
		dirPath = path.Dir(cleanPath)
	}
	dir, dirOK := approvals.NewFileDirScope(operation, dirPath, rule)
	tree, treeOK := approvals.NewFileTreeScope(operation, dirPath, rule)

	options := []map[string]any{approvals.ScopeFields(exact)}
	seen := map[string]bool{exact.Key: true}
	appendOption := func(scope approvals.Scope, ok bool) {
		if !ok || seen[scope.Key] {
			return
		}
		seen[scope.Key] = true
		options = append(options, approvals.ScopeFields(scope))
	}
	appendOption(dir, dirOK)
	appendOption(tree, treeOK)

	// When a model first touches one subdirectory, offer the containing
	// directory tree as an additional session scope. This lets the operator
	// approve the common parent for subsequent sibling subdirectory accesses
	// without granting broader access than that immediate parent.
	parentDir := path.Dir(dirPath)
	if parentDir != dirPath && parentDir != "." && parentDir != "/" {
		parentTree, parentTreeOK := approvals.NewFileTreeScope(operation, parentDir, rule)
		appendOption(parentTree, parentTreeOK)
	}

	return exact, true, options
}
