package api

import (
	"os"
	"path"
	"path/filepath"

	"github.com/agentsh/agentsh/internal/approvals"
)

func fileApprovalScopeOptions(operation, filePath, rule string) (approvals.Scope, bool, []map[string]any) {
	cleanPath := filepath.ToSlash(filepath.Clean(filePath))
	exact, ok := approvals.NewFileScopeWithRule(operation, cleanPath, rule)
	if !ok {
		return approvals.Scope{}, false, nil
	}

	dirPath := cleanPath
	if info, err := os.Stat(filepath.FromSlash(cleanPath)); err != nil || !info.IsDir() {
		dirPath = path.Dir(cleanPath)
	}
	tree, treeOK := approvals.NewFileTreeScope(operation, dirPath, rule)

	options := []map[string]any{approvals.ScopeFields(exact)}
	if treeOK && tree.Key != exact.Key {
		options = append(options, approvals.ScopeFields(tree))
	}
	return exact, true, options
}
