// internal/policygen/grouping_test.go
package policygen

import (
	"path/filepath"
	"testing"
)

func TestGroupPaths_ThresholdCollapse(t *testing.T) {
	// Normalize paths to use platform-specific separators
	paths := []string{
		filepath.FromSlash("/workspace/src/a.ts"),
		filepath.FromSlash("/workspace/src/b.ts"),
		filepath.FromSlash("/workspace/src/c.ts"),
		filepath.FromSlash("/workspace/src/d.ts"),
		filepath.FromSlash("/workspace/src/e.ts"),
		filepath.FromSlash("/workspace/src/f.ts"),
	}

	groups := GroupPaths(paths, 5)

	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	wantPattern := filepath.FromSlash("/workspace/src") + "/**"
	if groups[0].Pattern != wantPattern {
		t.Errorf("expected pattern %q, got %q", wantPattern, groups[0].Pattern)
	}
}

func TestGroupPaths_BelowThreshold(t *testing.T) {
	// Normalize paths to use platform-specific separators
	paths := []string{
		filepath.FromSlash("/workspace/src/a.ts"),
		filepath.FromSlash("/workspace/src/b.ts"),
	}

	groups := GroupPaths(paths, 5)

	// Below threshold, keep individual paths
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
}

func TestGroupPaths_CommonPrefix(t *testing.T) {
	// Normalize paths to use platform-specific separators
	paths := []string{
		filepath.FromSlash("/workspace/node_modules/lodash/index.js"),
		filepath.FromSlash("/workspace/node_modules/lodash/fp.js"),
		filepath.FromSlash("/workspace/node_modules/express/index.js"),
		filepath.FromSlash("/workspace/node_modules/express/router.js"),
		filepath.FromSlash("/workspace/node_modules/axios/index.js"),
		filepath.FromSlash("/workspace/node_modules/axios/lib/core.js"),
	}

	groups := GroupPaths(paths, 3)

	// Should collapse to /workspace/node_modules/**
	if len(groups) != 1 {
		t.Fatalf("expected 1 group after prefix collapse, got %d: %+v", len(groups), groups)
	}
	wantPattern := filepath.FromSlash("/workspace/node_modules") + "/**"
	if groups[0].Pattern != wantPattern {
		t.Errorf("expected %q, got %q", wantPattern, groups[0].Pattern)
	}
}

func TestGroupDomains_WildcardCollapse(t *testing.T) {
	domains := []string{
		"api.github.com",
		"raw.github.com",
		"gist.github.com",
	}

	groups := GroupDomains(domains)

	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].Pattern != "*.github.com" {
		t.Errorf("expected '*.github.com', got %q", groups[0].Pattern)
	}
}

func TestGroupDomains_NoCollapse(t *testing.T) {
	domains := []string{
		"api.github.com",
		"registry.npmjs.org",
	}

	groups := GroupDomains(domains)

	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
}
