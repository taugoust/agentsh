package api

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func draftLandingPathsDigest(paths ...string) string {
	hash := sha256.New()
	for _, candidate := range paths {
		_, _ = hash.Write([]byte(candidate))
		_, _ = hash.Write([]byte{0})
	}
	return fmt.Sprintf("sha256:%x", hash.Sum(nil))
}

func TestValidateDraftLandingPaths(t *testing.T) {
	paths := []string{"flake.nix", ".github/workflows/test.yml", "dir/AGENTS.md"}
	if err := validateDraftLandingPaths(paths, len(paths), draftLandingPathsDigest(paths...)); err != nil {
		t.Fatalf("valid paths rejected: %v", err)
	}

	tests := []struct {
		name   string
		paths  []string
		count  int
		digest string
	}{
		{name: "count mismatch", paths: paths, count: 2, digest: draftLandingPathsDigest(paths...)},
		{name: "digest mismatch", paths: paths, count: len(paths), digest: draftLandingPathsDigest("flake.nix")},
		{name: "absolute", paths: []string{"/flake.nix"}, count: 1, digest: draftLandingPathsDigest("/flake.nix")},
		{name: "parent traversal", paths: []string{"a/../flake.nix"}, count: 1, digest: draftLandingPathsDigest("a/../flake.nix")},
		{name: "non canonical", paths: []string{"a//flake.nix"}, count: 1, digest: draftLandingPathsDigest("a//flake.nix")},
		{name: "nul", paths: []string{"flake.nix\x00ignored"}, count: 1, digest: draftLandingPathsDigest("flake.nix\x00ignored")},
		{name: "empty", paths: []string{""}, count: 1, digest: draftLandingPathsDigest("")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateDraftLandingPaths(test.paths, test.count, test.digest); err == nil {
				t.Fatal("invalid paths accepted")
			}
		})
	}
}
