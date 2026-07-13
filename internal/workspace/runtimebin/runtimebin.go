package runtimebin

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// packagedPath is injected by hermetic package builds. When it is set, internal
// workspace lifecycle commands must resolve only from this trusted path and
// never fall back to the ambient login or session PATH.
var packagedPath string

// Resolve returns an absolute executable path for an internal workspace
// lifecycle dependency. Non-hermetic builds retain basename/PATH lookup as a
// compatibility fallback, but package builds fail closed within packagedPath.
func Resolve(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || filepath.Base(name) != name || name == "." || name == ".." {
		return "", fmt.Errorf("invalid runtime executable name %q", name)
	}

	if trustedPath := strings.TrimSpace(packagedPath); trustedPath != "" {
		for _, dir := range filepath.SplitList(trustedPath) {
			dir = strings.TrimSpace(dir)
			if dir == "" || !filepath.IsAbs(dir) {
				continue
			}
			candidate := filepath.Join(dir, name)
			resolved, err := exec.LookPath(candidate)
			if err == nil {
				return filepath.Clean(resolved), nil
			}
		}
		return "", fmt.Errorf("required runtime executable %q is unavailable in the packaged runtime closure", name)
	}

	resolved, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("required runtime executable %q is unavailable: %w", name, err)
	}
	absolute, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve runtime executable %q: %w", name, err)
	}
	return filepath.Clean(absolute), nil
}
