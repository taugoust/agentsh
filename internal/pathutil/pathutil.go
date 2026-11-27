// Package pathutil provides path boundary checking helpers shared across
// packages that need to determine whether a filesystem path is under a root.
package pathutil

import (
	"os"
	"strings"
)

// IsUnderRoot checks if a virtual path (using forward slashes) is equal to or
// under root. Returns false for empty root (fail closed). Handles root=="/".
func IsUnderRoot(path, root string) bool {
	if root == "" {
		return false
	}
	if root == "/" {
		return strings.HasPrefix(path, "/")
	}
	return path == root || strings.HasPrefix(path, root+"/")
}

// IsRealPathUnder checks if a real filesystem path is equal to or under root,
// using os.PathSeparator for boundary checks. Returns false for empty root
// (fail closed). Handles root=="/" or roots that already end with the
// separator.
func IsRealPathUnder(path, root string) bool {
	if root == "" {
		return false
	}
	sep := string(os.PathSeparator)
	if root == "/" || root == sep {
		return true
	}
	if strings.HasSuffix(root, sep) {
		return strings.HasPrefix(path, root)
	}
	return path == root || strings.HasPrefix(path, root+sep)
}

// TrimRootPrefix removes root from the front of path.
func TrimRootPrefix(path, root string) string {
	return strings.TrimPrefix(path, root)
}
