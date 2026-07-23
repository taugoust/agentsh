package landlock

import (
	"path/filepath"
	"strings"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
)

// DeriveExecutePathsFromPolicy extracts directory paths from policy command rules.
func DeriveExecutePathsFromPolicy(p *policy.Policy) []string {
	if p == nil {
		return nil
	}

	pathSet := make(map[string]struct{})

	for _, rule := range p.CommandRules {
		// Only process allow rules
		if strings.ToLower(rule.Decision) != "allow" {
			continue
		}

		for _, cmd := range rule.Commands {
			cmd = strings.TrimSpace(cmd)
			if cmd == "" {
				continue
			}

			// Only process commands with path separators
			if !strings.Contains(cmd, "/") {
				continue
			}

			// Extract base directory
			dir := extractBaseDir(cmd)
			if dir != "" && dir != "." && dir != "/" {
				pathSet[dir] = struct{}{}
			}
		}
	}

	// Convert to slice
	paths := make([]string, 0, len(pathSet))
	for p := range pathSet {
		paths = append(paths, p)
	}

	return paths
}

// DeriveReadPathsFromPolicy extracts directory paths from policy file rules.
func DeriveReadPathsFromPolicy(p *policy.Policy) []string {
	if p == nil {
		return nil
	}

	pathSet := make(map[string]struct{})

	for _, rule := range p.FileRules {
		// Only process allow rules
		if strings.ToLower(rule.Decision) != "allow" {
			continue
		}

		// Only include rules that allow read operations
		hasRead := false
		for _, op := range rule.Operations {
			op = strings.ToLower(op)
			if op == "read" || op == "*" {
				hasRead = true
				break
			}
		}
		if !hasRead && len(rule.Operations) > 0 {
			continue
		}

		for _, path := range rule.Paths {
			path = strings.TrimSpace(path)
			if path == "" {
				continue
			}

			// Extract base directory
			dir := extractBaseDir(path)
			if dir != "" && dir != "." && dir != "/" {
				pathSet[dir] = struct{}{}
			}
		}
	}

	// Convert to slice
	paths := make([]string, 0, len(pathSet))
	for p := range pathSet {
		paths = append(paths, p)
	}

	return paths
}

// DeriveListPathsFromPolicy extracts directory-only Landlock roots from allow
// rules that grant list without also granting full file reads. Unlike ordinary
// read-root derivation, an exact path names that directory itself: a `list` rule
// for `/` must not be collapsed away, and a `list` rule for `/scratch` must not
// become a rule for all of `/`. Glob roots are deliberately omitted because a
// Landlock path-beneath READ_DIR rule cannot preserve their segment bounds.
func DeriveListPathsFromPolicy(p *policy.Policy) []string {
	if p == nil {
		return nil
	}
	pathSet := make(map[string]struct{})
	for _, rule := range p.FileRules {
		if strings.ToLower(rule.Decision) != "allow" {
			continue
		}
		hasList := false
		hasFullRead := len(rule.Operations) == 0
		for _, operation := range rule.Operations {
			switch strings.ToLower(operation) {
			case "list":
				hasList = true
			case "read", "*":
				hasFullRead = true
			}
		}
		if !hasList || hasFullRead {
			continue
		}
		for _, pattern := range rule.Paths {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" || strings.IndexAny(pattern, "*?[") >= 0 {
				continue
			}
			path := filepath.Clean(pattern)
			if filepath.IsAbs(path) {
				pathSet[path] = struct{}{}
			}
		}
	}
	return pathSetToSlice(pathSet)
}

// DeriveApproveReadPathsFromPolicy extracts Landlock read path prefixes for
// approvable file rules, excluding prefixes that overlap explicit deny rules.
func DeriveApproveReadPathsFromPolicy(p *policy.Policy) []string {
	return deriveFilePathsFromPolicy(p, "approve", fileRuleHasReadOp, true)
}

// DeriveApproveWritePathsFromPolicy extracts Landlock write path prefixes for
// approvable file rules, excluding prefixes that overlap explicit deny rules.
func DeriveApproveWritePathsFromPolicy(p *policy.Policy) []string {
	return deriveFilePathsFromPolicy(p, "approve", fileRuleHasWriteOp, true)
}

// DeriveApproveExecutePathsFromPolicy extracts Landlock execute path prefixes
// for approvable command rules.
func DeriveApproveExecutePathsFromPolicy(p *policy.Policy) []string {
	if p == nil {
		return nil
	}
	pathSet := make(map[string]struct{})
	for _, rule := range p.CommandRules {
		if strings.ToLower(rule.Decision) != "approve" {
			continue
		}
		for _, cmd := range rule.Commands {
			cmd = strings.TrimSpace(cmd)
			if cmd == "" || !strings.Contains(cmd, "/") {
				continue
			}
			dir := extractBaseDir(cmd)
			if dir != "" && dir != "." && dir != "/" {
				pathSet[dir] = struct{}{}
			}
		}
	}
	return pathSetToSlice(pathSet)
}

// DeriveWritePathsFromPolicy extracts directory paths from policy file rules with write access.
func DeriveWritePathsFromPolicy(p *policy.Policy) []string {
	if p == nil {
		return nil
	}

	pathSet := make(map[string]struct{})

	for _, rule := range p.FileRules {
		// Only process allow rules
		if strings.ToLower(rule.Decision) != "allow" {
			continue
		}

		// Only include rules that allow write operations
		hasWrite := false
		for _, op := range rule.Operations {
			op = strings.ToLower(op)
			if op == "write" || op == "create" || op == "delete" || op == "rename" || op == "*" {
				hasWrite = true
				break
			}
		}
		if !hasWrite {
			continue
		}

		for _, path := range rule.Paths {
			path = strings.TrimSpace(path)
			if path == "" {
				continue
			}

			// Extract base directory
			dir := extractBaseDir(path)
			if dir != "" && dir != "." && dir != "/" {
				pathSet[dir] = struct{}{}
			}
		}
	}

	// Convert to slice
	paths := make([]string, 0, len(pathSet))
	for p := range pathSet {
		paths = append(paths, p)
	}

	return paths
}

func deriveFilePathsFromPolicy(p *policy.Policy, decision string, opMatch func(policy.FileRule) bool, excludeDenyOverlap bool) []string {
	if p == nil {
		return nil
	}
	pathSet := make(map[string]struct{})
	denyDirs := denyFileRuleBaseDirs(p)
	for _, rule := range p.FileRules {
		if strings.ToLower(rule.Decision) != decision {
			continue
		}
		if !opMatch(rule) {
			continue
		}
		for _, pathPattern := range rule.Paths {
			pathPattern = strings.TrimSpace(pathPattern)
			if pathPattern == "" {
				continue
			}
			dir := extractBaseDir(pathPattern)
			if dir == "" || dir == "." || dir == "/" {
				continue
			}
			if excludeDenyOverlap && overlapsAnyPathPrefix(dir, denyDirs) {
				continue
			}
			pathSet[dir] = struct{}{}
		}
	}
	return pathSetToSlice(pathSet)
}

func fileRuleHasReadOp(rule policy.FileRule) bool {
	if len(rule.Operations) == 0 {
		return true
	}
	for _, op := range rule.Operations {
		switch strings.ToLower(op) {
		case "read", "open", "stat", "list", "readlink", "access", "*":
			return true
		}
	}
	return false
}

func fileRuleHasWriteOp(rule policy.FileRule) bool {
	for _, op := range rule.Operations {
		switch strings.ToLower(op) {
		case "write", "create", "mkdir", "delete", "rmdir", "rename", "link", "symlink", "chmod", "chown", "mknod", "*":
			return true
		}
	}
	return false
}

func denyFileRuleBaseDirs(p *policy.Policy) []string {
	if p == nil {
		return nil
	}
	var dirs []string
	for _, rule := range p.FileRules {
		if strings.ToLower(rule.Decision) != "deny" {
			continue
		}
		for _, pathPattern := range rule.Paths {
			pathPattern = strings.TrimSpace(pathPattern)
			if pathPattern == "" {
				continue
			}
			dir := extractBaseDir(pathPattern)
			if dir != "" && dir != "." {
				dirs = append(dirs, dir)
			}
		}
	}
	return dirs
}

func overlapsAnyPathPrefix(candidate string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if pathPrefixesOverlap(candidate, prefix) {
			return true
		}
	}
	return false
}

func pathPrefixesOverlap(a, b string) bool {
	if a == "/" || b == "/" || a == b {
		return true
	}
	return strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func pathSetToSlice(pathSet map[string]struct{}) []string {
	paths := make([]string, 0, len(pathSet))
	for p := range pathSet {
		paths = append(paths, p)
	}
	return paths
}

// extractBaseDir extracts the non-glob prefix from a path pattern.
// e.g., "/usr/bin/*" -> "/usr/bin"
// e.g., "/opt/*/bin/*" -> "/opt"
// e.g., "/usr/bin/git" -> "/usr/bin"
func extractBaseDir(pathPattern string) string {
	// Find first glob character
	for i, c := range pathPattern {
		if c == '*' || c == '?' || c == '[' {
			// Return directory up to this point
			prefix := pathPattern[:i]
			// Handle cases like "/usr/bin/*" -> get "/usr/bin" not "/usr/bin/"
			prefix = strings.TrimSuffix(prefix, "/")
			if prefix == "" {
				return "/"
			}
			return prefix
		}
	}
	// No glob characters, return directory of the path
	return filepath.Dir(pathPattern)
}

// knownBinaryDirs lists standard FHS directories that contain executable binaries.
var knownBinaryDirs = []string{
	"/bin", "/sbin",
	"/usr/bin", "/usr/sbin",
	"/usr/local/bin", "/usr/local/sbin",
}

// couldContainBinaries returns true if dir is, or is a parent of, a known
// FHS binary directory (e.g. /bin, /usr/bin, /usr/local/sbin).
func couldContainBinaries(dir string) bool {
	for _, binDir := range knownBinaryDirs {
		if dir == binDir || strings.HasPrefix(binDir, dir+"/") {
			return true
		}
	}
	return false
}

// DeriveExecutePathsFromFileRules extracts Landlock execute paths from file
// rules. Explicit file-rule execute grants become Landlock execute grants for
// the corresponding path prefix. Additionally, read/open grants for FHS binary
// directories become execute grants as a compatibility bridge for policies that
// use bare command names (e.g. "git") with glob file rules (e.g. "/usr/**",
// "/bin/**"). Without this, Landlock can block exec with EACCES even when the
// command and file policy engines both allow the operation.
func DeriveExecutePathsFromFileRules(p *policy.Policy) []string {
	if p == nil {
		return nil
	}

	pathSet := make(map[string]struct{})

	for _, rule := range p.FileRules {
		// Only process allow rules
		if strings.ToLower(rule.Decision) != "allow" {
			continue
		}

		hasExecute := false
		hasReadOrOpen := false
		for _, op := range rule.Operations {
			op = strings.ToLower(op)
			if op == "execute" || op == "exec" {
				hasExecute = true
			}
			if op == "read" || op == "open" || op == "*" {
				hasReadOrOpen = true
			}
		}
		if !hasExecute && !hasReadOrOpen && len(rule.Operations) > 0 {
			continue
		}

		for _, path := range rule.Paths {
			path = strings.TrimSpace(path)
			if path == "" {
				continue
			}

			// Extract base directory (strips globs)
			dir := extractBaseDir(path)
			if dir == "" || dir == "." || dir == "/" {
				continue
			}

			if hasExecute || couldContainBinaries(dir) {
				pathSet[dir] = struct{}{}
			}
		}
	}

	// Convert to slice
	paths := make([]string, 0, len(pathSet))
	for p := range pathSet {
		paths = append(paths, p)
	}
	return paths
}

// BuildFromConfig creates a RulesetBuilder from config and policy.
func BuildFromConfig(cfg *config.LandlockConfig, pol *policy.Policy, workspace string, abi int) (*RulesetBuilder, error) {
	b := NewRulesetBuilder(abi)

	// Set workspace (full access)
	if workspace != "" {
		b.SetWorkspace(workspace)
	}

	// Add paths derived from policy
	if pol != nil {
		for _, p := range DeriveExecutePathsFromPolicy(pol) {
			_ = b.AddExecutePath(p)
		}
		for _, p := range DeriveExecutePathsFromFileRules(pol) {
			_ = b.AddExecutePath(p)
		}
		for _, p := range DeriveReadPathsFromPolicy(pol) {
			_ = b.AddReadPath(p)
		}
		for _, p := range DeriveWritePathsFromPolicy(pol) {
			_ = b.AddWritePath(p)
		}
	}

	// Add explicit config paths
	if cfg != nil {
		for _, p := range cfg.AllowExecute {
			_ = b.AddExecutePath(p)
		}
		for _, p := range cfg.AllowRead {
			_ = b.AddReadPath(p)
		}
		for _, p := range cfg.AllowWrite {
			_ = b.AddWritePath(p)
		}
		for _, p := range cfg.DenyPaths {
			b.AddDenyPath(p)
		}
		allowConnect := false
		if cfg.Network.AllowConnectTCP != nil {
			allowConnect = *cfg.Network.AllowConnectTCP
		}
		allowBind := false
		if cfg.Network.AllowBindTCP != nil {
			allowBind = *cfg.Network.AllowBindTCP
		}
		b.SetNetworkAccess(allowConnect, allowBind)
	}

	// Add default deny paths (container escape vectors)
	defaultDenyPaths := []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/run/containerd/containerd.sock",
		"/run/crio/crio.sock",
		"/var/run/crio/crio.sock",
		"/var/run/secrets/kubernetes.io",
		"/run/systemd/private",
	}
	for _, p := range defaultDenyPaths {
		b.AddDenyPath(p)
	}

	return b, nil
}
