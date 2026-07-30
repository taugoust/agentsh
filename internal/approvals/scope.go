package approvals

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	ScopeOnce    = "once"
	ScopeSession = "session"

	CommandRunScopeKind = "command-run"
	CommandRunScopeKey  = "command-run:all-approvals"
)

// Scope identifies the canonical target a session- or command-scoped approval applies to.
type Scope struct {
	Kind      string
	Key       string
	Label     string
	Operation string
	Path      string
	Rule      string
	Prefix    bool
}

// NormalizeResolutionScope returns the canonical resolution scope. An empty
// scope is accepted as "once" for backwards compatibility.
func NormalizeResolutionScope(scope string) (string, error) {
	scope = strings.ToLower(strings.TrimSpace(scope))
	if scope == "" {
		return ScopeOnce, nil
	}
	switch scope {
	case ScopeOnce, ScopeSession:
		return scope, nil
	default:
		return "", fmt.Errorf("invalid approval scope %q", scope)
	}
}

// NewCommandRunScope builds the command-wide approval target. Its constant key
// is safe because command-scoped decisions are nested under session_id and the
// unique top-level command_id; it never becomes a session-scoped grant.
func NewCommandRunScope() Scope {
	return Scope{
		Kind:  CommandRunScopeKind,
		Key:   CommandRunScopeKey,
		Label: "all requests for this command invocation",
	}
}

func IsCommandRunScope(scope Scope) bool {
	return scope.Kind == CommandRunScopeKind && scope.Key == CommandRunScopeKey
}

// NewNetworkScope builds a canonical network scope from host and explicit port.
// Hostnames are lower-cased and trailing DNS roots are removed; IP literals are
// normalized using net.ParseIP.String().
func NewNetworkScope(host string, port int) (Scope, bool) {
	host = strings.TrimSpace(host)
	if host == "" || port <= 0 || port > 65535 {
		return Scope{}, false
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	} else {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
	}
	if host == "" {
		return Scope{}, false
	}
	label := net.JoinHostPort(host, strconv.Itoa(port))
	return Scope{Kind: "network", Key: "network:" + label, Label: label}, true
}

// NewNetworkScopeFromTarget parses a host:port target into a network scope. If
// the target does not include a port, defaultPort is used when non-zero.
func NewNetworkScopeFromTarget(target string, defaultPort int) (Scope, bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return Scope{}, false
	}
	host, portText, err := net.SplitHostPort(target)
	if err == nil {
		port, perr := strconv.Atoi(portText)
		if perr != nil {
			return Scope{}, false
		}
		return NewNetworkScope(host, port)
	}
	if defaultPort > 0 {
		return NewNetworkScope(target, defaultPort)
	}
	return Scope{}, false
}

// NewCommandScope builds the default canonical command approval scope. The
// default session target is the executable/command identity, not the full argv,
// so approving a command for the session applies to later invocations of the
// same executable under the same policy rule.
func NewCommandScope(command string, args []string, rule string) (Scope, bool) {
	return NewCommandExecutableScope(command, rule)
}

// NewCommandExecutableScope builds a canonical command approval scope for an
// executable/command identity. The key deliberately excludes argv so session
// approvals cover later invocations of the same executable, but includes the
// policy rule to avoid satisfying unrelated command approval rules.
func NewCommandExecutableScope(command string, rule string) (Scope, bool) {
	command = normalizeCommandExecutable(command)
	if command == "" {
		return Scope{}, false
	}
	rule = strings.TrimSpace(rule)
	keyMaterial := strings.Join([]string{rule, command}, "\x00")
	sum := sha256.Sum256([]byte(keyMaterial))
	return Scope{
		Kind:      "command",
		Key:       "command-executable:" + hex.EncodeToString(sum[:]),
		Label:     command,
		Operation: "exec",
		Path:      command,
		Rule:      rule,
	}, true
}

// NewCommandInvocationScope builds a canonical command approval scope for an
// exact command invocation. The key is a stable hash of command + argv so exact
// session approvals do not widen to different arguments.
func NewCommandInvocationScope(command string, args []string, rule string) (Scope, bool) {
	command = normalizeCommandExecutable(command)
	if command == "" {
		return Scope{}, false
	}
	argv := append([]string{command}, args...)
	keyMaterial := strings.Join(argv, "\x00")
	sum := sha256.Sum256([]byte(keyMaterial))
	return Scope{
		Kind:      "command",
		Key:       "command-invocation:" + hex.EncodeToString(sum[:]),
		Label:     formatCommandScopeLabel(argv),
		Operation: "exec",
		Path:      command,
		Rule:      strings.TrimSpace(rule),
	}, true
}

func normalizeCommandExecutable(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return ""
	}
	if filepath.IsAbs(command) || strings.ContainsRune(command, filepath.Separator) {
		command = filepath.Clean(command)
	}
	return command
}

func formatCommandScopeLabel(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, part := range argv {
		if part == "" || strings.ContainsAny(part, " \t\r\n\"'\\$`") {
			parts = append(parts, strconv.Quote(part))
		} else {
			parts = append(parts, part)
		}
	}
	label := strings.Join(parts, " ")
	if len(label) > 240 {
		label = label[:237] + "..."
	}
	return label
}

func scopeFromFields(fields map[string]any) (Scope, bool) {
	if fields == nil {
		return Scope{}, false
	}
	kind, _ := fields["scope_kind"].(string)
	key, _ := fields["scope_key"].(string)
	label, _ := fields["scope_label"].(string)
	operation, _ := fields["scope_operation"].(string)
	pathValue, _ := fields["scope_path"].(string)
	rule, _ := fields["scope_rule"].(string)
	prefix, _ := fields["scope_prefix"].(bool)
	kind = strings.TrimSpace(kind)
	key = strings.TrimSpace(key)
	label = strings.TrimSpace(label)
	operation = normalizeFileScopeOperation(operation)
	pathValue = strings.TrimSpace(pathValue)
	if pathValue != "" {
		pathValue = path.Clean(pathValue)
	}
	rule = strings.TrimSpace(rule)
	if kind == "" || key == "" {
		return Scope{}, false
	}
	return Scope{Kind: kind, Key: key, Label: label, Operation: operation, Path: pathValue, Rule: rule, Prefix: prefix}, true
}

// NewFileScope builds a canonical file approval scope from an already-resolved
// path. Operations are normalized into stable classes where doing so preserves
// policy semantics, to avoid repeated prompts for equivalent read-like access.
func NewFileScope(operation, filePath string) (Scope, bool) {
	return NewFileScopeWithRule(operation, filePath, "")
}

func NewFileScopeWithRule(operation, filePath, rule string) (Scope, bool) {
	operation = normalizeFileScopeOperation(operation)
	filePath = strings.TrimSpace(filePath)
	if operation == "" || filePath == "" {
		return Scope{}, false
	}
	filePath = path.Clean(filePath)
	if filePath == "." {
		return Scope{}, false
	}
	key := "file:" + operation + ":" + filePath
	return Scope{Kind: "file", Key: key, Label: operation + " " + filePath, Operation: operation, Path: filePath, Rule: strings.TrimSpace(rule)}, true
}

func NewFileDirScope(operation, dirPath, rule string) (Scope, bool) {
	operation = normalizeFileScopeOperation(operation)
	dirPath = strings.TrimSpace(dirPath)
	if operation == "" || dirPath == "" {
		return Scope{}, false
	}
	dirPath = path.Clean(dirPath)
	if dirPath == "." {
		return Scope{}, false
	}
	rule = strings.TrimSpace(rule)
	key := "file-dir:" + operation + ":" + rule + ":" + dirPath
	return Scope{Kind: "file-dir", Key: key, Label: operation + " directory first-level " + dirPath, Operation: operation, Path: dirPath, Rule: rule}, true
}

func NewFileTreeScope(operation, dirPath, rule string) (Scope, bool) {
	operation = normalizeFileScopeOperation(operation)
	dirPath = strings.TrimSpace(dirPath)
	if operation == "" || dirPath == "" {
		return Scope{}, false
	}
	dirPath = path.Clean(dirPath)
	if dirPath == "." {
		return Scope{}, false
	}
	rule = strings.TrimSpace(rule)
	key := "file-tree:" + operation + ":" + rule + ":" + dirPath
	return Scope{Kind: "file-tree", Key: key, Label: operation + " directory recursively " + dirPath, Operation: operation, Path: dirPath, Rule: rule, Prefix: true}, true
}

func normalizeFileScopeOperation(operation string) string {
	switch strings.ToLower(strings.TrimSpace(operation)) {
	case "open", "read", "stat", "list", "readlink", "access":
		return "read"
	case "write", "create", "mkdir", "delete", "rmdir", "rename", "link", "symlink", "chmod", "chown", "mknod":
		return strings.ToLower(strings.TrimSpace(operation))
	default:
		return strings.ToLower(strings.TrimSpace(operation))
	}
}

// ScopeFields returns the wire/audit fields that identify a scope. Callers may
// add kind-specific fields to the returned map.
func ScopeFields(scope Scope) map[string]any {
	return scopeFields(scope)
}

func scopeFields(scope Scope) map[string]any {
	fields := map[string]any{
		"scope_kind":  scope.Kind,
		"scope_key":   scope.Key,
		"scope_label": scope.Label,
	}
	if scope.Operation != "" {
		fields["scope_operation"] = scope.Operation
	}
	if scope.Path != "" {
		fields["scope_path"] = scope.Path
	}
	if scope.Rule != "" {
		fields["scope_rule"] = scope.Rule
	}
	if scope.Prefix {
		fields["scope_prefix"] = true
	}
	if IsCommandRunScope(scope) {
		fields["scope_lifetime"] = "command"
	}
	return fields
}

func validScope(scope Scope) bool {
	return strings.TrimSpace(scope.Kind) != "" && strings.TrimSpace(scope.Key) != ""
}
