package approvals

import (
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"
)

const (
	ScopeOnce    = "once"
	ScopeSession = "session"
)

// Scope identifies the canonical target a session-scoped approval applies to.
type Scope struct {
	Kind  string
	Key   string
	Label string
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

func scopeFromFields(fields map[string]any) (Scope, bool) {
	if fields == nil {
		return Scope{}, false
	}
	kind, _ := fields["scope_kind"].(string)
	key, _ := fields["scope_key"].(string)
	label, _ := fields["scope_label"].(string)
	kind = strings.TrimSpace(kind)
	key = strings.TrimSpace(key)
	label = strings.TrimSpace(label)
	if kind == "" || key == "" {
		return Scope{}, false
	}
	return Scope{Kind: kind, Key: key, Label: label}, true
}

// NewFileScope builds a canonical file approval scope from an already-resolved
// path. Operations are normalized into stable classes where doing so preserves
// policy semantics, to avoid repeated prompts for equivalent read-like access.
func NewFileScope(operation, filePath string) (Scope, bool) {
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
	return Scope{Kind: "file", Key: key, Label: operation + " " + filePath}, true
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
	return map[string]any{
		"scope_kind":  scope.Kind,
		"scope_key":   scope.Key,
		"scope_label": scope.Label,
	}
}

func validScope(scope Scope) bool {
	return strings.TrimSpace(scope.Kind) != "" && strings.TrimSpace(scope.Key) != ""
}
