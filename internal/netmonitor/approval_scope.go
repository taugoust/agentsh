package netmonitor

import "github.com/agentsh/agentsh/internal/approvals"

func approvalScopeFor(kind string, target string) (approvals.Scope, bool) {
	switch kind {
	case "network":
		return approvals.NewNetworkScopeFromTarget(target, 0)
	case "dns":
		return approvals.NewNetworkScopeFromTarget(target, 53)
	default:
		return approvals.Scope{}, false
	}
}

func requestFieldsForScope(scope approvals.Scope) map[string]any {
	return map[string]any{
		"scope_kind":  scope.Kind,
		"scope_key":   scope.Key,
		"scope_label": scope.Label,
	}
}
