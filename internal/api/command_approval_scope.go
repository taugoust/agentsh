package api

import "github.com/agentsh/agentsh/internal/approvals"

func commandApprovalScopeOptions(command string, args []string, rule string) (approvals.Scope, bool, []map[string]any) {
	executable, ok := approvals.NewCommandExecutableScope(command, rule)
	if !ok {
		return approvals.Scope{}, false, nil
	}

	options := []map[string]any{approvals.ScopeFields(executable)}
	seen := map[string]bool{executable.Key: true}
	if invocation, invocationOK := approvals.NewCommandInvocationScope(command, args, rule); invocationOK && !seen[invocation.Key] {
		options = append(options, approvals.ScopeFields(invocation))
	}

	return executable, true, options
}
