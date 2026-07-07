package api

import (
	"context"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

func (a *App) applyCommandApproval(ctx context.Context, sessionID, cmdID string, command string, args []string, actor map[string]any, pre *policy.Decision) error {
	if pre == nil || pre.PolicyDecision != types.DecisionApprove || pre.EffectiveDecision != types.DecisionApprove || a.approvals == nil {
		return nil
	}

	fields := map[string]any{
		"command": command,
		"args":    args,
	}
	if actor != nil {
		fields["actor"] = actor
	}

	if scope, ok := approvals.NewCommandScope(command, args, pre.Rule); ok {
		if cached, ok := a.approvals.CheckScoped(ctx, sessionID, cmdID, scope); ok {
			if cached.Approved {
				pre.EffectiveDecision = types.DecisionAllow
			} else {
				pre.EffectiveDecision = types.DecisionDeny
			}
			return nil
		}
		for k, v := range approvals.ScopeFields(scope) {
			fields[k] = v
		}
	}

	apr := approvals.Request{
		ID:        "approval-" + uuid.NewString(),
		SessionID: sessionID,
		CommandID: cmdID,
		Kind:      "command",
		Target:    command,
		Rule:      pre.Rule,
		Message:   pre.Message,
		Fields:    fields,
	}
	res, err := a.approvals.RequestApproval(ctx, apr)
	if pre.Approval != nil {
		pre.Approval.ID = apr.ID
	}
	if err != nil || !res.Approved {
		pre.EffectiveDecision = types.DecisionDeny
	} else {
		pre.EffectiveDecision = types.DecisionAllow
	}
	return err
}
