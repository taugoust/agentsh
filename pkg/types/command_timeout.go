package types

// CommandTimeoutSource explains how an ordinary command's effective timeout
// was selected.
type CommandTimeoutSource string

const (
	CommandTimeoutSourcePolicyDefault CommandTimeoutSource = "policy_default"
	CommandTimeoutSourceExplicit      CommandTimeoutSource = "explicit_request"
	CommandTimeoutSourcePolicyCap     CommandTimeoutSource = "policy_cap"
	CommandTimeoutSourceFallback      CommandTimeoutSource = "fallback"
)

// CommandTimeout describes the timeout applied to one ordinary command.
// RequestedMS is present only when the caller supplied a timeout.
// ApprovalExtensionMS is the maximum cumulative approval-wait allowance; all
// approval requests for the command share this single allowance.
type CommandTimeout struct {
	RequestedMS         *int64               `json:"requested_ms,omitempty"`
	EffectiveMS         int64                `json:"effective_ms"`
	ApprovalExtensionMS int64                `json:"approval_extension_ms,omitempty"`
	Source              CommandTimeoutSource `json:"source"`
}

// SessionCommandTimeoutSource explains where a session's ordinary-command
// default and optional maximum came from.
type SessionCommandTimeoutSource string

const (
	SessionCommandTimeoutSourcePolicy   SessionCommandTimeoutSource = "policy"
	SessionCommandTimeoutSourceFallback SessionCommandTimeoutSource = "fallback"
)

// SessionCommandTimeout is the pre-command timeout contract exposed by a
// session snapshot. A nil MaximumMS means callers may explicitly request a
// timeout longer than DefaultMS. ApprovalExtensionMS is a single cumulative
// allowance, not an amount that can accumulate across approval requests.
type SessionCommandTimeout struct {
	DefaultMS           int64                       `json:"default_ms"`
	MaximumMS           *int64                      `json:"maximum_ms,omitempty"`
	ApprovalExtensionMS int64                       `json:"approval_extension_ms,omitempty"`
	Source              SessionCommandTimeoutSource `json:"source"`
}

const (
	TerminationReasonCommandTimeout  = "command_timeout"
	TerminationReasonCallerCancelled = "caller_cancelled"
	TerminationReasonCallerDeadline  = "caller_deadline"
)
