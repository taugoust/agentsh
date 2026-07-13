package api

import "strings"

type subagentProtocolOutcome struct {
	Final        string
	Completed    bool
	FailureKind  subagentFailureKind
	StopReason   string
	ErrorMessage string
}

func (outcome subagentProtocolOutcome) Failed() bool {
	return outcome.FailureKind != ""
}

func parseSubagentProtocolOutcome(protocol, stdout string) subagentProtocolOutcome {
	switch protocol {
	case "pi-json":
		return parsePiSubagentProtocol(stdout)
	case "text":
		return subagentProtocolOutcome{Final: strings.TrimSpace(stdout), Completed: true}
	default:
		return subagentProtocolOutcome{
			FailureKind:  subagentFailureConfiguration,
			ErrorMessage: "unsupported subagent output protocol",
		}
	}
}

func parseSubagentFinal(protocol, stdout string) string {
	return parseSubagentProtocolOutcome(protocol, stdout).Final
}
