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
		final := strings.TrimSpace(stripSubagentTerminalControls(stdout))
		if final == "" {
			return subagentProtocolOutcome{
				FailureKind:  subagentFailureProtocol,
				ErrorMessage: "child output contained no visible result",
			}
		}
		return subagentProtocolOutcome{Final: final, Completed: true}
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

func stripSubagentTerminalControls(value string) string {
	var visible strings.Builder
	visible.Grow(len(value))
	for i := 0; i < len(value); {
		if value[i] == 0x1b {
			i = skipSubagentEscapeSequence(value, i)
			continue
		}
		if (value[i] < 0x20 && value[i] != '\n' && value[i] != '\r' && value[i] != '\t') || value[i] == 0x7f {
			i++
			continue
		}
		visible.WriteByte(value[i])
		i++
	}
	return visible.String()
}

func skipSubagentEscapeSequence(value string, start int) int {
	if start+1 >= len(value) {
		return len(value)
	}
	switch value[start+1] {
	case '[':
		for i := start + 2; i < len(value); i++ {
			if value[i] >= 0x40 && value[i] <= 0x7e {
				return i + 1
			}
		}
		return len(value)
	case ']':
		for i := start + 2; i < len(value); i++ {
			if value[i] == 0x07 {
				return i + 1
			}
			if value[i] == 0x1b && i+1 < len(value) && value[i+1] == '\\' {
				return i + 2
			}
		}
		return len(value)
	case 'P', 'X', '^', '_':
		for i := start + 2; i+1 < len(value); i++ {
			if value[i] == 0x1b && value[i+1] == '\\' {
				return i + 2
			}
		}
		return len(value)
	default:
		return start + 2
	}
}
