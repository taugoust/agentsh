package api

import (
	"regexp"
	"strings"

	"github.com/agentsh/agentsh/internal/session"
)

var subagentPrivateKeyPattern = regexp.MustCompile(`-----BEGIN [^-\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\n]*PRIVATE KEY-----`)

func sanitizeSubagentArtifactFinal(value string) string {
	value = strings.TrimSpace(stripSubagentTerminalControls(value))
	value = subagentBearerPattern.ReplaceAllString(value, "Bearer [redacted]")
	value = subagentSecretPattern.ReplaceAllString(value, "$1=[redacted]")
	return subagentPrivateKeyPattern.ReplaceAllString(value, "[private key redacted]")
}

func (a *App) persistSubagentFinalArtifact(s *session.Session, result *subagentResult, protocol string, thresholdBytes int64) {
	if s == nil || result == nil || thresholdBytes <= 0 {
		return
	}
	if result.Terminal.State != subagentStateCompleted {
		return
	}
	if protocol == "pi-json" && !result.ProtocolSettled {
		return
	}
	normalizedStop := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(result.ModelStopReason, "_", ""), "-", ""))
	if normalizedStop == "tooluse" || normalizedStop == "error" || normalizedStop == "aborted" || normalizedStop == "cancelled" || normalizedStop == "canceled" {
		return
	}

	visibleFinal := sanitizeSubagentArtifactFinal(result.Final)
	totalBytes := int64(len([]byte(visibleFinal)))
	if visibleFinal == "" || totalBytes <= thresholdBytes {
		return
	}

	result.FinalTruncated = true
	result.FinalTotalBytes = totalBytes
	result.FinalInlineBytes = thresholdBytes
	artifact, err := s.WriteOutputArtifact("subagent-"+result.Label+".md", strings.NewReader(visibleFinal))
	if err != nil {
		complete := false
		result.ArtifactComplete = &complete
		result.ArtifactError = sanitizeSubagentDiagnostic(err.Error())
		return
	}
	result.FullResultPath = artifact.Path
	result.ArtifactBytes = artifact.BytesWritten
	complete := artifact.BytesWritten == totalBytes
	result.ArtifactComplete = &complete
}
