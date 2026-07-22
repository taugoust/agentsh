package api

import (
	"fmt"
	"runtime"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

const bubblewrapCompositionMode = "bubblewrap-0.11.2"

// selectSandboxComposition intersects policy intent with the operator host
// ceiling without mutating session-global state. Client-spawned wrap setup is
// asynchronous, so its exact selection must remain a request-local snapshot:
// two concurrent wrap-init requests must not lend composition authority to one
// another through Session.currentSandboxComposition.
func (a *App) selectSandboxComposition(dec *policy.Decision) (string, string) {
	if dec == nil || dec.SandboxComposition == "" || dec.EffectiveDecision == types.DecisionDeny {
		return "", ""
	}
	deny := func(code, message string) (string, string) {
		dec.EffectiveDecision = types.DecisionDeny
		dec.Message = message
		if dec.Rule == "" {
			dec.Rule = "sandbox-composition"
		}
		return "", code
	}
	if dec.SandboxComposition != bubblewrapCompositionMode {
		return deny("E_COMPOSITION_DIALECT_MISMATCH", fmt.Sprintf("unsupported sandbox composition %q", dec.SandboxComposition))
	}
	if runtime.GOOS != "linux" {
		return deny("E_COMPOSITION_BACKEND_UNAVAILABLE", "Bubblewrap composition is available only on Linux")
	}
	if a == nil || a.cfg == nil || !a.cfg.Sandbox.Composition.Bubblewrap.Enabled {
		return deny("E_COMPOSITION_HOST_DISABLED", "Bubblewrap composition was selected by policy but is disabled by the host ceiling")
	}
	if a.cfg.Sandbox.Composition.Bubblewrap.Dialect != "0.11.2" {
		return deny("E_COMPOSITION_DIALECT_MISMATCH", "host Bubblewrap composition dialect does not match policy")
	}
	if !a.cfg.Landlock.Enabled || !a.cfg.Sandbox.Seccomp.Execve.Enabled || !commandJailRequired(a.cfg) {
		return deny("E_COMPOSITION_BACKEND_UNAVAILABLE", "Bubblewrap composition requires Landlock, exec interception, and the strict command jail")
	}
	fileMonitor := a.cfg.Sandbox.Seccomp.FileMonitor
	if !config.FileMonitorBoolWithDefault(fileMonitor.Enabled, false) ||
		!config.FileMonitorBoolWithDefault(fileMonitor.EnforceWithoutFUSE, false) ||
		!config.FileMonitorBoolWithDefault(fileMonitor.InterceptMetadata, false) ||
		config.FileMonitorBoolWithDefault(fileMonitor.WriteOnlyOpens, !config.FileMonitorBoolWithDefault(fileMonitor.InterceptMetadata, false)) ||
		!config.FileMonitorBoolWithDefault(fileMonitor.BlockIOUring, config.FileMonitorBoolWithDefault(fileMonitor.EnforceWithoutFUSE, false)) {
		return deny("E_COMPOSITION_BACKEND_UNAVAILABLE", "Bubblewrap composition requires enforced read/write and metadata file interception plus io_uring denial for source attribution")
	}
	return bubblewrapCompositionMode, ""
}

// applySandboxCompositionSelection records a selection only for execution
// paths that already hold the session execution admission lock. The wrap-init
// path uses selectSandboxComposition directly and binds the returned mode into
// its serialized wrapper configuration instead.
func (a *App) applySandboxCompositionSelection(s *session.Session, dec *policy.Decision) string {
	mode, code := a.selectSandboxComposition(dec)
	if s != nil {
		s.SetCurrentSandboxComposition(mode)
	}
	return code
}
