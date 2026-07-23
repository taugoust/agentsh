//go:build linux && cgo

package api

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/composition"
	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

func (a *App) configureExecveComposition(handler any, s *session.Session, wrapperCfg seccompWrapperConfig, setupConnection *os.File, wrapperPID int) error {
	if wrapperCfg.SandboxComposition == "" {
		return nil
	}
	if s == nil || wrapperCfg.SandboxComposition != bubblewrapCompositionMode {
		return fmt.Errorf("unsupported selected composition mode %q", wrapperCfg.SandboxComposition)
	}
	h, ok := handler.(*unixmon.ExecveHandler)
	if !ok || h == nil {
		return fmt.Errorf("E_COMPOSITION_BACKEND_UNAVAILABLE: exec interception handler is unavailable")
	}
	if !wrapperCfg.LandlockEnabled {
		return fmt.Errorf("E_COMPOSITION_BACKEND_UNAVAILABLE: Landlock is not active")
	}
	if !wrapperCfg.FileMonitorEnabled || !wrapperCfg.InterceptMetadata || wrapperCfg.WriteOnlyOpens || !wrapperCfg.BlockIOUring {
		return fmt.Errorf("E_COMPOSITION_BACKEND_UNAVAILABLE: enforced source-aware read/write and metadata file interception is not active")
	}
	if wrapperPID <= 0 {
		return fmt.Errorf("E_COMPOSITION_REQUESTER_CHANGED: trusted wrapper PID is invalid")
	}
	if setupConnection == nil {
		return fmt.Errorf("E_COMPOSITION_BACKEND_UNAVAILABLE: trusted composition setup channel is unavailable")
	}
	ceiling := a.cfg.Sandbox.Composition.Bubblewrap
	adapterPath, err := resolveCompositionExecutable(ceiling.AdapterPath, "agentsh-bwrap-adapter")
	if err != nil {
		return err
	}
	helperPath, err := resolveCompositionExecutable(ceiling.MountHelperPath, "agentsh-composition-mount-helper")
	if err != nil {
		return err
	}
	wrapperPath, err := resolveCompositionExecutable(a.cfg.Sandbox.UnixSockets.WrapperBin, "agentsh-unixwrap")
	if err != nil {
		return err
	}
	wrapperPath = compositionProcessExecutablePath(wrapperPath)
	scratch := ceiling.ScratchRoot
	if scratch == "" || !filepath.IsAbs(scratch) || filepath.Clean(scratch) != scratch {
		return fmt.Errorf("E_COMPOSITION_BACKEND_UNAVAILABLE: trusted composition scratch root is unavailable")
	}
	pathRegistry := unixmon.NewCompositionPathRegistry()
	broker, err := composition.NewBroker(composition.BrokerConfig{
		HelperPath:            helperPath,
		AdapterPath:           adapterPath,
		ScratchRoot:           scratch,
		ReadRoots:             concreteCompositionRoots(wrapperCfg.CompositionAllowRead, wrapperCfg.Workspace),
		ListRoots:             concreteCompositionRoots(wrapperCfg.CompositionAllowList, ""),
		WriteRoots:            concreteCompositionRoots(wrapperCfg.CompositionAllowWrite, wrapperCfg.Workspace),
		ExecuteRoots:          concreteCompositionRoots(wrapperCfg.CompositionAllowExecute, wrapperCfg.Workspace),
		DenyRoots:             concreteCompositionRoots(wrapperCfg.DenyPaths, ""),
		MaxPlanOperations:     ceiling.MaxPlanOperations,
		MaxDataBytes:          ceiling.MaxDataBytes,
		RequestTimeout:        30 * time.Second,
		SetupConnection:       setupConnection,
		SetupSenderPID:        wrapperPID,
		SetupSenderExecutable: wrapperPath,
		SetupSyntheticRoots:   ceiling.MaxNamespaceTransitions,
		SetupSyntheticRW:      ceiling.MaxSyntheticMounts,
		DeviceIOCTLRoots:      ceiling.DeviceIOCTLPaths,
		PublishNormalizedPlan: func(parentPID, targetPID int, snapshot composition.NormalizedPlanSnapshot) {
			event := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Now().UTC(),
				Type:      "composition_plan",
				SessionID: s.ID,
				CommandID: s.CurrentCommandID(),
				Operation: "normalized_bubblewrap_plan",
				Fields: map[string]any{
					"parent_pid":      parentPID,
					"target_pid":      targetPID,
					"normalized_plan": snapshot,
				},
			}
			s.InjectTraceContext(event.Fields)
			_ = a.store.AppendEvent(context.Background(), event)
			a.broker.Publish(event)
		},
		PublishPathMappings: pathRegistry.Register,
	})
	if err != nil {
		_ = pathRegistry.Close()
		return fmt.Errorf("E_COMPOSITION_BACKEND_UNAVAILABLE: initialize broker: %w", err)
	}
	redirector, err := unixmon.NewManagedCompositionRedirector(
		adapterPath,
		broker.ServeOne,
		ceiling.MaxNamespaceTransitions,
		ceiling.MaxNamespaceDepth,
		func() error {
			return errors.Join(broker.Close(), pathRegistry.Close())
		},
	)
	if err != nil {
		_ = broker.Close()
		_ = pathRegistry.Close()
		return fmt.Errorf("E_COMPOSITION_BACKEND_UNAVAILABLE: initialize adapter redirect: %w", err)
	}
	h.SetComposition(bubblewrapCompositionMode, adapterPath, redirector)
	h.SetCompositionPathRegistry(pathRegistry)
	return nil
}

func resolveCompositionExecutable(configured, name string) (string, error) {
	path := strings.TrimSpace(configured)
	if path == "" {
		path = name
	}
	if !filepath.IsAbs(path) {
		resolved, err := exec.LookPath(path)
		if err != nil {
			return "", fmt.Errorf("E_COMPOSITION_BACKEND_UNAVAILABLE: %s not found: %w", path, err)
		}
		path = resolved
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", name, err)
	}
	return absolute, nil
}

// Nix's makeWrapper replaces an installed executable with a shell launcher and
// moves the real process image to .NAME-wrapped. Setup authentication compares
// /proc/PID/exe inode identity, so bind it to that real image when present.
func compositionProcessExecutablePath(path string) string {
	path = filepath.Clean(path)
	hidden := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"-wrapped")
	if info, err := os.Stat(hidden); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
		return hidden
	}
	return path
}

func concreteCompositionRoots(paths []string, workspace string) []string {
	out := make([]string, 0, len(paths)+1)
	if workspace != "" {
		out = append(out, workspace)
	}
	for _, path := range paths {
		if index := strings.IndexAny(path, "*?["); index >= 0 {
			path = strings.TrimSuffix(path[:index], string(filepath.Separator))
			if path == "" {
				path = string(filepath.Separator)
			}
		}
		if filepath.IsAbs(path) {
			out = append(out, filepath.Clean(path))
		}
	}
	return out
}
