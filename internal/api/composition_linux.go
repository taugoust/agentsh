//go:build linux && cgo

package api

import (
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
		PublishPathMappings:   pathRegistry.Register,
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
