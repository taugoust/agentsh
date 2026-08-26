//go:build !windows

package externalrunner

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/guestcontrol"
)

func productionHostMonitorDeps() hostMonitorDeps {
	return hostMonitorDeps{
		newControl: func(manifest guestcontrol.Manifest) (hostMonitorControl, error) {
			return guestcontrol.NewVSockClient(manifest)
		},
		newRelay: func(path string, control hostMonitorControl) (hostMonitorRelay, error) {
			client, ok := control.(*guestcontrol.Client)
			if !ok {
				return nil, fmt.Errorf("host monitor guest client type is invalid")
			}
			return guestcontrol.ListenHostRelay(path, client)
		},
		createVolume: CreateWorkspaceVolume,
		startRunner:  startHostRunner,
		validateRunner: func(profile Profile) error {
			store := filepath.Join(string(filepath.Separator), "nix", "store") + string(filepath.Separator)
			if !strings.HasPrefix(profile.Runner.Path, store) {
				return fmt.Errorf("host monitor runner must be an immutable Nix store executable")
			}
			return profile.VerifyRunner()
		},
		lock: acquireHostMonitorLock,
		now:  func() time.Time { return time.Now().UTC() },
	}
}
