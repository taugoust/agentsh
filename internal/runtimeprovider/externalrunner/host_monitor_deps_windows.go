//go:build windows

package externalrunner

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/agentsh/agentsh/internal/guestcontrol"
)

func productionHostMonitorDeps() hostMonitorDeps {
	unsupported := func() error { return fmt.Errorf("external MicroVM host monitors are supported only on Linux") }
	return hostMonitorDeps{
		newControl: func(guestcontrol.Manifest) (hostMonitorControl, error) { return nil, unsupported() },
		newRelay:   func(string, hostMonitorControl) (hostMonitorRelay, error) { return nil, unsupported() },
		createVolume: func(context.Context, WorkspaceVolumeRequest, string) (*WorkspaceVolume, error) {
			return nil, unsupported()
		},
		startRunner: func(Profile, HostMonitorLayout, uint32, *WorkspaceVolume, io.Writer) (hostRunner, error) {
			return nil, unsupported()
		},
		validateRunner: func(Profile) error { return unsupported() },
		lock:           func(context.Context, string) (io.Closer, error) { return nil, unsupported() },
		now:            func() time.Time { return time.Now().UTC() },
	}
}
