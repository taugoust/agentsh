//go:build !windows

package api

import (
	"os"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/detached"
)

func TestInterruptedProcessTerminationRequiresUnreusedIdentity(t *testing.T) {
	pid := os.Getpid()
	for _, tc := range []struct {
		name          string
		startIdentity string
		bootID        string
		want          string
	}{
		{name: "missing identity", want: "lacks a verifiable process identity"},
		{name: "reused identity", startIdentity: "not-this-process", bootID: "not-this-boot", want: "process identity was reused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := terminateDetachedInterruptedProcesses([]detached.InflightCommand{{
				CommandID: "cmd-untrusted-pid", ExternalProcess: true,
				PID: pid, ProcessGroupID: pid,
				ProcessStartIdentity: tc.startIdentity, BootID: tc.bootID,
			}})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("termination error=%v, want %q", err, tc.want)
			}
		})
	}
}
