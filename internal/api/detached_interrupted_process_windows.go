//go:build windows

package api

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/detached"
)

func terminateDetachedInterruptedProcesses(commands []detached.InflightCommand) error {
	for _, command := range commands {
		if command.ExternalProcess {
			return fmt.Errorf("interrupted external command %s cannot be proven terminated on Windows", command.CommandID)
		}
	}
	return nil
}
