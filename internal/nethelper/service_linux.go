//go:build linux

package nethelper

import (
	"fmt"
	"os"
)

// ValidatePrivilegedServiceUser enforces the supported helper topology: the
// fixed BPF backend runs as root, outside the same-UID tool boundary.
func ValidatePrivilegedServiceUser() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("nethelper serve must run as root under a supported systemd service")
	}
	return nil
}
