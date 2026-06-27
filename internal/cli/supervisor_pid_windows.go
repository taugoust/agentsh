//go:build windows

package cli

func supervisorPIDAlive(pid int) bool {
	// os.FindProcess does not reliably validate liveness on Windows. Keep
	// discovery conservative there and let the socket connection report staleness.
	return pid > 0
}
