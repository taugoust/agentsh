//go:build windows

package api

func detachedSupervisorPIDAlive(pid int) bool {
	// os.FindProcess does not reliably validate liveness on Windows. Keep
	// discovery conservative there and let socket requests report staleness.
	return pid > 0
}
