//go:build linux && cgo && agentsh_mount_broker_feasibility && !agentsh_nested_namespace_feasibility

package main

// Keep mount in the first, notify-capable filter. The VM broker continues the
// trusted PID-1 setup mounts before READY and emulates payload mounts after GO.
func commandJailSetupSyscallExempt(name string) bool {
	switch name {
	case "umount", "umount2", "prctl", "capset", "clone", "clone3", "seccomp", "close_range":
		return true
	default:
		return false
	}
}

// The broker fixture handles mount(2) through the first user-notify filter, so
// the final filter must not replace that notification with EPERM. All other
// production topology and kernel-control denials remain in force.
func commandJailBlockedSyscalls() []string {
	return []string{
		"umount2", "pivot_root", "setns", "unshare",
		"open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr",
		"ptrace", "process_vm_readv", "process_vm_writev", "kcmp", "pidfd_getfd",
		"bpf", "perf_event_open", "userfaultfd",
		"add_key", "request_key", "keyctl",
	}
}
