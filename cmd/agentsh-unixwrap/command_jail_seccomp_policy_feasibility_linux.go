//go:build linux && cgo && agentsh_nested_namespace_feasibility && !agentsh_mount_broker_feasibility

package main

// commandJailBlockedSyscalls is compiled only into the NixOS feasibility
// fixture. It deliberately removes namespace/mount syscalls from the final
// filter so the VM can isolate the next cumulative boundary: Landlock. It is
// not a production capability or runtime-selectable mode. setns and all
// unrelated process/kernel-control APIs remain denied.
func commandJailSetupSyscallExempt(name string) bool {
	switch name {
	case "mount", "umount", "umount2", "prctl", "capset", "clone", "clone3", "seccomp", "close_range":
		return true
	default:
		return false
	}
}

func commandJailBlockedSyscalls() []string {
	return []string{
		"setns",
		"ptrace", "process_vm_readv", "process_vm_writev", "kcmp", "pidfd_getfd",
		"bpf", "perf_event_open", "userfaultfd",
		"add_key", "request_key", "keyctl",
	}
}
