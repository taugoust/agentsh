//go:build linux && cgo && !agentsh_nested_namespace_feasibility && !agentsh_mount_broker_feasibility

package main

// commandJailBlockedSyscalls is the production immutable-mount contract. The
// mount view is complete before this filter is loaded. clone/clone3 remain
// available for ordinary process/thread creation; every descendant inherits
// this filter and the already-masked view.
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
		"mount", "umount2", "pivot_root", "setns", "unshare",
		"open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr",
		"ptrace", "process_vm_readv", "process_vm_writev", "kcmp", "pidfd_getfd",
		"bpf", "perf_event_open", "userfaultfd",
		"add_key", "request_key", "keyctl",
	}
}
