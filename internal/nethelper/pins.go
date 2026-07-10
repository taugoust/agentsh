package nethelper

// PinCleanupOptions selects helper-owned bpffs pins to remove. It is used by
// privileged recovery tooling after helper/supervisor crashes. It does not load
// or accept BPF fds from clients.
type PinCleanupOptions struct {
	PinRoot   string
	SessionID string
	DryRun    bool
	// TargetUID limits cleanup to one helper instance UID when EnforceTargetUID
	// is true.
	TargetUID        uint32
	EnforceTargetUID bool
	// OwnerUID is the required owner of validated pins (root in production).
	OwnerUID uint32
	// Force permits explicit removal of active or malformed pin trees. Without
	// it, cleanup removes only validated, gone/unpopulated command cgroups.
	Force bool
}

// PinCleanupResult reports bpffs pins/directories that were removed or would be
// removed in dry-run mode.
type PinCleanupResult struct {
	Removed  []string `json:"removed,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}
