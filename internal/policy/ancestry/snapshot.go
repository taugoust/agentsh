package ancestry

// ValidationResult describes the outcome of snapshot validation.
type ValidationResult int

const (
	// ValidationValid means the snapshot is confirmed valid.
	ValidationValid ValidationResult = iota
	// ValidationMissing means the snapshot was nil (missing parent).
	ValidationMissing
	// ValidationPIDMismatch means the PID was reused by a different process.
	ValidationPIDMismatch
	// ValidationError means an error occurred during validation.
	ValidationError
)

// CaptureSnapshot captures current process info for the given PID.
// This is implemented per-platform in snapshot_*.go files.
//
// StartTime comes from the jiffies field in /proc/PID/stat.
func CaptureSnapshot(pid int) (*ProcessSnapshot, error) {
	return captureSnapshotImpl(pid)
}

// ValidateSnapshot checks if a PID still refers to the same process
// by comparing start times. Returns true if valid or if validation
// cannot be performed (e.g., process exited).
//
// Note: This validation relies on StartTime accuracy. See the RacePolicy
// configuration for handling validation failures appropriately.
func ValidateSnapshot(pid int, snapshot *ProcessSnapshot) bool {
	if snapshot == nil {
		return false
	}

	current, err := CaptureSnapshot(pid)
	if err != nil {
		// Process doesn't exist anymore - that's fine,
		// we still have the cached snapshot data
		return true
	}

	// Compare start times - if they match, it's the same process
	return current.StartTime == snapshot.StartTime
}

// ValidateSnapshotDetailed checks if a PID still refers to the same process
// and returns a detailed result indicating what type of validation failure occurred.
func ValidateSnapshotDetailed(pid int, snapshot *ProcessSnapshot) ValidationResult {
	if snapshot == nil {
		return ValidationMissing
	}

	current, err := CaptureSnapshot(pid)
	if err != nil {
		// Process doesn't exist anymore - that's fine,
		// we still have the cached snapshot data
		return ValidationValid
	}

	// Compare start times - if they match, it's the same process
	if current.StartTime == snapshot.StartTime {
		return ValidationValid
	}

	// Start times don't match - PID was reused
	return ValidationPIDMismatch
}
