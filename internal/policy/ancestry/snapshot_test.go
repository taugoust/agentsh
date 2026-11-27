package ancestry

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCaptureSnapshot_CurrentProcess(t *testing.T) {
	pid := os.Getpid()
	snapshot, err := CaptureSnapshot(pid)

	require.NoError(t, err)
	require.NotNil(t, snapshot)

	// Comm should be set (the test binary name)
	assert.NotEmpty(t, snapshot.Comm)

	// StartTime should be non-zero
	assert.NotZero(t, snapshot.StartTime)

	t.Logf("Snapshot of current process (PID %d): Comm=%s, ExePath=%s, StartTime=%d",
		pid, snapshot.Comm, snapshot.ExePath, snapshot.StartTime)
}

func TestCaptureSnapshot_NonExistentProcess(t *testing.T) {
	// Use a very high PID that's unlikely to exist
	pid := 999999999
	_, err := CaptureSnapshot(pid)

	// Should return an error
	assert.Error(t, err)
}

func TestCaptureSnapshot_Consistency(t *testing.T) {
	pid := os.Getpid()

	// Capture two snapshots of the same process
	snapshot1, err := CaptureSnapshot(pid)
	require.NoError(t, err)

	snapshot2, err := CaptureSnapshot(pid)
	require.NoError(t, err)

	// StartTime should be the same (process hasn't restarted)
	assert.Equal(t, snapshot1.StartTime, snapshot2.StartTime)

	// Comm should be the same
	assert.Equal(t, snapshot1.Comm, snapshot2.Comm)
}
