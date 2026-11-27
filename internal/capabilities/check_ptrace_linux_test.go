//go:build linux

package capabilities

import "testing"

func TestProbePtraceAttach(t *testing.T) {
	result := probePtraceAttach()
	t.Logf("probePtraceAttach() = %v", result)
}

func TestCheckPtraceCapability(t *testing.T) {
	result := checkPtraceCapability()
	t.Logf("checkPtraceCapability() = %v", result)
}
