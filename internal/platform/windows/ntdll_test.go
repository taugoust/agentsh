package windows

import (
	"runtime"
	"testing"
)

func TestResumeProcessByPIDSignature(t *testing.T) {
	if runtime.GOOS != "windows" {
		err := ResumeProcessByPID(0)
		if err == nil {
			t.Error("expected error on non-Windows")
		}
	}
}

func TestSuspendProcessByPIDSignature(t *testing.T) {
	if runtime.GOOS != "windows" {
		err := SuspendProcessByPID(0)
		if err == nil {
			t.Error("expected error on non-Windows")
		}
	}
}

func TestTerminateProcessByPIDSignature(t *testing.T) {
	if runtime.GOOS != "windows" {
		err := TerminateProcessByPID(0, 1)
		if err == nil {
			t.Error("expected error on non-Windows")
		}
	}
}

func TestCreateProcessAsChildSignature(t *testing.T) {
	if runtime.GOOS != "windows" {
		_, err := CreateProcessAsChild(0, "", "test.exe", nil, "", false, nil)
		if err == nil {
			t.Error("expected error on non-Windows")
		}
	}
}

func TestProcThreadAttributeParentProcess(t *testing.T) {
	if PROC_THREAD_ATTRIBUTE_PARENT_PROCESS != 0x00020000 {
		t.Errorf("PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: expected 0x00020000, got 0x%X", PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)
	}
}
