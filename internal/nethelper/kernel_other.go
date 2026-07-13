//go:build !linux

package nethelper

// KernelBackendOptions controls the Linux helper backend. It is accepted on
// non-Linux so callers can compile cross-platform; operations fail closed.
type KernelBackendOptions struct {
	PinRoot               string
	TrustBoundaryComplete bool
	PinOwnerUID           uint32
	TargetUID             uint32
	EnforceTargetUID      bool
}

// DefaultBPFFSPinRoot is empty off Linux because bpffs/cgroup eBPF is unavailable.
func DefaultBPFFSPinRoot() string { return "" }

// KernelBackend is unavailable off Linux. Use FailClosedBackend semantics.
type KernelBackend struct{ FailClosedBackend }

func NewKernelBackend() *KernelBackend { return &KernelBackend{} }

func NewKernelBackendWithOptions(KernelBackendOptions) *KernelBackend { return &KernelBackend{} }

func CleanupPinnedResources(PinCleanupOptions) (PinCleanupResult, error) {
	return PinCleanupResult{Warnings: []string{"bpffs pin cleanup is only available on Linux"}}, nil
}
