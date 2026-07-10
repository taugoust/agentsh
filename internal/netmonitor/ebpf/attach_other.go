//go:build !linux

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// CgroupAttachOptions mirrors the Linux API so cross-platform callers can
// compile while the operation itself remains unsupported.
type CgroupAttachOptions struct {
	PinPath                string
	FailClosedBeforeAttach bool
}

// CgroupAttachment mirrors the Linux attachment owner.
type CgroupAttachment struct {
	Collection *ebpf.Collection
	CgroupID   uint64
}

// AttachConnectToCgroup is not supported on non-Linux platforms.
func AttachConnectToCgroup(_ string) (*ebpf.Collection, func() error, error) {
	return nil, nil, fmt.Errorf("ebpf attach not supported on this platform")
}

// AttachConnectToCgroupWithOptions is not supported on non-Linux platforms.
func AttachConnectToCgroupWithOptions(_ string, _ CgroupAttachOptions) (*CgroupAttachment, error) {
	return nil, fmt.Errorf("ebpf attach not supported on this platform")
}

func (a *CgroupAttachment) Close() error {
	if a != nil && a.Collection != nil {
		a.Collection.Close()
		a.Collection = nil
	}
	if a != nil {
		a.CgroupID = 0
	}
	return nil
}
