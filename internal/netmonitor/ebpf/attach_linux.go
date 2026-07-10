//go:build linux

package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var fixedConnectProgramRoles = map[string]ebpf.AttachType{
	"handle_connect4": ebpf.AttachCGroupInet4Connect,
	"handle_connect6": ebpf.AttachCGroupInet6Connect,
	"handle_sendmsg4": ebpf.AttachCGroupUDP4Sendmsg,
	"handle_sendmsg6": ebpf.AttachCGroupUDP6Sendmsg,
}

var fixedConnectMapRoles = map[string]struct{}{
	"events":       {},
	"allowlist":    {},
	"denylist":     {},
	"default_deny": {},
	"lpm4_allow":   {},
	"lpm6_allow":   {},
	"lpm4_deny":    {},
	"lpm6_deny":    {},
}

// CgroupAttachOptions controls how AgentSH's built-in cgroup connect programs
// are attached. It intentionally has no fields for caller-supplied bytecode,
// object paths, or fds: AttachConnectToCgroupWithOptions always loads the
// embedded AgentSH connect object via LoadConnectProgram.
type CgroupAttachOptions struct {
	// PinPath, when non-empty, is a bpffs directory where helper-owned maps and
	// bpf_links are pinned. The caller is responsible for constraining this path
	// to an AgentSH-owned bpffs subtree before passing it here.
	PinPath string

	// FailClosedBeforeAttach initializes the target cgroup's policy state to
	// deny-all before the first link is attached.
	FailClosedBeforeAttach bool
}

// CgroupAttachment owns one loaded AgentSH connect collection and the fixed
// bpf_links attached to a cgroup.
type CgroupAttachment struct {
	Collection  *ebpf.Collection
	Links       []link.Link
	PinnedPaths []string
	CgroupID    uint64
}

// AttachConnectToCgroup loads the fixed programs and attaches them to cgroupPath.
func AttachConnectToCgroup(cgroupPath string) (*ebpf.Collection, func() error, error) {
	att, err := AttachConnectToCgroupWithOptions(cgroupPath, CgroupAttachOptions{})
	if err != nil {
		return nil, nil, err
	}
	return att.Collection, att.Close, nil
}

// AttachConnectToCgroupWithOptions loads AgentSH's embedded connect/sendmsg
// programs, initializes policy when requested, attaches exactly four fixed
// roles, and optionally pins helper-owned maps/links. It never accepts an
// untrusted object, program, map, link, byte slice, path to bytecode, or fd.
func AttachConnectToCgroupWithOptions(cgroupPath string, opts CgroupAttachOptions) (*CgroupAttachment, error) {
	coll, err := LoadConnectProgram()
	if err != nil {
		return nil, err
	}
	if err := validateFixedConnectCollection(coll); err != nil {
		coll.Close()
		return nil, err
	}
	cgroupID, err := CgroupID(cgroupPath)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("resolve cgroup id before attach: %w", err)
	}

	att := &CgroupAttachment{Collection: coll, CgroupID: cgroupID}
	cleanupOnError := func() {
		_ = att.Close()
	}

	if opts.FailClosedBeforeAttach {
		if err := LockPolicy(coll, cgroupID); err != nil {
			cleanupOnError()
			return nil, fmt.Errorf("initialize fail-closed policy before attach: %w", err)
		}
	}

	pinPath := strings.TrimSpace(opts.PinPath)
	if pinPath != "" {
		if err := att.pinMaps(pinPath); err != nil {
			cleanupOnError()
			return nil, err
		}
	}

	attach := func(progName string, attachType ebpf.AttachType) error {
		prog := coll.Programs[progName]
		if prog == nil {
			return fmt.Errorf("fixed program %s not found", progName)
		}
		attached, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  attachType,
			Program: prog,
		})
		if err != nil {
			return err
		}
		att.Links = append(att.Links, attached)
		if pinPath == "" {
			return nil
		}
		linkPath := filepath.Join(pinPath, "links", progName)
		if err := os.MkdirAll(filepath.Dir(linkPath), 0o700); err != nil {
			return fmt.Errorf("create link pin dir: %w", err)
		}
		if err := attached.Pin(linkPath); err != nil {
			return fmt.Errorf("pin link %s: %w", progName, err)
		}
		att.PinnedPaths = append(att.PinnedPaths, linkPath)
		return nil
	}

	for _, role := range []struct {
		name       string
		attachType ebpf.AttachType
	}{
		{name: "handle_connect4", attachType: ebpf.AttachCGroupInet4Connect},
		{name: "handle_connect6", attachType: ebpf.AttachCGroupInet6Connect},
		{name: "handle_sendmsg4", attachType: ebpf.AttachCGroupUDP4Sendmsg},
		{name: "handle_sendmsg6", attachType: ebpf.AttachCGroupUDP6Sendmsg},
	} {
		if err := attach(role.name, role.attachType); err != nil {
			cleanupOnError()
			return nil, fmt.Errorf("attach %s: %w", role.name, err)
		}
	}
	return att, nil
}

func validateFixedConnectCollection(coll *ebpf.Collection) error {
	if coll == nil {
		return fmt.Errorf("nil eBPF connect collection")
	}
	if len(coll.Programs) != len(fixedConnectProgramRoles) {
		return fmt.Errorf("embedded connect object has %d programs, want exactly %d", len(coll.Programs), len(fixedConnectProgramRoles))
	}
	for name := range fixedConnectProgramRoles {
		if coll.Programs[name] == nil {
			return fmt.Errorf("embedded connect object is missing fixed program %s", name)
		}
	}
	if len(coll.Maps) != len(fixedConnectMapRoles) {
		return fmt.Errorf("embedded connect object has %d maps, want exactly %d", len(coll.Maps), len(fixedConnectMapRoles))
	}
	for name := range fixedConnectMapRoles {
		if coll.Maps[name] == nil {
			return fmt.Errorf("embedded connect object is missing fixed map %s", name)
		}
	}
	return nil
}

func (a *CgroupAttachment) pinMaps(pinPath string) error {
	if a == nil || a.Collection == nil {
		return fmt.Errorf("nil cgroup attachment")
	}
	mapsDir := filepath.Join(pinPath, "maps")
	if err := os.MkdirAll(mapsDir, 0o700); err != nil {
		return fmt.Errorf("create map pin dir: %w", err)
	}
	names := make([]string, 0, len(a.Collection.Maps))
	for name := range a.Collection.Maps {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		policyMap := a.Collection.Maps[name]
		if policyMap == nil {
			return fmt.Errorf("fixed map %s is unavailable", name)
		}
		mapPath := filepath.Join(mapsDir, name)
		if err := policyMap.Pin(mapPath); err != nil {
			return fmt.Errorf("pin map %s: %w", name, err)
		}
		a.PinnedPaths = append(a.PinnedPaths, mapPath)
	}
	return nil
}

// Close first locks the policy to deny-all, then removes every link pin before
// closing any link fd. A failure to lock or unpin therefore leaves enforcement
// attached and retryable instead of creating an allow window.
func (a *CgroupAttachment) Close() error {
	if a == nil {
		return nil
	}
	if a.Collection != nil && a.CgroupID != 0 && len(a.Links) > 0 {
		if err := LockPolicy(a.Collection, a.CgroupID); err != nil {
			return fmt.Errorf("lock policy before detach: %w", err)
		}
	}
	for _, attached := range a.Links {
		if attached == nil {
			continue
		}
		if pinned, ok := attached.(interface{ IsPinned() bool }); ok && pinned.IsPinned() {
			if err := attached.Unpin(); err != nil {
				return fmt.Errorf("unpin cgroup link before detach: %w", err)
			}
		}
	}

	var cleanupErr error
	for _, attached := range a.Links {
		if attached != nil {
			if err := attached.Close(); err != nil && cleanupErr == nil {
				cleanupErr = err
			}
		}
	}
	a.Links = nil
	if a.Collection != nil {
		for _, policyMap := range a.Collection.Maps {
			if policyMap == nil || !policyMap.IsPinned() {
				continue
			}
			if err := policyMap.Unpin(); err != nil && cleanupErr == nil {
				cleanupErr = err
			}
		}
		a.Collection.Close()
		a.Collection = nil
	}
	for i := len(a.PinnedPaths) - 1; i >= 0; i-- {
		_ = os.Remove(a.PinnedPaths[i])
	}
	a.PinnedPaths = nil
	a.CgroupID = 0
	return cleanupErr
}
