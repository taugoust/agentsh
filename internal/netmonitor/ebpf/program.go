package ebpf

import "sync"

var (
	mapAllowOverride   uint32
	mapDenyOverride    uint32
	mapLPMOverride     uint32
	mapLPMDenyOverride uint32
	mapDefaultOverride uint32
	mapOverrideOnce    sync.Once
)

type MapOverrides struct {
	Allow   uint32
	Deny    uint32
	LPM     uint32
	LPMDeny uint32
	Default uint32
}

// SetMapSizeOverrides sets runtime map size overrides for allowlist/LPM/default maps (0 = keep embedded default).
func SetMapSizeOverrides(allow, deny, lpm, lpmDeny, def uint32) {
	mapOverrideOnce.Do(func() {
		mapAllowOverride = allow
		mapDenyOverride = deny
		mapLPMOverride = lpm
		mapLPMDenyOverride = lpmDeny
		mapDefaultOverride = def
	})
}

func GetMapOverrides() MapOverrides {
	return MapOverrides{
		Allow:   mapAllowOverride,
		Deny:    mapDenyOverride,
		LPM:     mapLPMOverride,
		LPMDeny: mapLPMDenyOverride,
		Default: mapDefaultOverride,
	}
}

// AllowKey mirrors the BPF allow_key.
type AllowKey struct {
	CgroupID uint64
	Family   uint8
	Protocol uint8 // IPPROTO_TCP (6) or IPPROTO_UDP (17), 0 = any
	Dport    uint16
	Addr     [16]byte
	// _pad matches the kernel BPF struct's trailing alignment. clang sizes
	// `struct allow_key` at 32 bytes (__u64 head forces 8-byte struct
	// alignment), but encoding/binary emits 28 bytes for the fields above.
	// Without this pad, cilium/ebpf rejects every Put on the allow/deny
	// maps with "doesn't marshal to 32 bytes" and silently disables
	// connect-filter enforcement at runtime. See issue #349.
	_ [4]byte
}

// AllowCIDR represents a CIDR prefix allowed for a cgroup.
type AllowCIDR struct {
	CgroupID  uint64
	Family    uint8
	Protocol  uint8 // IPPROTO_TCP (6) or IPPROTO_UDP (17), 0 = any
	PrefixLen uint32
	Dport     uint16 // 0 means any port
	Addr      [16]byte
}
