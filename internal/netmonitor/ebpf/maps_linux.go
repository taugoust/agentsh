//go:build linux

package ebpf

import (
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/cilium/ebpf"
)

var (
	lastAllowCgroup    uint64
	lastDenyCgroup     uint64
	lastLpmAllowCgroup uint64
	lastLpmDenyCgroup  uint64
	lastAllowTotal     uint64
	lastDenyTotal      uint64
	lastLpmAllowTotal  uint64
	lastLpmDenyTotal   uint64
)

// MapCounts is a best-effort snapshot from the last PopulateAllowlist call.
type MapCounts struct {
	AllowCgroup    uint64
	AllowTotal     uint64
	DenyCgroup     uint64
	DenyTotal      uint64
	LpmAllowCgroup uint64
	LpmAllowTotal  uint64
	LpmDenyCgroup  uint64
	LpmDenyTotal   uint64
}

func GetLastMapCounts() MapCounts {
	return MapCounts{
		AllowCgroup:    atomic.LoadUint64(&lastAllowCgroup),
		AllowTotal:     atomic.LoadUint64(&lastAllowTotal),
		DenyCgroup:     atomic.LoadUint64(&lastDenyCgroup),
		DenyTotal:      atomic.LoadUint64(&lastDenyTotal),
		LpmAllowCgroup: atomic.LoadUint64(&lastLpmAllowCgroup),
		LpmAllowTotal:  atomic.LoadUint64(&lastLpmAllowTotal),
		LpmDenyCgroup:  atomic.LoadUint64(&lastLpmDenyCgroup),
		LpmDenyTotal:   atomic.LoadUint64(&lastLpmDenyTotal),
	}
}

// lpm4Key and lpm6Key mirror struct lpm{4,6}_key in connect.bpf.c.
// Keep padding explicit: github.com/cilium/ebpf marshals exported fields and
// rejects implicit Go padding when the encoded size does not match the BPF key.
type lpm4Key struct {
	Prefixlen uint32
	Pad0      uint32
	CgroupID  uint64
	Protocol  uint8
	Pad1      uint8
	Dport     uint16
	Addr      [4]byte
}

type lpm6Key struct {
	Prefixlen uint32
	Pad0      uint32
	CgroupID  uint64
	Protocol  uint8
	Pad1      uint8
	Dport     uint16
	Addr      [16]byte
	Pad2      [4]byte
}

const (
	lpmPrefixPaddingBits          = 32
	lpmSelectorPrefixBits         = lpmPrefixPaddingBits + 64 + 8 + 8 + 16
	policyStateDefaultAllow uint8 = 0
	policyStateDefaultDeny  uint8 = 1
	policyStateLocked       uint8 = 2
)

func lpmPrefixLen(addrBits uint32, _ bool) uint32 {
	return uint32(lpmSelectorPrefixBits) + addrBits
}

// LockPolicy puts cgroupID into deny-all update state. Attach paths use this
// before linking any program, and policy replacement uses it before removing or
// adding entries. A failed replacement therefore remains fail closed.
func LockPolicy(coll *ebpf.Collection, cgroupID uint64) error {
	if coll == nil {
		return fmt.Errorf("nil collection")
	}
	if cgroupID == 0 {
		return fmt.Errorf("cgroup id is required")
	}
	defdeny, ok := coll.Maps["default_deny"]
	if !ok || defdeny == nil {
		return fmt.Errorf("default_deny map missing")
	}
	if err := defdeny.Put(cgroupID, policyStateLocked); err != nil {
		return fmt.Errorf("lock network policy: %w", err)
	}
	return nil
}

// PopulateAllowlist atomically publishes a replacement policy from the BPF
// program's perspective. It first locks the cgroup into deny-all state, replaces
// every exact/LPM entry, and only then publishes default-allow or default-deny.
// Any error leaves the cgroup locked and therefore fail closed.
func PopulateAllowlist(coll *ebpf.Collection, cgroupID uint64, allow []AllowKey, allowCIDRs []AllowCIDR, deny []AllowKey, denyCIDRs []AllowCIDR, defaultDeny bool) error {
	if coll == nil {
		return fmt.Errorf("nil collection")
	}
	if err := validatePolicyEntries(cgroupID, allow, allowCIDRs, "allow"); err != nil {
		return err
	}
	if err := validatePolicyEntries(cgroupID, deny, denyCIDRs, "deny"); err != nil {
		return err
	}
	defdeny := coll.Maps["default_deny"]
	if defdeny == nil {
		return fmt.Errorf("default_deny map missing")
	}

	// Publish deny-all before inspecting or changing any other policy map. A
	// missing/corrupt map handle therefore cannot leave an attached cgroup in an
	// allow state while userspace reports an update failure.
	if err := LockPolicy(coll, cgroupID); err != nil {
		return err
	}
	allowMap := coll.Maps["allowlist"]
	if allowMap == nil {
		return fmt.Errorf("allowlist map missing")
	}
	denyMap := coll.Maps["denylist"]
	if denyMap == nil {
		return fmt.Errorf("denylist map missing")
	}
	lpm4 := coll.Maps["lpm4_allow"]
	lpm6 := coll.Maps["lpm6_allow"]
	lpm4deny := coll.Maps["lpm4_deny"]
	lpm6deny := coll.Maps["lpm6_deny"]
	for name, policyMap := range map[string]*ebpf.Map{
		"lpm4_allow": lpm4,
		"lpm6_allow": lpm6,
		"lpm4_deny":  lpm4deny,
		"lpm6_deny":  lpm6deny,
	} {
		if policyMap == nil {
			return fmt.Errorf("%s map missing", name)
		}
	}

	// Clear existing LPM entries for this cgroup.
	if lpm4 != nil {
		iter := lpm4.Iterate()
		var k lpm4Key
		var v uint8
		for iter.Next(&k, &v) {
			if k.CgroupID == cgroupID {
				if err := lpm4.Delete(k); err != nil && !isNoEntry(err) {
					return fmt.Errorf("delete lpm4 allow: %w", err)
				}
			}
		}
		if err := iter.Err(); err != nil {
			return fmt.Errorf("iterate lpm4: %w", err)
		}
	}
	if lpm6 != nil {
		iter := lpm6.Iterate()
		var k lpm6Key
		var v uint8
		for iter.Next(&k, &v) {
			if k.CgroupID == cgroupID {
				if err := lpm6.Delete(k); err != nil && !isNoEntry(err) {
					return fmt.Errorf("delete lpm6 allow: %w", err)
				}
			}
		}
		if err := iter.Err(); err != nil {
			return fmt.Errorf("iterate lpm6: %w", err)
		}
	}
	if lpm4deny != nil {
		iter := lpm4deny.Iterate()
		var k lpm4Key
		var v uint8
		for iter.Next(&k, &v) {
			if k.CgroupID == cgroupID {
				if err := lpm4deny.Delete(k); err != nil && !isNoEntry(err) {
					return fmt.Errorf("delete lpm4 deny: %w", err)
				}
			}
		}
		if err := iter.Err(); err != nil {
			return fmt.Errorf("iterate lpm4 deny: %w", err)
		}
	}
	if lpm6deny != nil {
		iter := lpm6deny.Iterate()
		var k lpm6Key
		var v uint8
		for iter.Next(&k, &v) {
			if k.CgroupID == cgroupID {
				if err := lpm6deny.Delete(k); err != nil && !isNoEntry(err) {
					return fmt.Errorf("delete lpm6 deny: %w", err)
				}
			}
		}
		if err := iter.Err(); err != nil {
			return fmt.Errorf("iterate lpm6 deny: %w", err)
		}
	}

	// Remove existing entries for this cgroup first to avoid stale rules after policy changes.
	iter := allowMap.Iterate()
	var k AllowKey
	var v uint8
	var allowInserted uint64
	var denyInserted uint64
	var lpmAllowInserted uint64
	var lpmDenyInserted uint64
	var allowRemoved uint64
	var denyRemoved uint64
	var allowTotalBefore uint64
	var denyTotalBefore uint64
	var lpmAllowTotal uint64
	var lpmDenyTotal uint64
	for iter.Next(&k, &v) {
		allowTotalBefore++
		if k.CgroupID == cgroupID {
			if err := allowMap.Delete(k); err != nil && !isNoEntry(err) {
				return fmt.Errorf("delete allowlist: %w", err)
			}
			allowRemoved++
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate allowlist: %w", err)
	}

	// Clear deny exact map
	iter = denyMap.Iterate()
	for iter.Next(&k, &v) {
		denyTotalBefore++
		if k.CgroupID == cgroupID {
			if err := denyMap.Delete(k); err != nil && !isNoEntry(err) {
				return fmt.Errorf("delete denylist: %w", err)
			}
			denyRemoved++
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate denylist: %w", err)
	}

	for _, e := range allow {
		key := e
		key.CgroupID = cgroupID
		val := uint8(1)
		if err := allowMap.Put(key, val); err != nil {
			return fmt.Errorf("put allowlist: %w", err)
		}
		allowInserted++
	}

	for _, e := range deny {
		key := e
		key.CgroupID = cgroupID
		val := uint8(1)
		if err := denyMap.Put(key, val); err != nil {
			return fmt.Errorf("put denylist: %w", err)
		}
		denyInserted++
	}

	// Load CIDRs into LPM tries.
	for _, c := range allowCIDRs {
		if c.Family == 2 {
			var key lpm4Key
			key.Prefixlen = lpmPrefixLen(c.PrefixLen, c.Dport != 0)
			key.CgroupID = cgroupID
			key.Protocol = c.Protocol
			key.Dport = c.Dport
			copy(key.Addr[:], c.Addr[:4])
			val := uint8(1)
			if err := lpm4.Put(key, val); err != nil {
				return fmt.Errorf("put lpm4 allow: %w", err)
			}
			lpmAllowInserted++
		} else if c.Family == 10 {
			var key lpm6Key
			key.Prefixlen = lpmPrefixLen(c.PrefixLen, c.Dport != 0)
			key.CgroupID = cgroupID
			key.Protocol = c.Protocol
			key.Dport = c.Dport
			copy(key.Addr[:], c.Addr[:])
			val := uint8(1)
			if err := lpm6.Put(key, val); err != nil {
				return fmt.Errorf("put lpm6 allow: %w", err)
			}
			lpmAllowInserted++
		}
	}
	// Count LPM allow totals after insertion (best effort, may race)
	if lpm4 != nil {
		iter := lpm4.Iterate()
		var k lpm4Key
		var v uint8
		for iter.Next(&k, &v) {
			lpmAllowTotal++
		}
	}
	if lpm6 != nil {
		iter := lpm6.Iterate()
		var k lpm6Key
		var v uint8
		for iter.Next(&k, &v) {
			lpmAllowTotal++
		}
	}
	for _, c := range denyCIDRs {
		if c.Family == 2 {
			var key lpm4Key
			key.Prefixlen = lpmPrefixLen(c.PrefixLen, c.Dport != 0)
			key.CgroupID = cgroupID
			key.Protocol = c.Protocol
			key.Dport = c.Dport
			copy(key.Addr[:], c.Addr[:4])
			val := uint8(1)
			if err := lpm4deny.Put(key, val); err != nil {
				return fmt.Errorf("put lpm4 deny: %w", err)
			}
			lpmDenyInserted++
		} else if c.Family == 10 {
			var key lpm6Key
			key.Prefixlen = lpmPrefixLen(c.PrefixLen, c.Dport != 0)
			key.CgroupID = cgroupID
			key.Protocol = c.Protocol
			key.Dport = c.Dport
			copy(key.Addr[:], c.Addr[:])
			val := uint8(1)
			if err := lpm6deny.Put(key, val); err != nil {
				return fmt.Errorf("put lpm6 deny: %w", err)
			}
			lpmDenyInserted++
		}
	}
	if lpm4deny != nil {
		iter := lpm4deny.Iterate()
		var k lpm4Key
		var v uint8
		for iter.Next(&k, &v) {
			lpmDenyTotal++
		}
	}
	if lpm6deny != nil {
		iter := lpm6deny.Iterate()
		var k lpm6Key
		var v uint8
		for iter.Next(&k, &v) {
			lpmDenyTotal++
		}
	}

	// Publish the completed policy only after every map replacement succeeds.
	defVal := policyStateDefaultAllow
	if defaultDeny {
		defVal = policyStateDefaultDeny
	}
	if err := defdeny.Put(cgroupID, defVal); err != nil {
		return fmt.Errorf("set default_deny: %w", err)
	}

	allowTotal := allowTotalBefore - allowRemoved + allowInserted
	denyTotal := denyTotalBefore - denyRemoved + denyInserted
	atomic.StoreUint64(&lastAllowCgroup, allowInserted)
	atomic.StoreUint64(&lastDenyCgroup, denyInserted)
	atomic.StoreUint64(&lastLpmAllowCgroup, lpmAllowInserted)
	atomic.StoreUint64(&lastLpmDenyCgroup, lpmDenyInserted)
	atomic.StoreUint64(&lastAllowTotal, allowTotal)
	atomic.StoreUint64(&lastDenyTotal, denyTotal)
	atomic.StoreUint64(&lastLpmAllowTotal, lpmAllowTotal)
	atomic.StoreUint64(&lastLpmDenyTotal, lpmDenyTotal)
	return nil
}

func validatePolicyEntries(cgroupID uint64, exact []AllowKey, cidrs []AllowCIDR, kind string) error {
	for i, entry := range exact {
		if entry.CgroupID != 0 && entry.CgroupID != cgroupID {
			return fmt.Errorf("%s exact entry %d carries a different cgroup id", kind, i)
		}
		if entry.Family != 2 && entry.Family != 10 {
			return fmt.Errorf("%s exact entry %d has unsupported family %d", kind, i, entry.Family)
		}
		if !validPolicyProtocol(entry.Protocol) {
			return fmt.Errorf("%s exact entry %d has unsupported protocol %d", kind, i, entry.Protocol)
		}
		if entry.Family == 2 && !zeroBytes(entry.Addr[4:]) {
			return fmt.Errorf("%s exact IPv4 entry %d has non-zero trailing address bytes", kind, i)
		}
	}
	for i, entry := range cidrs {
		if entry.CgroupID != 0 && entry.CgroupID != cgroupID {
			return fmt.Errorf("%s CIDR entry %d carries a different cgroup id", kind, i)
		}
		if !validPolicyProtocol(entry.Protocol) {
			return fmt.Errorf("%s CIDR entry %d has unsupported protocol %d", kind, i, entry.Protocol)
		}
		switch entry.Family {
		case 2:
			if entry.PrefixLen > 32 {
				return fmt.Errorf("%s IPv4 CIDR entry %d has prefix %d", kind, i, entry.PrefixLen)
			}
			if !zeroBytes(entry.Addr[4:]) {
				return fmt.Errorf("%s IPv4 CIDR entry %d has non-zero trailing address bytes", kind, i)
			}
			var raw [4]byte
			copy(raw[:], entry.Addr[:4])
			addr := netip.AddrFrom4(raw)
			if netip.PrefixFrom(addr, int(entry.PrefixLen)).Masked().Addr() != addr {
				return fmt.Errorf("%s IPv4 CIDR entry %d is not masked", kind, i)
			}
		case 10:
			if entry.PrefixLen > 128 {
				return fmt.Errorf("%s IPv6 CIDR entry %d has prefix %d", kind, i, entry.PrefixLen)
			}
			addr := netip.AddrFrom16(entry.Addr)
			if netip.PrefixFrom(addr, int(entry.PrefixLen)).Masked().Addr() != addr {
				return fmt.Errorf("%s IPv6 CIDR entry %d is not masked", kind, i)
			}
		default:
			return fmt.Errorf("%s CIDR entry %d has unsupported family %d", kind, i, entry.Family)
		}
	}
	return nil
}

func validPolicyProtocol(protocol uint8) bool {
	return protocol == 0 || protocol == 6 || protocol == 17
}

func zeroBytes(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

// ValidatePinnedPolicyState verifies the contents of a per-registration map set
// before pinned links are reused. Every entry must belong to cgroupID, values
// must use the fixed schema, and the policy state must already be default-deny
// or locked. A missing/default-allow state is unsafe to reuse after a crash.
func ValidatePinnedPolicyState(coll *ebpf.Collection, cgroupID uint64) error {
	if coll == nil || cgroupID == 0 {
		return fmt.Errorf("pinned policy collection and cgroup id are required")
	}
	defaultMap := coll.Maps["default_deny"]
	if defaultMap == nil {
		return fmt.Errorf("default_deny map missing")
	}
	var defaultEntries int
	iter := defaultMap.Iterate()
	var defaultCgroup uint64
	var state uint8
	for iter.Next(&defaultCgroup, &state) {
		defaultEntries++
		if defaultCgroup != cgroupID {
			return fmt.Errorf("default_deny contains unexpected cgroup id %d", defaultCgroup)
		}
		if state != policyStateDefaultDeny && state != policyStateLocked {
			return fmt.Errorf("default_deny has unsafe state %d for cgroup %d", state, cgroupID)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate default_deny: %w", err)
	}
	if defaultEntries != 1 {
		return fmt.Errorf("default_deny contains %d entries, want exactly one", defaultEntries)
	}
	for _, item := range []struct {
		name string
		m    *ebpf.Map
	}{
		{name: "allowlist", m: coll.Maps["allowlist"]},
		{name: "denylist", m: coll.Maps["denylist"]},
	} {
		if err := validatePinnedExactMap(item.m, item.name, cgroupID); err != nil {
			return err
		}
	}
	for _, item := range []struct {
		name     string
		m        *ebpf.Map
		addrBits uint32
	}{
		{name: "lpm4_allow", m: coll.Maps["lpm4_allow"], addrBits: 32},
		{name: "lpm4_deny", m: coll.Maps["lpm4_deny"], addrBits: 32},
	} {
		if err := validatePinnedLPM4Map(item.m, item.name, item.addrBits, cgroupID); err != nil {
			return err
		}
	}
	for _, item := range []struct {
		name     string
		m        *ebpf.Map
		addrBits uint32
	}{
		{name: "lpm6_allow", m: coll.Maps["lpm6_allow"], addrBits: 128},
		{name: "lpm6_deny", m: coll.Maps["lpm6_deny"], addrBits: 128},
	} {
		if err := validatePinnedLPM6Map(item.m, item.name, item.addrBits, cgroupID); err != nil {
			return err
		}
	}
	return nil
}

func validatePinnedExactMap(m *ebpf.Map, name string, cgroupID uint64) error {
	if m == nil {
		return fmt.Errorf("%s map missing", name)
	}
	iter := m.Iterate()
	var key AllowKey
	var value uint8
	for iter.Next(&key, &value) {
		if key.CgroupID != cgroupID || value != 1 {
			return fmt.Errorf("%s contains an entry outside the registered cgroup schema", name)
		}
		if err := validatePolicyEntries(cgroupID, []AllowKey{key}, nil, name); err != nil {
			return err
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate %s: %w", name, err)
	}
	return nil
}

func validatePinnedLPM4Map(m *ebpf.Map, name string, addrBits uint32, cgroupID uint64) error {
	if m == nil {
		return fmt.Errorf("%s map missing", name)
	}
	iter := m.Iterate()
	var key lpm4Key
	var value uint8
	for iter.Next(&key, &value) {
		if key.CgroupID != cgroupID || value != 1 || !validPolicyProtocol(key.Protocol) {
			return fmt.Errorf("%s contains an entry outside the registered cgroup schema", name)
		}
		if key.Prefixlen < lpmPrefixLen(0, true) || key.Prefixlen > lpmPrefixLen(addrBits, true) {
			return fmt.Errorf("%s contains invalid prefix length %d", name, key.Prefixlen)
		}
		bits := key.Prefixlen - lpmPrefixLen(0, true)
		addr := netip.AddrFrom4(key.Addr)
		if netip.PrefixFrom(addr, int(bits)).Masked().Addr() != addr {
			return fmt.Errorf("%s contains an unmasked address", name)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate %s: %w", name, err)
	}
	return nil
}

func validatePinnedLPM6Map(m *ebpf.Map, name string, addrBits uint32, cgroupID uint64) error {
	if m == nil {
		return fmt.Errorf("%s map missing", name)
	}
	iter := m.Iterate()
	var key lpm6Key
	var value uint8
	for iter.Next(&key, &value) {
		if key.CgroupID != cgroupID || value != 1 || !validPolicyProtocol(key.Protocol) {
			return fmt.Errorf("%s contains an entry outside the registered cgroup schema", name)
		}
		if key.Prefixlen < lpmPrefixLen(0, true) || key.Prefixlen > lpmPrefixLen(addrBits, true) {
			return fmt.Errorf("%s contains invalid prefix length %d", name, key.Prefixlen)
		}
		bits := key.Prefixlen - lpmPrefixLen(0, true)
		addr := netip.AddrFrom16(key.Addr)
		if netip.PrefixFrom(addr, int(bits)).Masked().Addr() != addr {
			return fmt.Errorf("%s contains an unmasked address", name)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate %s: %w", name, err)
	}
	return nil
}

// CleanupAllowlist locks cgroupID in deny-all state and removes its policy
// entries. It intentionally does not delete the state entry: callers must
// detach all links before closing/removing maps, so cleanup cannot create an
// allow-all interval while a link is still active.
func CleanupAllowlist(coll *ebpf.Collection, cgroupID uint64) error {
	if coll == nil {
		return nil
	}
	if err := LockPolicy(coll, cgroupID); err != nil {
		return err
	}
	if err := clearExactEntries(coll.Maps["allowlist"], cgroupID, "allowlist"); err != nil {
		return err
	}
	if err := clearExactEntries(coll.Maps["denylist"], cgroupID, "denylist"); err != nil {
		return err
	}
	if err := clearLPM4Entries(coll.Maps["lpm4_allow"], cgroupID, "lpm4_allow"); err != nil {
		return err
	}
	if err := clearLPM6Entries(coll.Maps["lpm6_allow"], cgroupID, "lpm6_allow"); err != nil {
		return err
	}
	if err := clearLPM4Entries(coll.Maps["lpm4_deny"], cgroupID, "lpm4_deny"); err != nil {
		return err
	}
	return clearLPM6Entries(coll.Maps["lpm6_deny"], cgroupID, "lpm6_deny")
}

func clearExactEntries(m *ebpf.Map, cgroupID uint64, name string) error {
	if m == nil {
		return nil
	}
	iter := m.Iterate()
	var key AllowKey
	var value uint8
	for iter.Next(&key, &value) {
		if key.CgroupID == cgroupID {
			if err := m.Delete(key); err != nil && !isNoEntry(err) {
				return fmt.Errorf("delete %s: %w", name, err)
			}
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate %s: %w", name, err)
	}
	return nil
}

func clearLPM4Entries(m *ebpf.Map, cgroupID uint64, name string) error {
	if m == nil {
		return nil
	}
	iter := m.Iterate()
	var key lpm4Key
	var value uint8
	for iter.Next(&key, &value) {
		if key.CgroupID == cgroupID {
			if err := m.Delete(key); err != nil && !isNoEntry(err) {
				return fmt.Errorf("delete %s: %w", name, err)
			}
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate %s: %w", name, err)
	}
	return nil
}

func clearLPM6Entries(m *ebpf.Map, cgroupID uint64, name string) error {
	if m == nil {
		return nil
	}
	iter := m.Iterate()
	var key lpm6Key
	var value uint8
	for iter.Next(&key, &value) {
		if key.CgroupID == cgroupID {
			if err := m.Delete(key); err != nil && !isNoEntry(err) {
				return fmt.Errorf("delete %s: %w", name, err)
			}
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate %s: %w", name, err)
	}
	return nil
}

func isNoEntry(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "no such file or directory") || strings.Contains(err.Error(), "not found")
}

// AddTemporaryAllowRule adds a single allow rule for a specific connection.
// This is used by the approve mode to allow future connections after user approval.
// The rule is added to the allowlist map and will persist until explicitly removed
// or the map is cleared during policy refresh.
func AddTemporaryAllowRule(coll *ebpf.Collection, cgroupID uint64, key AllowKey) error {
	if coll == nil {
		return fmt.Errorf("nil collection")
	}
	allowMap, ok := coll.Maps["allowlist"]
	if !ok {
		return fmt.Errorf("allowlist map missing")
	}

	if err := validatePolicyEntries(cgroupID, []AllowKey{key}, nil, "temporary allow"); err != nil {
		return err
	}
	k := key
	k.CgroupID = cgroupID
	val := uint8(1)
	if err := allowMap.Put(k, val); err != nil {
		return fmt.Errorf("put temporary allow: %w", err)
	}
	return nil
}

// RemoveTemporaryAllowRule removes a previously added temporary allow rule.
func RemoveTemporaryAllowRule(coll *ebpf.Collection, cgroupID uint64, key AllowKey) error {
	if coll == nil {
		return nil
	}
	allowMap, ok := coll.Maps["allowlist"]
	if !ok {
		return nil
	}

	k := key
	k.CgroupID = cgroupID
	_ = allowMap.Delete(k) // best effort
	return nil
}
