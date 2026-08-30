package externalrunner

import "fmt"

const (
	minimumHostEgressPort uint32 = 1024
	maximumHostEgressPort uint32 = 65535
)

// deriveHostEgressPort maps every CID in one v3 profile lease range to a
// distinct non-privileged VSOCK port. A leased CID is used verbatim whenever it
// is itself a valid, non-reserved port. CIDs that cannot be used verbatim are
// assigned, in CID order, to ports not claimed by any exact-CID mapping.
func deriveHostEgressPort(profile Profile, cid uint32) (uint32, error) {
	if profile.Schema != ProfileSchemaV3 || profile.HostEgress == nil || cid < profile.VSock.CIDMin || cid > profile.VSock.CIDMax {
		return 0, fmt.Errorf("external runner v3 egress CID binding is invalid")
	}
	reserved := func(port uint32) bool {
		return port == profile.Guest.ControlPort || port == profile.Guest.SupervisorPort
	}
	exact := func(candidate uint32) bool {
		return validPort(candidate) && !reserved(candidate)
	}
	if exact(cid) {
		return cid, nil
	}

	// Determine this non-exact CID's zero-based ordinal without arithmetic that
	// can wrap at the uint32 boundary.
	ordinal := uint64(0)
	for candidate := uint64(profile.VSock.CIDMin); candidate <= uint64(cid); candidate++ {
		if !exact(uint32(candidate)) {
			if uint32(candidate) == cid {
				break
			}
			ordinal++
		}
	}

	for candidate := minimumHostEgressPort; candidate <= maximumHostEgressPort; candidate++ {
		if reserved(candidate) {
			continue
		}
		// A valid port numerically inside the lease range belongs to that CID's
		// preferred exact mapping and cannot be consumed by a fallback CID.
		if candidate >= profile.VSock.CIDMin && candidate <= profile.VSock.CIDMax && exact(candidate) {
			continue
		}
		if ordinal == 0 {
			return candidate, nil
		}
		ordinal--
	}
	return 0, fmt.Errorf("external runner v3 egress port capacity is exhausted")
}
