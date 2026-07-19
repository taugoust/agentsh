package commandtimeout

import (
	"fmt"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

// Fallback is used only when resource_limits.command_timeout is absent or
// non-positive.
const Fallback = 5 * time.Minute

// Resolution is the validated timeout used to execute one ordinary command
// and the public metadata describing how it was selected.
type Resolution struct {
	Duration time.Duration
	Metadata types.CommandTimeout
}

// CeilMilliseconds converts a duration to public millisecond metadata without
// reporting a shorter interval than the server enforces. The quotient/remainder
// form avoids overflowing near time.Duration's maximum value.
func CeilMilliseconds(duration time.Duration) int64 {
	milliseconds := int64(duration / time.Millisecond)
	if duration > 0 && duration%time.Millisecond != 0 {
		milliseconds++
	}
	return milliseconds
}

// Resolve validates and resolves an optional caller timeout against the policy
// default/maximum. It is pure: it does not inspect request, session, or process
// state and has no side effects.
func Resolve(requested *string, policyLimit time.Duration) (Resolution, error) {
	base := Fallback
	source := types.CommandTimeoutSourceFallback
	if policyLimit > 0 {
		base = policyLimit
		source = types.CommandTimeoutSourcePolicyDefault
	}

	// Older REST and gRPC clients encode an omitted timeout as an empty
	// string, so preserve that wire compatibility.
	if requested == nil || *requested == "" {
		return Resolution{
			Duration: base,
			Metadata: types.CommandTimeout{
				EffectiveMS: CeilMilliseconds(base),
				Source:      source,
			},
		}, nil
	}

	duration, err := time.ParseDuration(*requested)
	if err != nil {
		return Resolution{}, fmt.Errorf("invalid timeout %q: %w", *requested, err)
	}
	if duration <= 0 {
		return Resolution{}, fmt.Errorf("timeout must be greater than zero")
	}
	if duration < time.Millisecond {
		return Resolution{}, fmt.Errorf("timeout must be at least 1ms")
	}

	requestedMS := CeilMilliseconds(duration)
	effective := duration
	source = types.CommandTimeoutSourceExplicit
	if policyLimit > 0 && duration > policyLimit {
		effective = policyLimit
		source = types.CommandTimeoutSourcePolicyCap
	}
	return Resolution{
		Duration: effective,
		Metadata: types.CommandTimeout{
			RequestedMS: &requestedMS,
			EffectiveMS: CeilMilliseconds(effective),
			Source:      source,
		},
	}, nil
}

// SessionMetadata exposes the default and optional maximum that apply before
// an ordinary command request is made.
func SessionMetadata(policyLimit time.Duration) types.SessionCommandTimeout {
	if policyLimit > 0 {
		milliseconds := CeilMilliseconds(policyLimit)
		return types.SessionCommandTimeout{
			DefaultMS: milliseconds,
			MaximumMS: &milliseconds,
			Source:    types.SessionCommandTimeoutSourcePolicy,
		}
	}
	return types.SessionCommandTimeout{
		DefaultMS: CeilMilliseconds(Fallback),
		Source:    types.SessionCommandTimeoutSourceFallback,
	}
}
