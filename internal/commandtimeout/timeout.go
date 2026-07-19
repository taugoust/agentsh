package commandtimeout

import (
	"fmt"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

// Fallback is used only when resource_limits.command_timeout is absent or
// non-positive.
const Fallback = 5 * time.Minute

// ParsedRequest is caller-owned timeout syntax validated independently of any
// session or policy snapshot. Its fields stay private so only ParseRequest can
// construct a supplied timeout.
type ParsedRequest struct {
	duration time.Duration
	supplied bool
}

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

// ParseRequest validates only caller-owned timeout syntax. It intentionally
// does not inspect a policy limit, allowing invalid requests to be rejected
// before session admission without taking a premature policy snapshot.
func ParseRequest(requested *string) (ParsedRequest, error) {
	// Older REST and gRPC clients encode an omitted timeout as an empty
	// string, so preserve that wire compatibility.
	if requested == nil || *requested == "" {
		return ParsedRequest{}, nil
	}

	duration, err := time.ParseDuration(*requested)
	if err != nil {
		return ParsedRequest{}, fmt.Errorf("invalid timeout %q: %w", *requested, err)
	}
	if duration <= 0 {
		return ParsedRequest{}, fmt.Errorf("timeout must be greater than zero")
	}
	if duration < time.Millisecond {
		return ParsedRequest{}, fmt.Errorf("timeout must be at least 1ms")
	}
	return ParsedRequest{duration: duration, supplied: true}, nil
}

// ResolveParsed selects the policy default/cap for caller syntax that was
// already validated by ParseRequest.
func ResolveParsed(requested ParsedRequest, policyLimit time.Duration) Resolution {
	base := Fallback
	source := types.CommandTimeoutSourceFallback
	if policyLimit > 0 {
		base = policyLimit
		source = types.CommandTimeoutSourcePolicyDefault
	}
	if !requested.supplied {
		return Resolution{
			Duration: base,
			Metadata: types.CommandTimeout{
				EffectiveMS: CeilMilliseconds(base),
				Source:      source,
			},
		}
	}

	requestedMS := CeilMilliseconds(requested.duration)
	effective := requested.duration
	source = types.CommandTimeoutSourceExplicit
	if policyLimit > 0 && requested.duration > policyLimit {
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
	}
}

// Resolve validates and resolves an optional caller timeout against the policy
// default/maximum. It is pure: it does not inspect request, session, or process
// state and has no side effects.
func Resolve(requested *string, policyLimit time.Duration) (Resolution, error) {
	parsed, err := ParseRequest(requested)
	if err != nil {
		return Resolution{}, err
	}
	return ResolveParsed(parsed, policyLimit), nil
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
