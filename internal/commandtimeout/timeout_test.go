package commandtimeout

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestCeilMillisecondsNeverShortensDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     int64
	}{
		{name: "zero", want: 0},
		{name: "one nanosecond", duration: time.Nanosecond, want: 1},
		{name: "sub millisecond", duration: 999 * time.Microsecond, want: 1},
		{name: "integral millisecond", duration: time.Millisecond, want: 1},
		{name: "fractional millisecond", duration: time.Millisecond + time.Nanosecond, want: 2},
		{name: "maximum duration does not overflow", duration: time.Duration(1<<63 - 1), want: 9_223_372_036_855},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := CeilMilliseconds(test.duration); got != test.want {
				t.Fatalf("CeilMilliseconds(%s) = %d, want %d", test.duration, got, test.want)
			}
		})
	}
}

func TestParseRequestSeparatesCallerValidationFromPolicyResolution(t *testing.T) {
	requested := "2s"
	parsed, err := ParseRequest(&requested)
	if err != nil {
		t.Fatal(err)
	}

	capped := ResolveParsed(parsed, time.Second)
	if capped.Duration != time.Second || capped.Metadata.Source != types.CommandTimeoutSourcePolicyCap {
		t.Fatalf("capped resolution = %+v", capped)
	}
	explicit := ResolveParsed(parsed, 3*time.Second)
	if explicit.Duration != 2*time.Second || explicit.Metadata.Source != types.CommandTimeoutSourceExplicit {
		t.Fatalf("explicit resolution = %+v", explicit)
	}

	for _, value := range []string{"bad", "0s", "-1ms", "500us"} {
		t.Run(value, func(t *testing.T) {
			if _, err := ParseRequest(&value); err == nil {
				t.Fatalf("ParseRequest(%q) succeeded", value)
			}
		})
	}
}

func TestResolveRoundsFractionalMetadataUp(t *testing.T) {
	t.Run("explicit", func(t *testing.T) {
		requested := "1.9ms"
		resolution, err := Resolve(&requested, 10*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		if resolution.Duration != 1900*time.Microsecond || resolution.Metadata.RequestedMS == nil || *resolution.Metadata.RequestedMS != 2 || resolution.Metadata.EffectiveMS != 2 || resolution.Metadata.Source != types.CommandTimeoutSourceExplicit {
			t.Fatalf("resolution = %+v", resolution)
		}
	})

	t.Run("policy cap", func(t *testing.T) {
		requested := "2.1ms"
		resolution, err := Resolve(&requested, 1900*time.Microsecond)
		if err != nil {
			t.Fatal(err)
		}
		if resolution.Duration != 1900*time.Microsecond || resolution.Metadata.RequestedMS == nil || *resolution.Metadata.RequestedMS != 3 || resolution.Metadata.EffectiveMS != 2 || resolution.Metadata.Source != types.CommandTimeoutSourcePolicyCap {
			t.Fatalf("resolution = %+v", resolution)
		}
	})

	t.Run("policy default", func(t *testing.T) {
		resolution, err := Resolve(nil, 1900*time.Microsecond)
		if err != nil {
			t.Fatal(err)
		}
		if resolution.Duration != 1900*time.Microsecond || resolution.Metadata.RequestedMS != nil || resolution.Metadata.EffectiveMS != 2 || resolution.Metadata.Source != types.CommandTimeoutSourcePolicyDefault {
			t.Fatalf("resolution = %+v", resolution)
		}
	})
}

func TestSessionMetadataRoundsFractionalPolicyUp(t *testing.T) {
	metadata := SessionMetadata(1900 * time.Microsecond)
	if metadata.DefaultMS != 2 || metadata.MaximumMS == nil || *metadata.MaximumMS != 2 || metadata.Source != types.SessionCommandTimeoutSourcePolicy {
		t.Fatalf("metadata = %+v", metadata)
	}
}
