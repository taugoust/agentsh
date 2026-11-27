package platform

import (
	"fmt"
	"runtime"
)

// PlatformOptions configures platform selection and fallback.
type PlatformOptions struct {
	// Mode is the preferred platform mode (use "auto" for automatic detection)
	Mode string

	// FallbackEnabled allows falling back to alternative platforms
	FallbackEnabled bool

	// FallbackOrder specifies fallback priority (first available is used)
	FallbackOrder []string
}

// New creates the appropriate platform implementation for the current OS.
// It automatically detects the best platform mode.
func New() (Platform, error) {
	return NewWithMode(ModeAuto)
}

// NewWithOptions creates a platform using the provided options.
// This supports mode selection and fallback behavior from config.
func NewWithOptions(opts PlatformOptions) (Platform, error) {
	mode := ParsePlatformMode(opts.Mode)

	if mode == ModeAuto {
		mode = detectPlatformMode()
	}

	// Try the preferred mode first
	plat, err := NewWithMode(mode)
	if err == nil {
		return plat, nil
	}

	// If fallback is disabled, return the error
	if !opts.FallbackEnabled || len(opts.FallbackOrder) == 0 {
		return nil, err
	}

	// Try fallback modes in order
	for _, fallbackName := range opts.FallbackOrder {
		fallbackMode := ParsePlatformMode(fallbackName)
		if fallbackMode == ModeAuto || fallbackMode == mode {
			continue // Skip auto and the already-tried mode
		}

		plat, fallbackErr := NewWithMode(fallbackMode)
		if fallbackErr == nil {
			return plat, nil
		}
	}

	// All fallbacks failed, return original error
	return nil, fmt.Errorf("platform %s failed: %w (no fallbacks available)", mode, err)
}

// NewWithMode creates a platform with a specific mode.
// Use ModeAuto to let the system choose the best implementation.
func NewWithMode(mode PlatformMode) (Platform, error) {
	if mode == ModeAuto {
		mode = detectPlatformMode()
	}

	switch mode {
	case ModeLinuxNative:
		return newLinuxPlatform()
	default:
		return nil, fmt.Errorf("unsupported platform mode: %v", mode)
	}
}

// detectPlatformMode determines the best platform mode for the current system.
// Only the Linux implementation exists.
func detectPlatformMode() PlatformMode {
	return ModeLinuxNative
}

// Detect returns information about the current platform without creating it.
// Useful for capability checking before initialization.
func Detect() (PlatformMode, Capabilities, error) {
	mode := detectPlatformMode()

	// Create a temporary platform to get capabilities
	plat, err := NewWithMode(mode)
	if err != nil {
		return mode, Capabilities{}, err
	}

	caps := plat.Capabilities()

	// Clean up - don't leave resources allocated
	// (Platform hasn't been initialized, so just discard)

	return mode, caps, nil
}

// MustNew is like New but panics on error.
// Useful in tests and initialization code.
func MustNew() Platform {
	p, err := New()
	if err != nil {
		panic(fmt.Sprintf("platform.New: %v", err))
	}
	return p
}

// MustNewWithMode is like NewWithMode but panics on error.
func MustNewWithMode(mode PlatformMode) Platform {
	p, err := NewWithMode(mode)
	if err != nil {
		panic(fmt.Sprintf("platform.NewWithMode(%v): %v", mode, err))
	}
	return p
}

// Platform constructor functions - implemented in platform-specific files.
// These are variables so they can be set by build-tag-specific files.

var newLinuxPlatform func() (Platform, error)

// RegisterLinux registers the Linux platform constructor.
// The linux package calls this from its init().
func RegisterLinux(constructor func() (Platform, error)) {
	newLinuxPlatform = constructor
}

// platformNotImplemented returns an error for unimplemented platforms.
func platformNotImplemented(name string) (Platform, error) {
	return nil, fmt.Errorf("platform %q not implemented on %s/%s", name, runtime.GOOS, runtime.GOARCH)
}

// init sets up fallback implementations for platforms that aren't compiled in.
func init() {
	if newLinuxPlatform == nil {
		newLinuxPlatform = func() (Platform, error) {
			return platformNotImplemented("linux")
		}
	}
}
