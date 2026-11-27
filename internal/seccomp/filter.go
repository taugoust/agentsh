//go:build linux && cgo

package seccomp

// FilterConfig holds settings for building a seccomp filter.
type FilterConfig struct {
	UnixSocketEnabled bool
	BlockedSyscalls   []string
	BlockedFamilies   []BlockedFamily
	SocketRules       []SocketRule
	OnBlock           OnBlockAction
}
