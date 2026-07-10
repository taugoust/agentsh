//go:build !linux

package nethelper

// ValidateCredentialFileOwnership is a Linux production-service check. The
// helper itself is unavailable on other platforms.
func ValidateCredentialFileOwnership(string) error { return nil }
