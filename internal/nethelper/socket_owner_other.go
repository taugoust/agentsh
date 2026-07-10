//go:build !linux && !windows

package nethelper

func protectedUnmappedRootOwner(string, uint32) bool { return false }
