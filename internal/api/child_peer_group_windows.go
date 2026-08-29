//go:build !linux && !darwin

package api

func childPeerInProcessGroup(pid, processGroupID int) bool { return false }
