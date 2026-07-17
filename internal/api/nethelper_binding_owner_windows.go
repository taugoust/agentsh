//go:build windows

package api

import "os"

func helperCurrentUIDGID() (uint32, uint32, bool)   { return 0, 0, false }
func helperPathOwnedByUID(os.FileInfo, uint32) bool { return false }
func helperPathOwnedByCurrentUser(os.FileInfo) bool { return false }
