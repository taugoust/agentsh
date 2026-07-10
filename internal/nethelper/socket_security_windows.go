//go:build windows

package nethelper

func validateListenSocketPath(string) error   { return nil }
func validateSocketParent(string) error       { return nil }
func validateSocketFileSecurity(string) error                     { return nil }
func validateSocketFileOwner(string, uint32, bool) error           { return nil }
func validateClientSocketPath(string) error                        { return nil }
