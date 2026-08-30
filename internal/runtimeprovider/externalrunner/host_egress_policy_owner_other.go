//go:build !linux

package externalrunner

import "os"

func operatorPolicyOwnerTrusted(string, os.FileInfo) bool { return true }
