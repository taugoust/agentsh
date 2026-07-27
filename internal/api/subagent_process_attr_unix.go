//go:build !linux && !windows

package api

import "syscall"

func getSubagentSysProcAttr() *syscall.SysProcAttr {
	return getSysProcAttr()
}
