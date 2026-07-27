//go:build windows

package api

import "syscall"

func getSubagentSysProcAttr() *syscall.SysProcAttr {
	return getSysProcAttr()
}
