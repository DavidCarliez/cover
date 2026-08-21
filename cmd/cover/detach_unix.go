//go:build !windows

package main

import "syscall"

// detachSysProcAttr returns SysProcAttr settings that start the detached
// background process in its own session, so it survives the parent
// terminal exiting.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
