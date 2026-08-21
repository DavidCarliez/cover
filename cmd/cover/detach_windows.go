//go:build windows

package main

import "syscall"

const (
	detachedProcess       = 0x00000008
	createNewProcessGroup = 0x00000200
)

// detachSysProcAttr returns SysProcAttr settings that start the detached
// background process without a console window and outside the parent's
// process group, so it survives the parent terminal exiting.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: detachedProcess | createNewProcessGroup,
		HideWindow:    true,
	}
}
