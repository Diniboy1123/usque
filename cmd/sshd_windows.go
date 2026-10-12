//go:build windows

package cmd

import (
	"os/exec"
	"os/user"
)

func setCmdUser(cmd *exec.Cmd, u *user.User, username string) {
	// Windows doesn't support Unix-style UID/GID credentials via SysProcAttr here
}