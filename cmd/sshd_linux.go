//go:build linux || darwin || freebsd

package cmd

import (
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

func setCmdUser(cmd *exec.Cmd, u *user.User, username string) {
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 == nil && err2 == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
		}
	}
}