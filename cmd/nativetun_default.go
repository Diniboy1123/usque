//go:build !linux && !windows

package cmd

import (
	"errors"

	"github.com/Diniboy1123/usque/api"
)

var longDescription = "Expose Warp as a native TUN device that accepts any IP traffic." +
	" This command is not supported on your platform."

func (tun *tunDevice) create() (api.TunnelDevice, error) {
	return nil, errors.New("nativetun is not supported on this platform")
}
