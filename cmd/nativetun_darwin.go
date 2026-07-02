//go:build darwin

package cmd

import (
	"fmt"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"golang.zx2c4.com/wireguard/tun"
)

var longDescription = "Expose Warp as a native TUN device that accepts any IP traffic." +
	" Requires root."

// macOS utun devices prepend a 4-byte address-family header; wireguard-go/tun
// exposes it as a read/write offset that the shared NetstackAdapter strips.
const darwinTunOffset = 4

func (t *tunDevice) create() (api.TunnelDevice, error) {
	if t.name == "" {
		t.name = "utun"
	}

	dev, err := tun.CreateTUN(t.name, t.mtu)
	if err != nil {
		return nil, err
	}

	t.name, err = dev.Name()
	if err != nil {
		return nil, err
	}

	if t.ipv4 {
		if err := internal.SetIPv4Address(t.name, config.AppConfig.IPv4, "255.255.255.255"); err != nil {
			return nil, fmt.Errorf("failed to set IPv4 address: %v", err)
		}
		if err := internal.SetIPv4MTU(t.name, t.mtu); err != nil {
			return nil, fmt.Errorf("failed to set IPv4 MTU: %v", err)
		}
	}

	if t.ipv6 {
		if err := internal.SetIPv6Address(t.name, config.AppConfig.IPv6, "128"); err != nil {
			return nil, fmt.Errorf("failed to set IPv6 address: %v", err)
		}
		if err := internal.SetIPv6MTU(t.name, t.mtu); err != nil {
			return nil, fmt.Errorf("failed to set IPv6 MTU: %v", err)
		}
	}

	if err := internal.SetInterfaceUp(t.name); err != nil {
		return nil, fmt.Errorf("failed to bring interface up: %v", err)
	}

	return api.NewNetstackAdapterWithOffset(dev, darwinTunOffset), nil
}
