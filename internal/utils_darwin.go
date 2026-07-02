//go:build darwin

package internal

import (
	"fmt"
	"log"
	"net"
	"os/exec"
)

// SetIPv4Address assigns a point-to-point IPv4 address to a utun interface via
// ifconfig. macOS needs the peer/destination set and an explicit prefix; a bare
// address otherwise defaults to a classful mask (e.g. /16) that breaks routing.
func SetIPv4Address(ifaceName, ipAddr, mask string) error {
	prefix := 32
	if m := net.IPMask(net.ParseIP(mask).To4()); m != nil {
		if ones, bits := m.Size(); bits == 32 {
			prefix = ones
		}
	}
	// utun is point-to-point: local and peer are the same tunnel address.
	cmd := exec.Command("ifconfig", ifaceName, "inet",
		fmt.Sprintf("%s/%d", ipAddr, prefix), ipAddr, "alias")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", output)
	}

	log.Println("IPv4 address set successfully:", ipAddr)
	return nil
}

func SetIPv6Address(ifaceName, ipAddr, mask string) error {
	cmd := exec.Command("ifconfig", ifaceName, "inet6", ipAddr, "prefixlen", mask, "alias")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", output)
	}

	log.Println("IPv6 address set successfully:", ipAddr)
	return nil
}

// SetIPv4MTU sets the interface MTU. On macOS the MTU is per-interface (not
// per-address-family), so SetIPv6MTU is an alias for this.
func SetIPv4MTU(ifaceName string, mtu int) error {
	cmd := exec.Command("ifconfig", ifaceName, "mtu", fmt.Sprintf("%d", mtu))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", output)
	}

	log.Println("MTU set successfully:", mtu)
	return nil
}

func SetIPv6MTU(ifaceName string, mtu int) error {
	return SetIPv4MTU(ifaceName, mtu)
}

func SetInterfaceUp(ifaceName string) error {
	cmd := exec.Command("ifconfig", ifaceName, "up")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", output)
	}
	return nil
}
