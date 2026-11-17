package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/pflag"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// The command owns package globals; these tests deliberately do not run in parallel.
func startupConfig(t *testing.T, local, remote []string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	oldConfig, oldLoaded := config.AppConfig, config.ConfigLoaded
	oldSilence := portFwCmd.SilenceUsage
	oldSilenceErrors := portFwCmd.SilenceErrors
	config.AppConfig = config.Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(private),
		EndpointPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})),
		EndpointV4:     "127.0.0.1", EndpointH2V4: "127.0.0.1",
		IPv4: "100.64.0.2", IPv6: "fd00::2",
	}
	config.ConfigLoaded = true
	t.Cleanup(func() {
		config.AppConfig, config.ConfigLoaded = oldConfig, oldLoaded
		portFwCmd.SilenceUsage = oldSilence
		portFwCmd.SilenceErrors = oldSilenceErrors
	})
	for _, item := range []struct {
		name   string
		values []string
	}{
		{"local-ports", local}, {"remote-ports", remote},
	} {
		flag := portFwCmd.Flags().Lookup(item.name)
		previous, err := portFwCmd.Flags().GetStringArray(item.name)
		if err != nil {
			t.Fatal(err)
		}
		changed := flag.Changed
		if err := flag.Value.(pflag.SliceValue).Replace(item.values); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := flag.Value.(pflag.SliceValue).Replace(previous); err != nil {
				t.Error(err)
			}
			flag.Changed = changed
		})
	}
}

func TestPortfwStartupBusyPortReturnsError(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	mapping := fmt.Sprintf("127.0.0.1:%d:127.0.0.1:8443", busy.Addr().(*net.TCPAddr).Port)
	startupConfig(t, []string{mapping}, nil)
	// Valid dummy credentials let this reach binding, without any tunnel dial.
	err = portFwCmd.RunE(portFwCmd, nil)
	if err == nil || !strings.Contains(err.Error(), busy.Addr().String()) {
		t.Fatalf("expected occupied-port error, got %v", err)
	}
}

func TestPortfwStartupRollsBackEarlierListeners(t *testing.T) {
	for _, remoteFailure := range []bool{false, true} {
		t.Run(fmt.Sprintf("remote-failure=%t", remoteFailure), func(t *testing.T) {
			first, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			firstAddr := first.Addr().String()
			firstPort := first.Addr().(*net.TCPAddr).Port
			if err := first.Close(); err != nil {
				t.Fatal(err)
			}
			busy, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = busy.Close() }()
			local := []string{fmt.Sprintf("127.0.0.1:%d:127.0.0.1:8443", firstPort)}
			var remote []string
			expected := busy.Addr().String()
			if remoteFailure {
				// The second virtual listener collides in the same in-process stack.
				remote = []string{"100.64.0.2:8443:127.0.0.1:8443", "100.64.0.2:8443:127.0.0.1:8443"}
				expected = "100.64.0.2:8443"
			} else {
				local = append(local, fmt.Sprintf("127.0.0.1:%d:127.0.0.1:8443", busy.Addr().(*net.TCPAddr).Port))
			}
			startupConfig(t, local, remote)
			err = portFwCmd.RunE(portFwCmd, nil)
			if err == nil || !strings.Contains(err.Error(), expected) {
				t.Fatalf("expected later bind failure for %s, got %v", expected, err)
			}
			check, err := net.Listen("tcp", firstAddr)
			if err != nil {
				t.Fatalf("earlier listener was not rolled back: %v", err)
			}
			if err := check.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type acceptingListener struct {
	net.Listener
	entered chan struct{}
}

func (l acceptingListener) Accept() (net.Conn, error) {
	select {
	case l.entered <- struct{}{}:
	default:
	}
	return l.Listener.Accept()
}

func TestPortfwForwarderStopsAfterOwnerClosesListener(t *testing.T) {
	for _, remote := range []bool{false, true} {
		t.Run(fmt.Sprintf("remote=%t", remote), func(t *testing.T) {
			dev, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("100.64.0.2")}, nil, 1280)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = dev.Close() }()
			mapping := internal.PortMapping{BindAddress: "127.0.0.1"}
			if remote {
				mapping.BindAddress = "100.64.0.2"
			}
			listener, err := listenForwardPort(stack, mapping, remote)
			if err != nil {
				t.Fatal(err)
			}
			stop, done := make(chan struct{}), make(chan struct{})
			entered := make(chan struct{}, 1)
			go func() {
				defer close(done)
				forwardPort(acceptingListener{listener, entered}, stack, mapping, remote, stop)
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("forwarder did not enter Accept")
			}
			close(stop)
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("forwarder kept retrying its closed listener")
			}
		})
	}
}

func TestPortfwStartupConfigurationErrors(t *testing.T) {
	cases := []struct {
		name          string
		change        func()
		local, remote []string
		expected      string
	}{
		{name: "unregistered", change: func() { config.ConfigLoaded = false }, expected: "config not loaded"},
		{name: "private-key", change: func() { config.AppConfig.PrivateKey = "not-base64" }, expected: "private key"},
		{name: "endpoint-key", change: func() { config.AppConfig.EndpointPubKey = "not-PEM" }, expected: "public key"},
		{name: "endpoint-address", change: func() { config.AppConfig.EndpointV4 = "not-an-IP" }, expected: "endpoint_v4"},
		{name: "local-mapping", local: []string{"invalid"}, expected: "local port mapping"},
		{name: "remote-mapping", remote: []string{"invalid"}, expected: "remote port mapping"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			startupConfig(t, tc.local, tc.remote)
			if tc.change != nil {
				tc.change()
			}
			err := portFwCmd.RunE(portFwCmd, nil)
			if err == nil || !strings.Contains(err.Error(), tc.expected) {
				t.Fatalf("expected %s startup error, got %v", tc.expected, err)
			}
		})
	}
}

func TestPortfwBindsNormalizedIPv6Address(t *testing.T) {
	// ParsePortMapping resolves and normalizes bind addresses to IP.String(),
	// without brackets. Binding must add brackets back for an IPv6 address.
	dev, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("fd00::2")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dev.Close() }()
	mapping := internal.PortMapping{BindAddress: "fd00::2"}
	listener, err := listenForwardPort(stack, mapping, true)
	if err != nil {
		t.Fatalf("normalized IPv6 bind failed: %v", err)
	}
	defer func() { _ = listener.Close() }()
	if !strings.HasPrefix(listener.Addr().String(), "[fd00::2]:") {
		t.Fatalf("unexpected bound address %s", listener.Addr())
	}
}
