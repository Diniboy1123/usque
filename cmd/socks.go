package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"reflect"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
	"github.com/things-go/go-socks5"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var socksCmd = &cobra.Command{
	Use:   "socks",
	Short: "Expose Warp as a SOCKS5 proxy",
	Long:  "Dual-stack SOCKS5 proxy with optional authentication. Doesn't require elevated privileges.",
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}

		s := newSocksServerConfig()
		useFileCfgPath, err := cmd.Flags().GetString("settings")
		if useFileCfgPath == "" || err != nil {

			if err := s.ReadFromCmd(cmd); err != nil {
				cmd.Printf("Failed to read SOCKS server config: %v\n", err)
				return
			}
		} else {
			cmd.Printf("Using settings: %s\n", useFileCfgPath)

			if err := s.ReadFromFile(useFileCfgPath); err != nil {
				cmd.Printf("Failed to read SOCKS server config: %v\n", err)
				return
			}
		}

		var localAddresses []netip.Addr
		if !s.NoTunnelIPv4 {
			v4, err := netip.ParseAddr(config.AppConfig.IPv4)
			if err != nil {
				cmd.Printf("Failed to parse IPv4 address: %v\n", err)
				return
			}
			localAddresses = append(localAddresses, v4)
		}
		if !s.NoTunnelIPv6 {
			v6, err := netip.ParseAddr(config.AppConfig.IPv6)
			if err != nil {
				cmd.Printf("Failed to parse IPv6 address: %v\n", err)
				return
			}
			localAddresses = append(localAddresses, v6)
		}

		privKey, err := config.AppConfig.GetEcPrivateKey()
		if err != nil {
			cmd.Printf("Failed to get private key: %v\n", err)
			return
		}
		peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
		if err != nil {
			cmd.Printf("Failed to get public key: %v\n", err)
			return
		}

		cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
		if err != nil {
			cmd.Printf("Failed to generate cert: %v\n", err)
			return
		}

		tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, s.SNIAddress)
		if err != nil {
			cmd.Printf("Failed to prepare TLS config: %v\n", err)
			return
		}

		var endpoint *net.UDPAddr
		if s.IPv6 {
			endpoint = &net.UDPAddr{
				IP:   net.ParseIP(config.AppConfig.EndpointV6),
				Port: s.ConnectPort,
			}
		} else {
			endpoint = &net.UDPAddr{
				IP:   net.ParseIP(config.AppConfig.EndpointV4),
				Port: s.ConnectPort,
			}
		}

		var dnsAddrs []netip.Addr
		for _, dns := range s.DNSServers {
			addr, err := netip.ParseAddr(dns)
			if err != nil {
				cmd.Printf("Failed to parse DNS server: %v\n", err)
				return
			}
			dnsAddrs = append(dnsAddrs, addr)
		}

		tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, s.MTU)
		if err != nil {
			cmd.Printf("Failed to create virtual TUN device: %v\n", err)
			return
		}
		defer tunDev.Close()

		go api.MaintainTunnel(context.Background(), tlsConfig, s.KeepalivePeriod, s.InitialPacketSize, endpoint, api.NewNetstackAdapter(tunDev), s.MTU, s.ReconnectDelay)

		var server *socks5.Server
		if s.Username == "" || s.Password == "" {
			server = socks5.NewServer(
				socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
				socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
					return tunNet.DialContext(ctx, network, addr)
				}),
				socks5.WithResolver(TunnelDNSResolver{tunNet, dnsAddrs, s.DNSTimeout}),
			)
		} else {
			server = socks5.NewServer(
				socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
				socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
					return tunNet.DialContext(ctx, network, addr)
				}),
				socks5.WithResolver(TunnelDNSResolver{tunNet, dnsAddrs, s.DNSTimeout}),
				socks5.WithAuthMethods(
					[]socks5.Authenticator{
						socks5.UserPassAuthenticator{
							Credentials: socks5.StaticCredentials{
								s.Username: s.Password,
							},
						},
					},
				),
			)
		}

		log.Printf("SOCKS proxy listening on %s:%s", s.BindAddress, s.Port)
		if err := server.ListenAndServe("tcp", net.JoinHostPort(s.BindAddress, s.Port)); err != nil {
			cmd.Printf("Failed to start SOCKS proxy: %v\n", err)
			return
		}
	},
}

// TunnelDNSResolver implements a DNS resolver that uses the provided DNS servers inside a MASQUE tunnel.
type TunnelDNSResolver struct {
	// tunNet is the network stack for the tunnel you want to use for DNS resolution.
	tunNet *netstack.Net
	// dnsAddrs is the list of DNS servers to use for resolution.
	dnsAddrs []netip.Addr
	// timeout is the timeout for DNS queries on a specific server before trying the next one.
	timeout time.Duration
}

// Resolve performs a DNS lookup using the provided DNS resolvers.
// It tries each resolver in order until one succeeds.
//
// Parameters:
//   - ctx: context.Context - The context for the DNS lookup.
//   - name: string - The domain name to resolve.
//
// Returns:
//   - context.Context: The context for the DNS lookup.
//   - net.IP: The resolved IP address.
//   - error: An error if the lookup fails.
func (r TunnelDNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	var lastErr error

	for _, dnsAddr := range r.dnsAddrs {
		dnsHost := net.JoinHostPort(dnsAddr.String(), "53")

		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return r.tunNet.DialContext(ctx, "udp", dnsHost)
			},
		}

		ips, err := resolver.LookupIP(ctx, "ip", name)
		if err == nil && len(ips) > 0 {
			return ctx, ips[0], nil
		}
		lastErr = err
	}

	return ctx, nil, fmt.Errorf("all DNS servers failed: %v", lastErr)
}

type SocksServerConfig struct {
	BindAddress       string        `json:"bindAddress" cmd:"bind" shorthand:"b"`
	Port              string        `json:"port" cmd:"port" shorthand:"p"`
	Username          string        `json:"username" cmd:"username"`
	Password          string        `json:"password" cmd:"password"`
	ConnectPort       int           `json:"connectPort" cmd:"connect-port"`
	DNSServers        []string      `json:"dnsServers" cmd:"dns"`
	DNSTimeout        time.Duration `json:"dnsTimeout" cmd:"dns-timeout"`
	IPv6              bool          `json:"ipv6" cmd:"ipv6"`
	NoTunnelIPv4      bool          `json:"noTunnelIPv4" cmd:"no-tunnel-ipv4"`
	NoTunnelIPv6      bool          `json:"noTunnelIPv6" cmd:"no-tunnel-ipv6"`
	SNIAddress        string        `json:"sniAddress" cmd:"sni-address"`
	KeepalivePeriod   time.Duration `json:"keepalivePeriod" cmd:"keepalive-period"`
	MTU               int           `json:"mtu" cmd:"mtu"`
	InitialPacketSize uint16        `json:"initialPacketSize" cmd:"initial-packet-size"`
	ReconnectDelay    time.Duration `json:"reconnectDelay" cmd:"reconnect-delay"`
}

func newSocksServerConfig() *SocksServerConfig {
	return &SocksServerConfig{
		BindAddress:       internal.DefaultSocksBindAddress,
		Port:              internal.DefaultSocksPort,
		Username:          "",
		Password:          "",
		ConnectPort:       internal.DefaultSocksConnectPort,
		DNSServers:        []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"},
		DNSTimeout:        internal.DefaultSocksDnsTimeout,
		IPv6:              false,
		NoTunnelIPv4:      false,
		NoTunnelIPv6:      false,
		SNIAddress:        internal.ConnectSNI,
		KeepalivePeriod:   internal.DefaultSocksKeepalivePeriod,
		MTU:               internal.DefaultSocksMTU,
		InitialPacketSize: internal.DefaultSocksInitialPacketSize,
		ReconnectDelay:    internal.DefaultSocksReconnectDelay,
	}
}

// ReadFromCmd reads the configuration from command line flags.
func (s *SocksServerConfig) ReadFromCmd(cmd *cobra.Command) error {
	cmdAutoGet := func(cmd *cobra.Command, name string, typeName string) (interface{}, error) {
		switch typeName {
		case "string":
			return cmd.Flags().GetString(name)
		case "int":
			return cmd.Flags().GetInt(name)
		case "uint16":
			return cmd.Flags().GetUint16(name)
		case "bool":
			return cmd.Flags().GetBool(name)
		case "time.Duration":
			return cmd.Flags().GetDuration(name)
		case "[]string":
			return cmd.Flags().GetStringArray(name)
		default:
			return nil, fmt.Errorf("unsupported type %s", typeName)
		}
	}
	fields := reflect.TypeOf(*s)
	v := reflect.ValueOf(s).Elem()
	for i := 0; i < fields.NumField(); i++ {
		field := fields.Field(i)
		tag := field.Tag.Get("cmd")
		if tag == "" {
			continue
		}
		value, err := cmdAutoGet(cmd, tag, field.Type.String())
		if err != nil {
			return fmt.Errorf("failed to get flag %s: %v", tag, err)
		}

		v.Field(i).Set(reflect.ValueOf(value))
	}
	return nil
}

// ReadFromFile reads the configuration from a JSON file.
func (s *SocksServerConfig) ReadFromFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	if err = json.NewDecoder(file).Decode(s); err != nil {
		return err
	}

	if s.ReconnectDelay < internal.DefaultSocksReconnectDelay {
		s.ReconnectDelay = internal.DefaultSocksReconnectDelay
	}

	if s.KeepalivePeriod < internal.DefaultSocksKeepalivePeriod {
		s.KeepalivePeriod = internal.DefaultSocksKeepalivePeriod
	}

	if s.DNSTimeout < internal.DefaultSocksDnsTimeout {
		s.DNSTimeout = internal.DefaultSocksDnsTimeout
	}

	if len(s.DNSServers) == 0 {
		s.DNSServers = internal.DefaultSocksDnsServers
	}

	return nil
}

func init() {
	socksCmd.Flags().String("settings", "", "Path to JSON file with settings")
	// SocksServer Settings
	socksCmd.Flags().StringP("bind", "b", internal.DefaultSocksBindAddress, "Address to bind the SOCKS proxy to")
	socksCmd.Flags().StringP("port", "p", internal.DefaultSocksPort, "Port to listen on for SOCKS proxy")
	socksCmd.Flags().StringP("username", "u", "", "Username for proxy authentication (specify both username and password to enable)")
	socksCmd.Flags().StringP("password", "w", "", "Password for proxy authentication (specify both username and password to enable)")
	socksCmd.Flags().IntP("connect-port", "P", internal.DefaultSocksConnectPort, "Used port for MASQUE connection")
	socksCmd.Flags().StringArrayP("dns", "d", internal.DefaultSocksDnsServers, "DNS servers to use inside the MASQUE tunnel")
	socksCmd.Flags().DurationP("dns-timeout", "t", internal.DefaultSocksDnsTimeout, "Timeout for DNS queries on a specific server (tries the next server if exceeded)")
	socksCmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 for MASQUE connection")
	socksCmd.Flags().BoolP("no-tunnel-ipv4", "F", false, "Disable IPv4 inside the MASQUE tunnel")
	socksCmd.Flags().BoolP("no-tunnel-ipv6", "S", false, "Disable IPv6 inside the MASQUE tunnel")
	socksCmd.Flags().StringP("sni-address", "s", internal.ConnectSNI, "SNI address to use for MASQUE connection")
	socksCmd.Flags().DurationP("keepalive-period", "k", internal.DefaultSocksKeepalivePeriod, "Keepalive period for MASQUE connection")
	socksCmd.Flags().IntP("mtu", "m", internal.DefaultSocksMTU, "MTU for MASQUE connection")
	socksCmd.Flags().Uint16P("initial-packet-size", "i", internal.DefaultSocksInitialPacketSize, "Initial packet size for MASQUE connection")
	socksCmd.Flags().DurationP("reconnect-delay", "r", internal.DefaultSocksReconnectDelay, "Delay between reconnect attempts")
	rootCmd.AddCommand(socksCmd)
}
