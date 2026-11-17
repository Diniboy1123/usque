package cmd

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var portFwCmd = &cobra.Command{
	Use:   "portfw",
	Short: "Forward ports through a MASQUE tunnel",
	Long: "This tool is useful if you have Cloudflare Zero Trust Gateway enabled and want to forward ports to/from the tunnel." +
		" It creates a virtual TUN device and forward ports through it either from or to the client. It works a bit like SSH port forwarding. TCP only at the moment." +
		"Doesn't require elevated privileges.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		if !config.ConfigLoaded {
			return fmt.Errorf("config not loaded; please register first")
		}

		sni, err := cmd.Flags().GetString("sni-address")
		if err != nil {
			return fmt.Errorf("failed to get SNI address: %w", err)
		}

		privKey, err := config.AppConfig.GetEcPrivateKey()
		if err != nil {
			return fmt.Errorf("failed to get private key: %w", err)
		}
		peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
		if err != nil {
			return fmt.Errorf("failed to get public key: %w", err)
		}

		cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to generate cert: %w", err)
		}

		insecure, err := cmd.Flags().GetBool("insecure")
		if err != nil {
			return fmt.Errorf("failed to get insecure flag: %w", err)
		}

		tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni, insecure)
		if err != nil {
			return fmt.Errorf("failed to prepare TLS config: %w", err)
		}

		keepalivePeriod, err := cmd.Flags().GetDuration("keepalive-period")
		if err != nil {
			return fmt.Errorf("failed to get keepalive period: %w", err)
		}
		initialPacketSize, err := cmd.Flags().GetUint16("initial-packet-size")
		if err != nil {
			return fmt.Errorf("failed to get initial packet size: %w", err)
		}

		connectPort, err := cmd.Flags().GetInt("connect-port")
		if err != nil {
			return fmt.Errorf("failed to get connect port: %w", err)
		}

		useHTTP2, err := cmd.Flags().GetBool("http2")
		if err != nil {
			return fmt.Errorf("failed to get HTTP/2 flag: %w", err)
		}

		useIPv6, err := cmd.Flags().GetBool("ipv6")
		if err != nil {
			return fmt.Errorf("failed to get ipv6 flag: %w", err)
		}

		endpoint, err := config.SelectEndpointFromConfig(useHTTP2, useIPv6, connectPort)
		if err != nil {
			return fmt.Errorf("failed to select endpoint: %w", err)
		}

		if insecure {
			config.WarnInsecure()
		}

		if useHTTP2 {
			config.LogHTTP2Endpoint(endpoint)
		}

		tunnelIPv4, err := cmd.Flags().GetBool("no-tunnel-ipv4")
		if err != nil {
			return fmt.Errorf("failed to get no tunnel IPv4: %w", err)
		}

		tunnelIPv6, err := cmd.Flags().GetBool("no-tunnel-ipv6")
		if err != nil {
			return fmt.Errorf("failed to get no tunnel IPv6: %w", err)
		}

		var localAddresses []netip.Addr
		if !tunnelIPv4 {
			v4, err := netip.ParseAddr(config.AppConfig.IPv4)
			if err != nil {
				return fmt.Errorf("failed to parse IPv4 address: %w", err)
			}
			localAddresses = append(localAddresses, v4)
		}
		if !tunnelIPv6 {
			v6, err := netip.ParseAddr(config.AppConfig.IPv6)
			if err != nil {
				return fmt.Errorf("failed to parse IPv6 address: %w", err)
			}
			localAddresses = append(localAddresses, v6)
		}

		dnsServers, err := cmd.Flags().GetStringArray("dns")
		if err != nil {
			return fmt.Errorf("failed to get DNS servers: %w", err)
		}

		var dnsAddrs []netip.Addr
		for _, dns := range dnsServers {
			addr, err := netip.ParseAddr(dns)
			if err != nil {
				return fmt.Errorf("failed to parse DNS server: %w", err)
			}
			dnsAddrs = append(dnsAddrs, addr)
		}

		mtu, err := cmd.Flags().GetInt("mtu")
		if err != nil {
			return fmt.Errorf("failed to get MTU: %w", err)
		}
		if mtu != 1280 {
			log.Println("Warning: MTU is not the default 1280. This is not supported. Packet loss and other issues may occur.")
		}

		localPorts, err := cmd.Flags().GetStringArray("local-ports")
		if err != nil {
			return fmt.Errorf("failed to get local ports: %w", err)
		}

		remotePorts, err := cmd.Flags().GetStringArray("remote-ports")
		if err != nil {
			return fmt.Errorf("failed to get remote ports: %w", err)
		}

		var localPortMappings []internal.PortMapping
		var remotePortMappings []internal.PortMapping

		for _, port := range localPorts {
			portMapping, err := internal.ParsePortMapping(port)
			if err != nil {
				return fmt.Errorf("failed to parse local port mapping: %w", err)
			}
			localPortMappings = append(localPortMappings, portMapping)
		}

		for _, port := range remotePorts {
			portMapping, err := internal.ParsePortMapping(port)
			if err != nil {
				return fmt.Errorf("failed to parse remote port mapping: %w", err)
			}
			remotePortMappings = append(remotePortMappings, portMapping)
		}

		reconnectDelay, err := cmd.Flags().GetDuration("reconnect-delay")
		if err != nil {
			return fmt.Errorf("failed to get reconnect delay: %w", err)
		}

		alwaysReconnect := true
		alwaysChanged := cmd.Flags().Changed("always-reconnect")
		dontAlwaysChanged := cmd.Flags().Changed("dont-always-reconnect")
		if alwaysChanged && dontAlwaysChanged {
			return fmt.Errorf("use either --always-reconnect or --dont-always-reconnect, not both")
		}
		if alwaysChanged {
			alwaysReconnect, err = cmd.Flags().GetBool("always-reconnect")
			if err != nil {
				return fmt.Errorf("failed to get always-reconnect flag: %w", err)
			}
		}
		if dontAlwaysChanged {
			dontAlwaysReconnect, err := cmd.Flags().GetBool("dont-always-reconnect")
			if err != nil {
				return fmt.Errorf("failed to get dont-always-reconnect flag: %w", err)
			}
			alwaysReconnect = !dontAlwaysReconnect
		}

		onConnect, err := cmd.Flags().GetString("on-connect")
		if err != nil {
			return fmt.Errorf("failed to get on-connect flag: %w", err)
		}

		onDisconnect, err := cmd.Flags().GetString("on-disconnect")
		if err != nil {
			return fmt.Errorf("failed to get on-disconnect flag: %w", err)
		}

		hookEnv := map[string]string{
			"USQUE_MODE": "portfw",
			"USQUE_IPV4": config.AppConfig.IPv4,
			"USQUE_IPV6": config.AppConfig.IPv6,
		}

		tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, mtu)
		if err != nil {
			return fmt.Errorf("failed to create virtual TUN device: %w", err)
		}
		defer func() { _ = tunDev.Close() }()

		type forwarding struct {
			listener net.Listener
			mapping  internal.PortMapping
			remote   bool
		}
		var forwards []forwarding
		stop := make(chan struct{})
		defer func() {
			close(stop)
			for _, f := range forwards {
				_ = f.listener.Close()
			}
		}()
		for _, group := range []struct {
			mappings []internal.PortMapping
			remote   bool
		}{
			{localPortMappings, false}, {remotePortMappings, true},
		} {
			for _, pm := range group.mappings {
				listener, err := listenForwardPort(tunNet, pm, group.remote)
				if err != nil {
					return err
				}
				forwards = append(forwards, forwarding{listener, pm, group.remote})
			}
		}

		go api.MaintainTunnel(context.Background(), api.MaintainTunnelConfig{
			TLSConfig:         tlsConfig,
			KeepalivePeriod:   keepalivePeriod,
			InitialPacketSize: initialPacketSize,
			Endpoint:          endpoint,
			Device:            api.NewNetstackAdapter(tunDev),
			MTU:               mtu,
			ReconnectDelay:    reconnectDelay,
			AlwaysReconnect:   alwaysReconnect,
			UseHTTP2:          useHTTP2,
			OnConnect:         onConnect,
			OnDisconnect:      onDisconnect,
			HookEnv:           hookEnv,
		})

		log.Printf("Virtual tunnel created, forwarding ports")

		for _, f := range forwards {
			go forwardPort(f.listener, tunNet, f.mapping, f.remote, stop)
		}

		// One packet must be sent in order to listen for incoming packets
		// a ping may suffice as well, but we will use a simple GET request
		client := &http.Client{
			Transport: &http.Transport{
				DialContext: tunNet.DialContext,
			},
		}
		resp, err := client.Get("https://cloudflareok.com/test")
		if err != nil {
			cmd.Printf("Failed to make request to cloudflare.com: %v\n", err)
			return nil
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != 204 {
			cmd.Printf("Failed to make request to cloudflare.com: %s\n", resp.Status)
			return nil
		}
		log.Println("Successfully connected to Cloudflare")

		select {}
	},
}

// listenForwardPort binds before maintenance starts so a failed mapping can
// roll back all listeners without dialing the MASQUE endpoint.
func listenForwardPort(netstackNet *netstack.Net, pm internal.PortMapping, isRemote bool) (net.Listener, error) {
	addr := net.JoinHostPort(pm.BindAddress, fmt.Sprint(pm.LocalPort))
	local, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid local address: %w", err)
	}
	var listener net.Listener
	if isRemote {
		listener, err = netstackNet.ListenTCPAddrPort(local)
	} else {
		listener, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	return listener, nil
}

// forwardPort serves an already-bound listener. stop is closed before the owner
// closes its listeners; virtual listeners do not wrap net.ErrClosed.
func forwardPort(listener net.Listener, netstackNet *netstack.Net, pm internal.PortMapping, isRemote bool, stop <-chan struct{}) {
	addr := fmt.Sprintf("%s:%d", pm.BindAddress, pm.LocalPort)
	if isRemote {
		log.Printf("Remote forwarding: Listening on MASQUE network %s, forwarding to local %s:%d", addr, pm.RemoteIP, pm.RemotePort)
	} else {
		log.Printf("Local forwarding: Listening on %s, forwarding to remote %s:%d", addr, pm.RemoteIP, pm.RemotePort)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-stop:
				return
			default:
				log.Printf("Accept error on %s: %v", addr, err)
				continue
			}
		}
		go handleConnection(conn, pm, isRemote, netstackNet)
	}
}

// handleConnection manages an individual forwarded connection between the local and remote endpoints.
//
// Parameters:
//   - localConn: net.Conn - The connection from the source (client).
//   - pm: internal.PortMapping - The port mapping configuration.
//   - isRemote: bool - Indicates whether the connection is remote-forwarded.
//   - tunNet: *netstack.Net - The network stack used for making remote connections.
func handleConnection(localConn net.Conn, pm internal.PortMapping, isRemote bool, tunNet *netstack.Net) {
	defer func() { _ = localConn.Close() }()

	remoteAddrPort, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", pm.RemoteIP, pm.RemotePort))
	if err != nil {
		log.Printf("Invalid remote address: %v", err)
		return
	}

	var remoteConn net.Conn
	if isRemote {
		// Remote forwarding: Connect to the external remote host
		remoteConn, err = net.Dial("tcp", remoteAddrPort.String())
	} else {
		// Local forwarding: Connect inside the tunnel network
		remoteConn, err = tunNet.DialContext(context.Background(), "tcp", remoteAddrPort.String())
	}

	if err != nil {
		log.Printf("Failed to connect to remote %s: %v", remoteAddrPort, err)
		return
	}
	defer func() { _ = remoteConn.Close() }()

	go func() { _, _ = io.Copy(remoteConn, localConn) }()
	_, _ = io.Copy(localConn, remoteConn)
}

func init() {
	portFwCmd.Flags().StringArrayP("local-ports", "L", []string{}, "List of port mappings to forward (SSH like e.g. localhost:8080:100.96.0.2:8080)")
	portFwCmd.Flags().StringArrayP("remote-ports", "R", []string{}, "List of port mappings to forward (SSH like e.g. 100.96.0.3:8080:localhost:8080)")
	portFwCmd.Flags().IntP("connect-port", "P", 443, "Used port for MASQUE connection")
	portFwCmd.Flags().StringArrayP("dns", "d", []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"}, "DNS servers to use inside the MASQUE tunnel")
	portFwCmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 for MASQUE connection")
	portFwCmd.Flags().BoolP("no-tunnel-ipv4", "F", false, "Disable IPv4 inside the MASQUE tunnel")
	portFwCmd.Flags().BoolP("no-tunnel-ipv6", "S", false, "Disable IPv6 inside the MASQUE tunnel")
	portFwCmd.Flags().StringP("sni-address", "s", internal.ConnectSNI, "SNI address to use for MASQUE connection")
	portFwCmd.Flags().DurationP("keepalive-period", "k", 30*time.Second, "Keepalive period for MASQUE connection")
	portFwCmd.Flags().IntP("mtu", "m", 1280, "MTU for MASQUE connection")
	portFwCmd.Flags().Uint16P("initial-packet-size", "i", 0, "Custom initial packet size for MASQUE connection (default: auto with PMTU discovery)")
	portFwCmd.Flags().DurationP("reconnect-delay", "r", 1*time.Second, "Delay between reconnect attempts")
	portFwCmd.Flags().Bool("http2", false, "Use HTTP/2 over TCP+TLS instead of HTTP/3 over QUIC."+config.EndpointHelpSuffixH2)
	portFwCmd.Flags().Bool("insecure", false, "Disable endpoint certificate pinning and trust any certificate")
	portFwCmd.Flags().Bool("always-reconnect", false, "Always reconnect after tunnel loss, even when idle (default behavior in portfw)")
	portFwCmd.Flags().Bool("dont-always-reconnect", false, "Disable always reconnect in portfw; reconnect only when new activity arrives")
	portFwCmd.Flags().String("on-connect", "", "Path to an executable to run after each successful tunnel connect (no args; context via USQUE_* env vars)")
	portFwCmd.Flags().String("on-disconnect", "", "Path to an executable to run after each tunnel disconnect (no args; context via USQUE_* env vars)")
	rootCmd.AddCommand(portFwCmd)
}
