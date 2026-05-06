package cmd

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
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
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}

		sni, err := cmd.Flags().GetString("sni-address")
		if err != nil {
			cmd.Printf("Failed to get SNI address: %v\n", err)
			return
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

		insecure, err := cmd.Flags().GetBool("insecure")
		if err != nil {
			cmd.Printf("Failed to get insecure flag: %v\n", err)
			return
		}

		tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni, insecure)
		if err != nil {
			cmd.Printf("Failed to prepare TLS config: %v\n", err)
			return
		}

		keepalivePeriod, err := cmd.Flags().GetDuration("keepalive-period")
		if err != nil {
			cmd.Printf("Failed to get keepalive period: %v\n", err)
			return
		}
		initialPacketSize, err := cmd.Flags().GetUint16("initial-packet-size")
		if err != nil {
			cmd.Printf("Failed to get initial packet size: %v\n", err)
			return
		}

		connectPort, err := cmd.Flags().GetInt("connect-port")
		if err != nil {
			cmd.Printf("Failed to get connect port: %v\n", err)
			return
		}

		useHTTP2, err := cmd.Flags().GetBool("http2")
		if err != nil {
			cmd.Printf("Failed to get HTTP/2 flag: %v\n", err)
			return
		}

		useIPv6, err := cmd.Flags().GetBool("ipv6")
		if err != nil {
			cmd.Printf("Failed to get ipv6 flag: %v\n", err)
			return
		}

		endpoint, err := config.SelectEndpointFromConfig(useHTTP2, useIPv6, connectPort)
		if err != nil {
			cmd.Printf("Failed to select endpoint: %v\n", err)
			return
		}

		if insecure {
			config.WarnInsecure()
		}

		if useHTTP2 {
			config.LogHTTP2Endpoint(endpoint)
		}

		tunnelIPv4, err := cmd.Flags().GetBool("no-tunnel-ipv4")
		if err != nil {
			cmd.Printf("Failed to get no tunnel IPv4: %v\n", err)
			return
		}

		tunnelIPv6, err := cmd.Flags().GetBool("no-tunnel-ipv6")
		if err != nil {
			cmd.Printf("Failed to get no tunnel IPv6: %v\n", err)
			return
		}

		var localAddresses []netip.Addr
		if !tunnelIPv4 {
			v4, err := netip.ParseAddr(config.AppConfig.IPv4)
			if err != nil {
				cmd.Printf("Failed to parse IPv4 address: %v\n", err)
				return
			}
			localAddresses = append(localAddresses, v4)
		}
		if !tunnelIPv6 {
			v6, err := netip.ParseAddr(config.AppConfig.IPv6)
			if err != nil {
				cmd.Printf("Failed to parse IPv6 address: %v\n", err)
				return
			}
			localAddresses = append(localAddresses, v6)
		}

		dnsServers, err := cmd.Flags().GetStringArray("dns")
		if err != nil {
			cmd.Printf("Failed to get DNS servers: %v\n", err)
			return
		}

		var dnsAddrs []netip.Addr
		for _, dns := range dnsServers {
			addr, err := netip.ParseAddr(dns)
			if err != nil {
				cmd.Printf("Failed to parse DNS server: %v\n", err)
				return
			}
			dnsAddrs = append(dnsAddrs, addr)
		}

		mtu, err := cmd.Flags().GetInt("mtu")
		if err != nil {
			cmd.Printf("Failed to get MTU: %v\n", err)
			return
		}
		if mtu != 1280 {
			log.Println("Warning: MTU is not the default 1280. This is not supported. Packet loss and other issues may occur.")
		}

		localPorts, err := cmd.Flags().GetStringArray("local-ports")
		if err != nil {
			cmd.Printf("Failed to get local ports: %v\n", err)
			return
		}

		remotePorts, err := cmd.Flags().GetStringArray("remote-ports")
		if err != nil {
			cmd.Printf("Failed to get remote ports: %v\n", err)
			return
		}

		var localPortMappings []internal.PortMapping
		var remotePortMappings []internal.PortMapping

		for _, port := range localPorts {
			portMapping, err := internal.ParsePortMapping(port)
			if err != nil {
				cmd.Printf("Failed to parse local port mapping: %v\n", err)
				return
			}
			localPortMappings = append(localPortMappings, portMapping)
		}

		for _, port := range remotePorts {
			portMapping, err := internal.ParsePortMapping(port)
			if err != nil {
				cmd.Printf("Failed to parse remote port mapping: %v\n", err)
				return
			}
			remotePortMappings = append(remotePortMappings, portMapping)
		}

		reconnectDelay, err := cmd.Flags().GetDuration("reconnect-delay")
		if err != nil {
			cmd.Printf("Failed to get reconnect delay: %v\n", err)
			return
		}

		alwaysReconnect := true
		alwaysChanged := cmd.Flags().Changed("always-reconnect")
		dontAlwaysChanged := cmd.Flags().Changed("dont-always-reconnect")
		if alwaysChanged && dontAlwaysChanged {
			cmd.Printf("Use either --always-reconnect or --dont-always-reconnect, not both\n")
			return
		}
		if alwaysChanged {
			alwaysReconnect, err = cmd.Flags().GetBool("always-reconnect")
			if err != nil {
				cmd.Printf("Failed to get always-reconnect flag: %v\n", err)
				return
			}
		}
		if dontAlwaysChanged {
			dontAlwaysReconnect, err := cmd.Flags().GetBool("dont-always-reconnect")
			if err != nil {
				cmd.Printf("Failed to get dont-always-reconnect flag: %v\n", err)
				return
			}
			alwaysReconnect = !dontAlwaysReconnect
		}

		onConnect, err := cmd.Flags().GetString("on-connect")
		if err != nil {
			cmd.Printf("Failed to get on-connect flag: %v\n", err)
			return
		}

		onDisconnect, err := cmd.Flags().GetString("on-disconnect")
		if err != nil {
			cmd.Printf("Failed to get on-disconnect flag: %v\n", err)
			return
		}

		udp, err := cmd.Flags().GetBool("udp")
		if err != nil {
			cmd.Printf("Failed to get udp flag: %v\n", err)
			return
		}

		hookEnv := map[string]string{
			"USQUE_MODE": "portfw",
			"USQUE_IPV4": config.AppConfig.IPv4,
			"USQUE_IPV6": config.AppConfig.IPv6,
		}

		tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, mtu)
		if err != nil {
			cmd.Printf("Failed to create virtual TUN device: %v\n", err)
			return
		}
		defer func() { _ = tunDev.Close() }()

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

		// Start Local Port Forwarding (-L)
		for _, pm := range localPortMappings {
			go func(pm internal.PortMapping) {
				var err error
				if udp {
					err = forwardPortUdp(tunNet, pm, false) // false = local forwarding
				} else {
					err = forwardPort(tunNet, pm, false) // false = local forwarding
				}
				if err != nil {
					cmd.Printf("Error in local forwarding %d: %v\n", pm.LocalPort, err)
				}
			}(pm)
		}

		// Start Remote Port Forwarding (-R)
		for _, pm := range remotePortMappings {
			go func(pm internal.PortMapping) {
				var err error
				if udp {
					err = forwardPortUdp(tunNet, pm, true) // true = remote forwarding
				} else {
					err = forwardPort(tunNet, pm, true) // true = remote forwarding
				}
				if err != nil {
					cmd.Printf("Error in remote forwarding %d: %v\n", pm.LocalPort, err)
				}
			}(pm)
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
			return
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != 204 {
			cmd.Printf("Failed to make request to cloudflare.com: %s\n", resp.Status)
			return
		}
		log.Println("Successfully connected to Cloudflare")

		select {}
	},
}

// forwardPortUdp sets up a local or remote udp port forwarding using either the MASQUE tunnel or the local network.
//
// Parameters:
//   - netstackNet: *netstack.Net - The network stack used for handling remote forwarding.
//   - pm: internal.PortMapping - The port mapping configuration containing bind address, local port, remote IP, and remote port.
//   - isRemote: bool - Indicates whether the forwarding is remote (true) or local (false).
//
// Returns:
//   - error: An error if port forwarding fails; otherwise, nil.
func forwardPortUdp(netstackNet *netstack.Net, pm internal.PortMapping, isRemote bool) error {
	localAddrPort, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", pm.BindAddress, pm.LocalPort))
	if err != nil {
		return fmt.Errorf("invalid local address: %w", err)
	}

	remoteAddrPort, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", pm.RemoteIP, pm.RemotePort))
	if err != nil {
		log.Printf("Invalid remote address: %v", err)
		return fmt.Errorf("Invalid remote address: %w", err)
	}

	if isRemote {
		// Remote forwarding: Listen inside the MASQUE tunnel
		log.Printf("Remote forwarding: Listening on MASQUE network %s/udp, forwarding to local %s:%d", localAddrPort, pm.RemoteIP, pm.RemotePort)

		go udpRemoteForward(netstackNet, localAddrPort, remoteAddrPort.String())
	} else {
		// Local forwarding: Listen on local machine
		log.Printf("Local forwarding: Listening on %s:%d/udp, forwarding to remote %s:%d", pm.BindAddress, pm.LocalPort, pm.RemoteIP, pm.RemotePort)

		go udpForward(netstackNet, localAddrPort.String(), remoteAddrPort.String())
	}
	return nil
}

// udpForward listens for incoming UDP packets on a local address and
// forwards them to a remote destination via the provided netstack instance.
// It maintains sessions based on the client's source address.
func udpForward(tunNet *netstack.Net, localAddr string, remoteAddr string) {
	// 1. Listen on the UDP port on the host side
	pc, err := net.ListenPacket("udp", localAddr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP: %v", err)
	}
	defer func() { _ = pc.Close() }()

	// Map for session management (Source address -> netstack connection)
	sessions := make(map[string]net.Conn)
	var mu sync.Mutex

	buf := make([]byte, 1500)
	for {
		// 2. Receive packet on the host side
		n, clientAddr, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}

		mu.Lock()
		remoteConn, exists := sessions[clientAddr.String()]
		if !exists {
			// 3. If it's a new source, create a connection to the destination via netstack
			remoteConn, err = tunNet.DialContext(context.Background(), "udp", remoteAddr)
			if err != nil {
				log.Printf("Failed to dial remote: %v", err)
				mu.Unlock()
				continue
			}
			sessions[clientAddr.String()] = remoteConn

			// 4. Start a goroutine to send replies from the destination back to the client
			go func(cAddr net.Addr, rConn net.Conn) {
				defer func() {
					mu.Lock()
					delete(sessions, cAddr.String())
					mu.Unlock()
					_ = rConn.Close()
				}()

				resBuf := make([]byte, 1500)
				for {
					// Note: Session will persist unless a timeout is set
					err := rConn.SetReadDeadline(time.Now().Add(60 * time.Second))
					if err != nil {
						return
					}
					rn, err := rConn.Read(resBuf)
					if err != nil {
						return
					}
					// Send back to the client
					_, err = pc.WriteTo(resBuf[:rn], cAddr)
					if err != nil {
						return
					}
				}
			}(clientAddr, remoteConn)
		}
		mu.Unlock()

		// 5. Forward the packet to the destination
		_, err = remoteConn.Write(buf[:n])
		if err != nil {
			log.Printf("Failed to write to remote: %v", err)
		}
	}
}

// udpRemoteForward listens for UDP packets within the tunNet (tunnel network)
// and forwards them to a target address on the host side.
// It creates a reverse path to ensure replies from the target are routed
// back to the original sender inside the tunnel.
func udpRemoteForward(tunNet *netstack.Net, listenAddrPort netip.AddrPort, targetAddr string) {
	// 1. Listen on the IP and port within the WireGuard tunnel
	listener, err := tunNet.ListenUDPAddrPort(listenAddrPort)
	if err != nil {
		log.Fatalf("Tunnel listen failed: %v", err)
	}
	defer func() { _ = listener.Close() }()

	// Session management (Source -> UDP connection to the host side)
	sessions := make(map[string]*net.UDPConn)
	var mu sync.Mutex

	buf := make([]byte, 1500)
	for {
		// 2. Receive packet (from) within the tunnel
		n, remoteAddr, err := listener.ReadFrom(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			continue
		}

		mu.Lock()
		targetConn, exists := sessions[remoteAddr.String()]
		if !exists {
			// 3. Resolve the UDP address of the destination (e.g., host side)
			raddr, _ := net.ResolveUDPAddr("udp", targetAddr)
			// Create a socket to connect to the destination
			targetConn, err = net.DialUDP("udp", nil, raddr)
			if err != nil {
				log.Printf("Dial target failed: %v", err)
				mu.Unlock()
				continue
			}
			sessions[remoteAddr.String()] = targetConn

			// 4. Goroutine to return replies from the destination back into the tunnel
			go func(srcAddr net.Addr, tConn *net.UDPConn) {
				defer func() {
					mu.Lock()
					delete(sessions, srcAddr.String())
					mu.Unlock()
					_ = tConn.Close()
				}()

				resBuf := make([]byte, 1500)
				for {
					err := tConn.SetReadDeadline(time.Now().Add(60 * time.Second))
					if err != nil {
						return
					}
					rn, _, err := tConn.ReadFrom(resBuf)
					if err != nil {
						return
					}
					// Send back to the source within the tunnel
					_, err = listener.WriteTo(resBuf[:rn], srcAddr)
					if err != nil {
						return
					}
				}
			}(remoteAddr, targetConn)
		}
		mu.Unlock()

		// 5. Write the actual data to the destination
		_, err = targetConn.Write(buf[:n])
		if err != nil {
			return
		}
	}
}

// forwardPort sets up a local or remote port forwarding using either the MASQUE tunnel or the local network.
//
// Parameters:
//   - netstackNet: *netstack.Net - The network stack used for handling remote forwarding.
//   - pm: internal.PortMapping - The port mapping configuration containing bind address, local port, remote IP, and remote port.
//   - isRemote: bool - Indicates whether the forwarding is remote (true) or local (false).
//
// Returns:
//   - error: An error if port forwarding fails; otherwise, nil.
func forwardPort(netstackNet *netstack.Net, pm internal.PortMapping, isRemote bool) error {
	localAddrPort, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", pm.BindAddress, pm.LocalPort))
	if err != nil {
		return fmt.Errorf("invalid local address: %w", err)
	}

	if isRemote {
		// Remote forwarding: Listen inside the MASQUE tunnel
		listener, err := netstackNet.ListenTCPAddrPort(localAddrPort)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", localAddrPort, err)
		}
		defer func() { _ = listener.Close() }()

		log.Printf("Remote forwarding: Listening on MASQUE network %s, forwarding to local %s:%d", localAddrPort, pm.RemoteIP, pm.RemotePort)

		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Accept error on %s: %v", localAddrPort, err)
				continue
			}

			go handleConnection(conn, pm, isRemote, netstackNet)
		}
	} else {
		// Local forwarding: Listen on local machine
		listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", pm.BindAddress, pm.LocalPort))
		if err != nil {
			return fmt.Errorf("failed to listen on %s:%d: %w", pm.BindAddress, pm.LocalPort, err)
		}
		defer func() { _ = listener.Close() }()

		log.Printf("Local forwarding: Listening on %s:%d, forwarding to remote %s:%d", pm.BindAddress, pm.LocalPort, pm.RemoteIP, pm.RemotePort)

		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Accept error on %s:%d: %v", pm.BindAddress, pm.LocalPort, err)
				continue
			}

			go handleConnection(conn, pm, isRemote, netstackNet)
		}
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
	portFwCmd.Flags().BoolP("udp", "u", false, "Global protocol type for port mappings")
	rootCmd.AddCommand(portFwCmd)
}
