package cmd

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// escapeFilterWriter strips ANSI/OSC/CSI escape sequences from output.
// This avoids leaking control sequences into terminals that do not interpret them
// (notably Windows conhost), while still allowing plain text through.
type escapeFilterWriter struct {
	w     io.Writer
	state escapeFilterState
}

type escapeFilterState int

const (
	escapeFilterNormal escapeFilterState = iota
	escapeFilterEscape
	escapeFilterCSI
	escapeFilterOSCString
	escapeFilterOSCStringESC
)

// Matches ANSI OSC sequences (window titles, etc.) but leaves CSI
// sequences alone so cursor movement and other control sequences
// can reach the local terminal when it supports them.
var ansiEscapeRegexp = regexp.MustCompile(`\x1b\][^\x07]*\x07|\x1b\][^\x1b]*\x1b\\`)

// normalizeLineEndings converts bare CR and CRLF to LF so Windows conhost
// does not show stray leading spaces or double-spaced output.
func normalizeLineEndings(p []byte) []byte {
	out := make([]byte, 0, len(p))
	for i := 0; i < len(p); i++ {
		if p[i] == '\r' {
			if i+1 < len(p) && p[i+1] == '\n' {
				out = append(out, '\n')
				i++
				continue
			}
			out = append(out, '\n')
			continue
		}
		out = append(out, p[i])
	}
	return out
}

func newEscapeFilterWriter(w io.Writer) *escapeFilterWriter {
	return &escapeFilterWriter{w: w}
}

func (f *escapeFilterWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	normalized := normalizeLineEndings(p)
	filtered := ansiEscapeRegexp.ReplaceAll(normalized, []byte{})
	n, err := f.w.Write(filtered)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// sshCmd represents the ssh command
var sshCmd = &cobra.Command{
	Use:   "ssh [user@]target[:port]",
	Short: "SSH through the MASQUE tunnel",
	Long:  "Establish an SSH connection through the usque MASQUE tunnel to a target virtual IP or hostname. Similar to Tailscale SSH.",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}

		target := args[0]
		var command string
		if len(args) > 1 {
			command = strings.Join(args[1:], " ")
		}
		user, host, port, err := parseSSHTarget(target)
		if err != nil {
			cmd.Printf("Failed to parse target '%s': %v\n", target, err)
			cmd.Println("Expected format: [user@]host[:port] (e.g., root@100.64.0.2:22)")
			return
		}

		// Allow CLI flags to override parsed values
		userOverride, _ := cmd.Flags().GetString("user")
		if userOverride != "" {
			user = userOverride
		}

		portOverride, _ := cmd.Flags().GetInt("port")
		if portOverride != 22 {
			port = portOverride
		}

		password, _ := cmd.Flags().GetString("password")
		if password == "" {
			fmt.Fprintf(os.Stderr, "SSH password for %s@%s: ", user, host)
			pwBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				cmd.Printf("Failed to read password: %v\n", err)
				return
			}
			password = string(pwBytes)
			fmt.Fprintln(os.Stderr)
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

		mtu, err := cmd.Flags().GetInt("mtu")
		if err != nil {
			cmd.Printf("Failed to get MTU: %v\n", err)
			return
		}
		if mtu != 1280 {
			log.Println("Warning: MTU is not the default 1280. This is not supported. Packet loss and other issues may occur.")
		}

		reconnectDelay, err := cmd.Flags().GetDuration("reconnect-delay")
		if err != nil {
			cmd.Printf("Failed to get reconnect delay: %v\n", err)
			return
		}

		alwaysReconnect, err := cmd.Flags().GetBool("always-reconnect")
		if err != nil {
			cmd.Printf("Failed to get always-reconnect flag: %v\n", err)
			return
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

		// Create virtual TUN device for the tunnel (same as portfw)
		tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, nil, mtu)
		if err != nil {
			cmd.Printf("Failed to create virtual TUN device: %v\n", err)
			return
		}
		defer func() { _ = tunDev.Close() }()

		// Start tunnel maintenance (same as portfw)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		hookEnv := map[string]string{
			"USQUE_MODE": "ssh",
			"USQUE_TARGET": host,
			"USQUE_IPV4": config.AppConfig.IPv4,
			"USQUE_IPV6": config.AppConfig.IPv6,
		}

		go api.RunTunnel(ctx, api.MaintainTunnelConfig{
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

		// Wait a moment for tunnel to establish
		log.Println("Establishing MASQUE tunnel for SSH...")
		time.Sleep(2 * time.Second)

		targetAddr := fmt.Sprintf("%s:%d", host, port)

		// Establish TCP connection through tunnel directly (like portfw)
		maxRetries := 30
		var conn net.Conn
		for i := 0; i < maxRetries; i++ {
			conn, err = tunNet.DialContext(ctx, "tcp", targetAddr)
			if err == nil {
				log.Printf("SSH connection established to %s via tunnel", targetAddr)
				break
			}
			log.Printf("Waiting for tunnel connectivity to %s (attempt %d/%d)...", targetAddr, i+1, maxRetries)
			time.Sleep(1 * time.Second)
		}

		if err != nil {
			log.Printf("Failed to establish SSH connection to %s via tunnel: %v", targetAddr, err)
			return
		}
		defer func() { _ = conn.Close() }()

		// Perform SSH handshake and authentication using golang.org/x/crypto/ssh
		sshConfig := &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         10 * time.Second,
		}

		log.Println("Performing SSH handshake...")
		sshConn, channelCh, requestCh, err := ssh.NewClientConn(conn, targetAddr, sshConfig)
		if err != nil {
			log.Printf("SSH handshake failed: %v", err)
			return
		}
		defer func() { _ = sshConn.Close() }()

		client := ssh.NewClient(sshConn, channelCh, requestCh)

		log.Println("Requesting pseudo-terminal...")
		session, err := client.NewSession()
		if err != nil {
			log.Printf("Failed to create SSH session: %v", err)
			return
		}
		defer session.Close()

		// Set up the local terminal so the remote PTY can handle all
		// display. Platform-specific helpers disable local echo and, on
		// Windows, enable VT processing for ANSI sequences.
		restoreTerminal, err := setupTerminal()
		if err != nil {
			log.Printf("Failed to set up terminal: %v", err)
		} else if restoreTerminal != nil {
			defer restoreTerminal()
		}

		// Start I/O pump between local terminal and remote SSH session.
		// Create pipes BEFORE starting the shell so SSH can wire them up correctly.
		stdinPipe, err := session.StdinPipe()
		if err != nil {
			log.Printf("Failed to create stdin pipe: %v", err)
			return
		}
		stdoutPipe, err := session.StdoutPipe()
		if err != nil {
			log.Printf("Failed to create stdout pipe: %v", err)
			return
		}
		stderrPipe, err := session.StderrPipe()
		if err != nil {
			log.Printf("Failed to create stderr pipe: %v", err)
			return
		}

		// Request terminal with standard settings.
		// Explicitly enable remote echo so keystrokes are displayed
		// immediately by the remote PTY. Local echo is suppressed
		// per-platform below to avoid double-printing.
		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.ICANON:        1,
			ssh.ISIG:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		termType := "xterm-256color"
		if _, err := term.GetState(int(syscall.Stdin)); err != nil {
			termType = "dumb"
		}

		// Get current terminal size and pass it to the initial PTY request so the remote
		// shell starts with the correct dimensions instead of assuming a very narrow width.
		width, height := getTerminalSize()
		if width <= 0 || height <= 0 {
			width, height = 80, 40
		}
		log.Printf("Terminal size: %dx%d", width, height)
		if err := session.RequestPty(termType, height, width, modes); err != nil {
			log.Printf("Failed to request pseudo-terminal: %v", err)
			return
		}

		// Keep window size in sync in case the user resizes the local console window.
		go func() {
			lastW, lastH := width, height
			for {
				time.Sleep(1 * time.Second)
				w, h := getTerminalSize()
				if (w > 0 && h > 0) && (w != lastW || h != lastH) {
					log.Printf("Window size changed: %dx%d -> %dx%d", lastW, lastH, w, h)
					_ = session.WindowChange(h, w)
					lastW, lastH = w, h
				}
			}
		}()

		if command != "" {
			if err := session.Start(command); err != nil {
				log.Printf("Failed to start command: %v", err)
				return
			}
		} else {
			// Start interactive shell
			if err := session.Shell(); err != nil {
				log.Printf("Failed to start shell: %v", err)
				return
			}
		}

		go func() {
			_, _ = io.Copy(stdinPipe, os.Stdin)
		}()
		go func() {
			_, _ = io.Copy(os.Stdout, stdoutPipe)
		}()
		go func() {
			_, _ = io.Copy(os.Stderr, stderrPipe)
		}()

		// Wait for session to finish
		if err := session.Wait(); err != nil {
			if exitErr, ok := err.(*ssh.ExitError); ok {
				log.Printf("SSH exited with code %d", exitErr.ExitStatus())
			} else {
				log.Printf("SSH error: %v", err)
			}
		}
	},
}

// getTerminalSize returns the current terminal width and height.
// On Windows it stabilizes the value by ignoring obviously invalid
// readings (for example 1-tall or extremely narrow buffers) and
// falling back to a sane default so the remote PTY does not get a
// broken geometry.
func parseSSHTarget(target string) (string, string, int, error) {
	user := ""
	host := ""
	port := 22

	// Split user@host
	if idx := strings.Index(target, "@"); idx != -1 {
		user = target[:idx]
		target = target[idx+1:]
	}

	// Handle IPv6 [host]:port
	if strings.HasPrefix(target, "[") {
		end := strings.Index(target, "]")
		if end < 0 {
			return "", "", 0, fmt.Errorf("invalid IPv6 address")
		}
		host = target[1:end]
		if end+1 < len(target) && target[end+1] == ':' {
			portStr := target[end+2:]
			if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
				return "", "", 0, fmt.Errorf("invalid port: %s", portStr)
			}
		}
	} else {
		// Split host:port (last colon to handle IPv6 without brackets)
		if idx := strings.LastIndex(target, ":"); idx != -1 {
			// simple heuristic: if colon appears after another char and not in brackets
			host = target[:idx]
			portStr := target[idx+1:]
			if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
				return "", "", 0, fmt.Errorf("invalid port: %s", portStr)
			}
		} else {
			host = target
		}
	}

	if host == "" {
		return "", "", 0, fmt.Errorf("host is empty")
	}

	return user, host, port, nil
}

func init() {
	rootCmd.AddCommand(sshCmd)

	sshCmd.Flags().StringP("user", "l", "", "SSH username (overrides user in target)")
	sshCmd.Flags().IntP("port", "p", 22, "SSH port (overrides port in target)")
	sshCmd.Flags().IntP("connect-port", "P", 443, "Used port for MASQUE connection")
	sshCmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 for MASQUE connection")
	sshCmd.Flags().BoolP("no-tunnel-ipv4", "F", false, "Disable IPv4 inside the MASQUE tunnel")
	sshCmd.Flags().BoolP("no-tunnel-ipv6", "S", false, "Disable IPv6 inside the MASQUE tunnel")
	sshCmd.Flags().StringP("sni-address", "s", internal.ConnectSNI, "SNI address to use for MASQUE connection")
	sshCmd.Flags().DurationP("keepalive-period", "k", 30*time.Second, "Keepalive period for MASQUE connection")
	sshCmd.Flags().IntP("mtu", "m", 1280, "MTU for MASQUE connection")
	sshCmd.Flags().Uint16P("initial-packet-size", "i", 0, "Custom initial packet size for MASQUE connection (default: auto with PMTU discovery)")
	sshCmd.Flags().DurationP("reconnect-delay", "r", 1*time.Second, "Delay between reconnect attempts")
	sshCmd.Flags().Bool("always-reconnect", false, "Always reconnect after tunnel loss, even when idle")
	sshCmd.Flags().Bool("http2", false, "Use HTTP/2 over TCP+TLS instead of HTTP/3 over QUIC."+config.EndpointHelpSuffixH2)
	sshCmd.Flags().Bool("insecure", false, "Disable endpoint certificate pinning and trust any certificate")
	sshCmd.Flags().String("on-connect", "", "Path to an executable to run after each successful tunnel connect (no args; context via USQUE_* env vars)")
	sshCmd.Flags().String("on-disconnect", "", "Path to an executable to run after each tunnel disconnect (no args; context via USQUE_* env vars)")
	sshCmd.Flags().StringP("password", "w", "", "SSH password for authentication")
}
