package cmd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io" // <--- 补上这一行
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings" // <--- 加上这一行
	"syscall" // <--- 加上这一行
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/pkg/sftp" // <--- 确保导入了 sftp 包
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var sshdCmd = &cobra.Command{
	Use:   "sshd",
	Short: "Run SSH server over the MASQUE tunnel",
	Long:  "Start an SSH server that listens on the tunnel's virtual IP address. Supports public key authentication and interactive shell/exec.",
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}

		port, _ := cmd.Flags().GetInt("port")
		authorizedKeysPath, _ := cmd.Flags().GetString("authorized-keys")

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

		hookEnv := map[string]string{
			"USQUE_MODE": "sshd",
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

		log.Println("Virtual tunnel created, establishing SSHD...")
		time.Sleep(2 * time.Second)

		bindAddr, _ := cmd.Flags().GetString("bind")
		listenAddr := bindAddr
		if listenAddr == "" {
			if config.AppConfig.IPv4 != "" {
				listenAddr = config.AppConfig.IPv4
			} else if config.AppConfig.IPv6 != "" {
				listenAddr = config.AppConfig.IPv6
			} else {
				cmd.Println("No tunnel IP configured")
				return
			}
		}
		localAddrPort, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", listenAddr, port))
		if err != nil {
			cmd.Printf("Invalid listen address: %v\n", err)
			return
		}
		listener, err := tunNet.ListenTCPAddrPort(localAddrPort)
		if err != nil {
			cmd.Printf("Failed to listen on tunnel IP: %v\n", err)
			return
		}

		allowPassword, _ := cmd.Flags().GetBool("allow-password")
		serverPassword, _ := cmd.Flags().GetString("password")

		sshConfig := &ssh.ServerConfig{
			PublicKeyCallback: keyAuthCallback(authorizedKeysPath),
			ServerVersion:     "SSH-2.0-usque",
		}
		if allowPassword {
			sshConfig.PasswordCallback = func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
				if serverPassword != "" && string(pass) == serverPassword {
					return &ssh.Permissions{Extensions: map[string]string{"user": c.User()}}, nil
				}
				if serverPassword == "" {
					return &ssh.Permissions{Extensions: map[string]string{"user": c.User()}}, nil
				}
				return nil, errors.New("password rejected")
			}
		}

		hostKey, err := generateHostKey()
		if err != nil {
			cmd.Printf("Failed to generate host key: %v\n", err)
			return
		}
		sshConfig.AddHostKey(hostKey)

		log.Printf("sshd listening on %s", localAddrPort)

		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					log.Printf("Accept error on %s: %v", localAddrPort, err)
					continue
				}
				go handleSSHConnection(conn, sshConfig)
			}
		}()

		go func() {
			client := &http.Client{
				Transport: &http.Transport{
					DialContext: tunNet.DialContext,
				},
			}
			resp, err := client.Get("https://cloudflareok.com/test")
			if err != nil {
				log.Printf("Failed to make request to cloudflare.com: %v", err)
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != 204 {
				log.Printf("Failed to make request to cloudflare.com: %s", resp.Status)
				return
			}
			log.Println("Successfully connected to Cloudflare")
		}()

		select {}
	},
}

func generateHostKey() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	return signer, nil
}

func keyAuthCallback(authorizedKeysPath string) func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if authorizedKeysPath == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			authorizedKeysPath = filepath.Join(home, ".ssh", "authorized_keys")
		}
	}
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		data, err := os.ReadFile(authorizedKeysPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read authorized_keys: %w", err)
		}
		for len(data) > 0 {
			pk, _, _, rest, err := ssh.ParseAuthorizedKey(data)
			if err != nil {
				break
			}
			if ssh.FingerprintSHA256(key) == ssh.FingerprintSHA256(pk) {
				return &ssh.Permissions{Extensions: map[string]string{"user": conn.User()}}, nil
			}
			data = rest
		}
		return nil, errors.New("public key not allowed")
	}
}

// 处理每个 SSH 连接的主循环
func handleSSHConnection(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("SSH handshake failed: %v", err)
		return
	}
	defer sshConn.Close()

	// 在后台处理全局请求
	go ssh.DiscardRequests(reqs)

	for ch := range chans {
		if ch.ChannelType() != "session" {
			ch.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := ch.Accept()
		if err != nil {
			log.Printf("Could not accept channel: %v", err)
			continue
		}

		// 统一在后台协程中分发是 SFTP 子系统还是普通 SSH 会话
		go func(ch ssh.Channel, in <-chan *ssh.Request, username string) {
			req, ok := <-in
			if !ok {
				ch.Close()
				return
			}

			// 检查是否为 SFTP 子系统请求
			if req.Type == "subsystem" {
				var subPayload struct {
				Name string
			}
				if err := ssh.Unmarshal(req.Payload, &subPayload); err == nil {
					// 转为小写匹配，兼容不同客户端的写法
					if strings.ToLower(subPayload.Name) == "sftp" {
						log.Println("requested SFTP subsystem, starting server...")
						req.Reply(true, nil) // 修正：只传一个 bool

						// 启动 SFTP 服务端（可按需通过 sftp.WithRoot 限制根目录沙箱）
						serverOptions := []sftp.ServerOption{}

						sftpServer, err := sftp.NewServer(
							io.ReadWriteCloser(ch),
							serverOptions...,
						)
						if err != nil {
							log.Printf("Failed to start SFTP server: %v", err)
							ch.Close()
							return
						}

						if err := sftpServer.Serve(); err != nil {
							log.Printf("SFTP server error: %v", err)
						}
						return
					}
				}

				if req.WantReply {
					req.Reply(false, nil) // 修正：只传一个 bool
				}
				ch.Close()
				return
			}

			// 如果不是 subsystem（说明是 pty-req, shell, exec 等普通终端请求），交由 handleSession 处理
			handleSessionWithFirstRequest(ch, in, req, username)

		}(channel, requests, sshConn.User())
	}
}

// 辅助函数：将第一个偷看消费掉的 request 与后续的 requests 管道合并
func handleSessionWithFirstRequest(channel ssh.Channel, requests <-chan *ssh.Request, firstReq *ssh.Request, username string) {
	proxyChan := make(chan *ssh.Request, 10)
	proxyChan <- firstReq
	
	go func() {
		defer close(proxyChan)
		for req := range requests {
			proxyChan <- req
		}
	}()

	handleSession(channel, proxyChan, username)
}

func handleSession(channel ssh.Channel, requests <-chan *ssh.Request, username string) {
	defer channel.Close()

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	cols := uint32(80)
	rows := uint32(40)

	for req := range requests {
		switch req.Type {
		case "pty-req":
			type ptyRequestPayload struct {
				Term   string
				Cols   uint32
				Rows   uint32
				Width  uint32
				Height uint32
				Modes  string
			}
			var pty ptyRequestPayload
			if err := ssh.Unmarshal(req.Payload, &pty); err == nil {
				cols = pty.Cols
				rows = pty.Rows
			}
			req.Reply(true, nil)

		case "window-change":
			type windowChangePayload struct {
				Cols   uint32
				Rows   uint32
				Width  uint32
				Height uint32
			}
			var win windowChangePayload
			if err := ssh.Unmarshal(req.Payload, &win); err == nil {
				cols = win.Cols
				rows = win.Rows
			}
			req.Reply(true, nil)

		case "env":
			req.Reply(true, nil)

		case "shell":
			go func() {
				cmd := exec.Command("script", "-q", "-c", shell, "/dev/null")
				if u, err := user.Lookup(username); err == nil {
					setCmdUser(cmd, u, username)
				}
				cmd.Env = append(os.Environ(),
					fmt.Sprintf("COLUMNS=%d", cols),
					fmt.Sprintf("LINES=%d", rows),
					"TERM=xterm-256color",
				)
				cmd.Stdin = channel
				cmd.Stdout = channel
				cmd.Stderr = channel

				err := cmd.Run()
				exitCode := getExitCode(err)

				// 关键修复：主动向客户端发送退出状态码，避免客户端报错
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{Status: uint32(exitCode)}))
				_ = channel.Close()
			}()
			req.Reply(true, nil)

		case "exec":
			go func() {
				var payload struct {
					Command string
				}
				_ = ssh.Unmarshal(req.Payload, &payload)
				
				var cmd *exec.Cmd
				// 判断是否为 SCP 命令，如果是则直接执行，不经过 script 包装
				if strings.HasPrefix(payload.Command, "scp ") {
					// 将命令中的 "scp " 替换为绝对路径 "/usr/bin/scp "
					//fullCmd := strings.Replace(payload.Command, "scp ", "/usr/bin/scp ", 1)
					//cmd = exec.Command("sh", "-c", fullCmd)
					cmd = exec.Command("sh", "-c", payload.Command)
				} else {
					cmd = exec.Command("script", "-q", "-c", payload.Command, "/dev/null")
					//cmd = exec.Command("sh", "-c", payload.Command)
					cmd.Env = append(os.Environ(),
						fmt.Sprintf("COLUMNS=%d", cols),
						fmt.Sprintf("LINES=%d", rows),
						"TERM=xterm-256color",
					)
				}
				
				if u, err := user.Lookup(username); err == nil {
					setCmdUser(cmd, u, username)
				}
				// 核心修改：对于单条执行的命令，其实并不需要将标准输入长时间挂载在 channel 上阻塞
				// 如果命令不需要接收外部标准输入，可以直接切断或不绑定 Stdin
				cmd.Stdin = nil // 关键：避免 Stdin 阻塞等待客户端 EOF
				//cmd.Stdin = channel
				cmd.Stdout = channel
				cmd.Stderr = channel

				err := cmd.Run()
				exitCode := getExitCode(err)
				
				// 【新增这一行】主动关闭 channel 的写端，触发客户端 io.Copy 结束阻塞
				if writer, ok := channel.(interface{ CloseWrite() error }); ok {
					_ = writer.CloseWrite()
				}

				// 关键修复：主动向客户端发送退出状态码
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{Status: uint32(exitCode)}))
				_ = channel.Close()
			}()
			req.Reply(true, nil)

		default:
			_ = req.Reply(false, nil)
		}
	}
}

// 辅助函数：安全提取命令退出码
func getExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if status.Exited() {
				return status.ExitStatus()
			}
		}
	}
	return 1
}

func getUID(u *user.User) int {
	var uid int
	_, _ = fmt.Sscanf(u.Uid, "%d", &uid)
	return uid
}

func getGID(u *user.User) int {
	var gid int
	_, _ = fmt.Sscanf(u.Gid, "%d", &gid)
	return gid
}


func init() {
	sshdCmd.Flags().IntP("port", "p", 22, "Port to listen on")
	sshdCmd.Flags().String("authorized-keys", "", "Path to authorized_keys file")
	sshdCmd.Flags().Bool("allow-password", false, "Allow password authentication")
	sshdCmd.Flags().String("password", "", "Password for password authentication (if allowed)")
	sshdCmd.Flags().String("bind", "", "Bind address to listen on (e.g., 0.0.0.0)")
	sshdCmd.Flags().IntP("connect-port", "P", 443, "Used port for MASQUE connection")
	sshdCmd.Flags().StringArrayP("dns", "d", []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"}, "DNS servers to use inside the MASQUE tunnel")
	sshdCmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 for MASQUE connection")
	sshdCmd.Flags().BoolP("no-tunnel-ipv4", "F", false, "Disable IPv4 inside the MASQUE tunnel")
	sshdCmd.Flags().BoolP("no-tunnel-ipv6", "S", false, "Disable IPv6 inside the MASQUE tunnel")
	sshdCmd.Flags().StringP("sni-address", "s", internal.ConnectSNI, "SNI address to use for MASQUE connection")
	sshdCmd.Flags().DurationP("keepalive-period", "k", 30*time.Second, "Keepalive period for MASQUE connection")
	sshdCmd.Flags().IntP("mtu", "m", 1280, "MTU for MASQUE connection")
	sshdCmd.Flags().Uint16P("initial-packet-size", "i", 0, "Custom initial packet size for MASQUE connection")
	sshdCmd.Flags().Duration("reconnect-delay", 1*time.Second, "Delay between reconnect attempts")
	sshdCmd.Flags().Bool("http2", false, "Use HTTP/2 over TCP+TLS instead of HTTP/3 over QUIC"+config.EndpointHelpSuffixH2)
	sshdCmd.Flags().Bool("insecure", false, "Disable endpoint certificate pinning")
	sshdCmd.Flags().Bool("always-reconnect", false, "Always reconnect after tunnel loss, even when idle")
	sshdCmd.Flags().Bool("dont-always-reconnect", false, "Disable always reconnect in portfw; reconnect only when new activity arrives")
	sshdCmd.Flags().String("on-connect", "", "Path to executable on connect")
	sshdCmd.Flags().String("on-disconnect", "", "Path to executable on disconnect")
	rootCmd.AddCommand(sshdCmd)
}