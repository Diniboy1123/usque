package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// sshServerBanner records the SSH-2.0 banner reported by the remote
// server during the most recent establishSSHTunnel call. It is read by
// runSCP and runSFTP to emit platform-specific advice (for example,
// warning the user that dropbear targets should use `usque scp`
// rather than `usque sftp`). It is intentionally a package global
// rather than threading a new return value through every caller of
// establishSSHTunnel.
var sshServerBanner string

// isDropbearServer reports whether the captured SSH banner indicates
// a dropbear server (the default SSH server on OpenWrt and most
// embedded Linux distributions). Recognised prefixes:
//
//	SSH-2.0-dropbear
//	SSH-2.0-dropbear_2022.82
//	SSH-2.0-DropBear
//
// Anything else is treated as a generic OpenSSH-class server.
func isDropbearServer() bool {
	b := strings.ToLower(sshServerBanner)
	return strings.HasPrefix(b, "ssh-2.0-dropbear") || strings.Contains(b, "dropbear")
}

// scpEntryKind describes whether an scp argument is a local file or a remote one.
type scpEntryKind int

const (
	scpLocal scpEntryKind = iota
	scpRemote
)

// scpEntry is one parsed operand: either a local path or user@host:path.
type scpEntry struct {
	Kind scpEntryKind
	User string
	Host string
	Port int
	Path string
}

var scpCmd = &cobra.Command{
	Use:   "scp [user@]host:/path <local>  |  <local> [user@]host:/path",
	Short: "Transfer files through the MASQUE tunnel using the SCP protocol",
	Long: "Transfer files between the local host and a target reachable through the usque MASQUE tunnel, " +
		"using the standard SCP protocol on top of SSH. Currently supports single-file upload and download, " +
		"and recursive directory copy. Wildcards are expanded locally only.",
	Args: cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}

		recursive, _ := cmd.Flags().GetBool("recursive")
		preserve, _ := cmd.Flags().GetBool("preserve")

		entries, err := parseSCPArgs(args)
		if err != nil {
			cmd.Printf("Failed to parse arguments: %v\n", err)
			return
		}
		if len(entries) < 2 {
			cmd.Println("scp requires at least one source and one destination.")
			return
		}

		// Determine direction: last entry is the target, everything before is sources.
		target := entries[len(entries)-1]
		sources := entries[:len(entries)-1]

		// Validate direction: all sources on one side, target on the other.
		// Each source must be on the opposite side of the target.
		for _, s := range sources {
			if s.Kind == target.Kind {
				cmd.Printf("scp: source %q and target are both %s; need local+remote or remote+local.\n",
					s.Path, sideName(s.Kind))
				return
			}
		}

		// Find the remote host (assumes all remote entries point to the same host).
		var remote *scpEntry
		if target.Kind == scpRemote {
			remote = &target
		} else {
			for i := range sources {
				if sources[i].Kind == scpRemote {
					remote = &sources[i]
					break
				}
			}
		}
		if remote == nil {
			cmd.Println("scp: no remote host in arguments.")
			return
		}

		// Apply CLI flag overrides.
		if u, _ := cmd.Flags().GetString("user"); u != "" {
			remote.User = u
		}
		if p, _ := cmd.Flags().GetInt("port"); p != 0 {
			remote.Port = p
		}

		password, _ := cmd.Flags().GetString("password")
		if password == "" {
			pw, err := readPassword(fmt.Sprintf("SCP password for %s@%s: ", remote.User, remote.Host))
			if err != nil {
				cmd.Printf("Failed to read password: %v\n", err)
				return
			}
			password = pw
		}

		// Establish MASQUE tunnel (reused from ssh.go).
		sshClient, cleanup, err := establishSCPTunnel(cmd, remote, password)
		if err != nil {
			cmd.Printf("Failed to establish tunnel: %v\n", err)
			return
		}
		defer cleanup()

		// Identify the remote SSH server and, when it's dropbear,
		// surface the version string and a single-line hint so the
		// user knows the SCP path is the right one to take. The full
		// platform-specific guidance lives in the README; here we
		// just point at the sshd we are talking to.
		if isDropbearServer() {
			log.Printf("scp: remote server is dropbear (%s) — scp is the correct transfer mode here; `usque sftp` would fail because dropbear does not provide sftp-server", sshServerBanner)
		}

		// Dispatch.
		if target.Kind == scpRemote {
			// Upload: sources local, target remote (must be a directory if multiple).
			destPath := remoteTargetDir(remote.Path, len(sources) > 1)
			log.Printf("SCP dispatch: sources=%d dest=%q (upload)", len(sources), destPath)
			for _, src := range sources {
				if src.Kind != scpLocal {
					cmd.Println("scp: only local-to-remote or remote-to-local are supported.")
					return
				}
				log.Printf("SCP uploading %s -> %s", src.Path, destPath)
				if err := scpUpload(cmd.Context(), sshClient, src.Path, destPath, recursive, preserve); err != nil {
					cmd.Printf("scp: upload %s failed: %v\n", src.Path, err)
					return
				}
				log.Printf("SCP upload %s done", src.Path)
			}
		} else {
			// Download: sources remote, target local.
			destPath := target.Path
			if len(sources) > 1 {
				if err := ensureLocalDir(destPath); err != nil {
					cmd.Printf("scp: %v\n", err)
					return
				}
			}
			for _, src := range sources {
				if src.Kind != scpRemote {
					cmd.Println("scp: only local-to-remote or remote-to-local are supported.")
					return
				}
				// If the local target is an existing directory (or ends in
				// a separator) and the source is a single file, we must
				// place the file inside the directory using the remote
				// basename — matching OpenSSH scp behaviour.
				localTarget := destPath
				if info, err := os.Stat(destPath); err == nil && info.IsDir() {
					localTarget = filepath.Join(destPath, baseNameAny(src.Path))
				} else if strings.HasSuffix(destPath, "/") || strings.HasSuffix(destPath, `\`) {
					localTarget = filepath.Join(strings.TrimRight(destPath, `/\`), baseNameAny(src.Path))
				}
				if err := scpDownload(cmd.Context(), sshClient, src.Path, localTarget, recursive, preserve); err != nil {
					cmd.Printf("scp: download %s failed: %v\n", src.Path, err)
					return
				}
			}
		}
	},
}

// parseSCPArgs splits a list of [user@]host:path or local-path operands.
func parseSCPArgs(args []string) ([]scpEntry, error) {
	out := make([]scpEntry, 0, len(args))
	for _, a := range args {
		e, err := parseSCPEntry(a)
		if err != nil {
			return nil, fmt.Errorf("invalid argument %q: %w", a, err)
		}
		out = append(out, e)
	}
	return out, nil
}

func parseSCPEntry(s string) (scpEntry, error) {
	// Find first colon that is not the Windows drive letter (e.g. C:\...).
	colonIdx := -1
	if len(s) >= 2 && s[1] == ':' && isAlpha(s[0]) {
		// Windows absolute path: skip leading "C:" when searching.
		idx := strings.Index(s[2:], ":")
		if idx >= 0 {
			colonIdx = idx + 2
		}
	} else {
		colonIdx = strings.Index(s, ":")
	}

	if colonIdx < 0 {
		return scpEntry{Kind: scpLocal, Path: s}, nil
	}
	hostPart := s[:colonIdx]
	pathPart := s[colonIdx+1:]
	if pathPart == "" {
		return scpEntry{}, fmt.Errorf("missing remote path")
	}
	user, host, port, err := parseSSHTarget(hostPart)
	if err != nil {
		return scpEntry{}, fmt.Errorf("invalid host spec %q: %w", hostPart, err)
	}
	if port == 0 {
		port = 22
	}
	return scpEntry{
		Kind: scpRemote,
		User: user,
		Host: host,
		Port: port,
		Path: pathPart,
	}, nil
}

func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func sideName(k scpEntryKind) string {
	if k == scpLocal {
		return "local"
	}
	return "remote"
}

// remoteTargetDir normalizes the remote destination: if multi-source, the
// destination must be a directory (or not exist yet); we always treat it as a
// directory and append the source basename.
func remoteTargetDir(remotePath string, multi bool) string {
	if !multi {
		return remotePath
	}
	if !strings.HasSuffix(remotePath, "/") {
		return remotePath + "/"
	}
	return remotePath
}

func ensureLocalDir(path string) error {
	if path == "" {
		return fmt.Errorf("destination path is empty")
	}
	info, err := os.Stat(path)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("destination %q is not a directory", path)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.MkdirAll(path, 0o755)
}

// establishSSHTunnel sets up the MASQUE tunnel and dials SSH over it,
// returning a connected SSH client. The cleanup function tears down the
// tunnel. `mode` is recorded in the USQUE_MODE hook env (e.g. "scp" or
// "sftp") for any on-connect / on-disconnect scripts the user has
// configured.
//
// This is the shared MASQUE+SSH bootstrap used by both `usque scp` and
// `usque sftp`; the protocol layer above the SSH client is what
// differentiates the two subcommands.
func establishSSHTunnel(cmd *cobra.Command, user, host string, port int, password, mode string) (*ssh.Client, func(), error) {
	sni, err := cmd.Flags().GetString("sni-address")
	if err != nil {
		return nil, nil, err
	}
	privKey, err := config.AppConfig.GetEcPrivateKey()
	if err != nil {
		return nil, nil, err
	}
	peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
	if err != nil {
		return nil, nil, err
	}
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	insecure, _ := cmd.Flags().GetBool("insecure")
	tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni, insecure)
	if err != nil {
		return nil, nil, err
	}
	keepalivePeriod, _ := cmd.Flags().GetDuration("keepalive-period")
	initialPacketSize, _ := cmd.Flags().GetUint16("initial-packet-size")
	connectPort, _ := cmd.Flags().GetInt("connect-port")
	useHTTP2, _ := cmd.Flags().GetBool("http2")
	useIPv6, _ := cmd.Flags().GetBool("ipv6")
	endpoint, err := config.SelectEndpointFromConfig(useHTTP2, useIPv6, connectPort)
	if err != nil {
		return nil, nil, err
	}
	if insecure {
		config.WarnInsecure()
	}
	if useHTTP2 {
		config.LogHTTP2Endpoint(endpoint)
	}

	tunnelIPv4, _ := cmd.Flags().GetBool("no-tunnel-ipv4")
	tunnelIPv6, _ := cmd.Flags().GetBool("no-tunnel-ipv6")

	var localAddresses []netip.Addr
	if !tunnelIPv4 {
		v4, err := netip.ParseAddr(config.AppConfig.IPv4)
		if err != nil {
			return nil, nil, err
		}
		localAddresses = append(localAddresses, v4)
	}
	if !tunnelIPv6 {
		v6, err := netip.ParseAddr(config.AppConfig.IPv6)
		if err != nil {
			return nil, nil, err
		}
		localAddresses = append(localAddresses, v6)
	}

	mtu, _ := cmd.Flags().GetInt("mtu")
	if mtu != 1280 {
		log.Println("Warning: MTU is not the default 1280. This is not supported. Packet loss and other issues may occur.")
	}

	reconnectDelay, _ := cmd.Flags().GetDuration("reconnect-delay")
	alwaysReconnect, _ := cmd.Flags().GetBool("always-reconnect")
	onConnect, _ := cmd.Flags().GetString("on-connect")
	onDisconnect, _ := cmd.Flags().GetString("on-disconnect")

	tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, nil, mtu)
	if err != nil {
		return nil, nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	hookEnv := map[string]string{
		"USQUE_MODE":   mode,
		"USQUE_TARGET": host,
		"USQUE_IPV4":   config.AppConfig.IPv4,
		"USQUE_IPV6":   config.AppConfig.IPv6,
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

	log.Printf("Establishing MASQUE tunnel for %s...", strings.ToUpper(mode))
	time.Sleep(2 * time.Second)

	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))

	var tunnelConn net.Conn
	maxRetries := 30
	for i := 0; i < maxRetries; i++ {
		tunnelConn, err = tunNet.DialContext(ctx, "tcp", targetAddr)
		if err == nil {
			log.Printf("%s tunnel connection established to %s via tunnel", strings.ToUpper(mode), targetAddr)
			break
		}
		log.Printf("Waiting for tunnel connectivity to %s (attempt %d/%d): %v", targetAddr, i+1, maxRetries, err)
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		cancel()
		_ = tunDev.Close()
		return nil, nil, fmt.Errorf("connect %s via tunnel: %w", targetAddr, err)
	}

	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	sshConn, ch, req, err := ssh.NewClientConn(tunnelConn, targetAddr, sshConfig)
	if err != nil {
		cancel()
		_ = tunDev.Close()
		return nil, nil, fmt.Errorf("ssh handshake: %w", err)
	}
	log.Printf("SSH handshake succeeded for %s to %s", strings.ToUpper(mode), targetAddr)
	// Identify the remote SSH server so the calling subcommand can
	// adapt (e.g. warn when SCP runs against dropbear, recommend SFTP
	// only on OpenSSH-class servers). ServerVersion() returns the
	// raw SSH-2.0-banner bytes, e.g. "SSH-2.0-dropbear_2022.82".
	// The package-level lastSSHBanner is read by runSCP/runSFTP
	// before they dispatch; it is intentionally a global rather than
	// threading another return value through every caller.
	sshServerBanner = string(sshConn.ServerVersion())
	client := ssh.NewClient(sshConn, ch, req)

	cleanup := func() {
		_ = client.Close()
		cancel()
		_ = tunDev.Close()
	}
	return client, cleanup, nil
}

// establishSCPTunnel is a thin wrapper that preserves the original
// scpEntry-typed API. New callers (e.g. `usque sftp`) should call
// establishSSHTunnel directly with primitive types.
func establishSCPTunnel(cmd *cobra.Command, remote *scpEntry, password string) (*ssh.Client, func(), error) {
	return establishSSHTunnel(cmd, remote.User, remote.Host, remote.Port, password, "scp")
}

// scpUpload copies a local path to a remote path through SCP.
func scpUpload(ctx context.Context, client *ssh.Client, localPath, remotePath string, recursive, preserve bool) error {
	info, err := os.Stat(localPath)
	if err != nil {
		return err
	}

	if info.IsDir() {
		if !recursive {
			return fmt.Errorf("%s: is a directory (use -r)", localPath)
		}
		// Mirror OpenSSH scp semantics: when uploading a directory, the
		// remote target becomes "<remoteDir>/<localDir basename>". The
		// caller already normalised remotePath to end in a separator if
		// it is a directory; here we append the local basename.
		base := filepath.Base(localPath)
		// Strip a trailing separator to keep path joining clean.
		remoteDir := strings.TrimRight(remotePath, `/\`)
		remoteDir = remoteDir + "/" + base
		return scpUploadDir(ctx, client, localPath, remoteDir, preserve)
	}
	return scpUploadFile(ctx, client, localPath, remotePath, info, preserve)
}

func scpUploadDir(ctx context.Context, client *ssh.Client, localDir, remoteDir string, preserve bool) error {
	// Ensure remote directory exists.
	if err := scpRemoteMkdir(ctx, client, remoteDir); err != nil {
		return err
	}
	entries, err := os.ReadDir(localDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		src := filepath.Join(localDir, e.Name())
		dst := remoteDir + "/" + e.Name()
		if e.IsDir() {
			if err := scpUploadDir(ctx, client, src, dst, preserve); err != nil {
				return err
			}
		} else {
			info, err := e.Info()
			if err != nil {
				return err
			}
			if err := scpUploadFile(ctx, client, src, dst, info, preserve); err != nil {
				return err
			}
		}
	}
	return nil
}

// scpRemoteMkdir creates a directory (with parents) on the remote. For
// Windows drive-letter paths we use PowerShell because cmd.exe has no
// "mkdir -p" equivalent; for POSIX paths we use the standard `mkdir -p`.
func scpRemoteMkdir(ctx context.Context, client *ssh.Client, remoteDir string) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	var cmd string
	if isWindowsDrivePath(remoteDir) {
		cmd = fmt.Sprintf(`powershell -NoProfile -Command "New-Item -ItemType Directory -Force -Path %s | Out-Null"`, shellQuote(remoteDir))
	} else {
		cmd = "mkdir -p " + shellQuote(remoteDir)
	}
	return sess.Run(cmd)
}

// scpRemoteRename runs a single "rename" command on the remote to drop
// the .usque_tmp suffix from the staging file and reveal it under the
// final destination filename. This is done in the same directory so the
// operation stays a same-volume rename. `dst` is the new filename only
// (no directory component). If the destination already exists, the
// existing file is removed first so the rename acts as an overwrite.
//
// The remote platform determines the right tool to use: Windows uses
// PowerShell (because cmd.exe has no atomic "remove then rename"
// primitive and because path quoting is much more reliable in PS);
// POSIX uses a single `rm -f && mv` shell pipeline.
func scpRemoteRename(ctx context.Context, client *ssh.Client, src, dst, parentDir string) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	var cmd string
	if isWindowsDrivePath(src) || isWindowsDrivePath(parentDir) {
		// Resolve the absolute Windows path of the destination by joining
		// the parent directory with the new filename, then call
		// PowerShell to remove any existing file at that path before
		// renaming. Using a single PowerShell command keeps the operation
		// atomic from the remote's point of view.
		winParent := strings.ReplaceAll(parentDir, "/", `\`)
		finalPath := winParent + `\` + dst
		cmd = fmt.Sprintf(`powershell -NoProfile -Command "if (Test-Path -LiteralPath %s) { Remove-Item -LiteralPath %s -Force }; Rename-Item -LiteralPath %s -NewName %s"`, shellQuote(finalPath), shellQuote(finalPath), shellQuote(src), shellQuote(dst))
	} else {
		// POSIX: `rm -f` the existing file (if any) and `mv` the
		// staging file to its final name. We collapse both into a single
		// command so the operation is "atomic enough" on POSIX file
		// systems: the destination either points to the old file or to
		// the new one, never half-renamed.
		dstPath := strings.TrimRight(parentDir, "/") + "/" + dst
		cmd = fmt.Sprintf("rm -f %s && mv %s %s", shellQuote(dstPath), shellQuote(src), shellQuote(dstPath))
	}
	out, err := sess.CombinedOutput(cmd)
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimRight(string(out), "\r\n"))
	}
	return nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// toWindowsScpDir returns a path safe to pass to `scp -t` / `scp -f` on a
// Windows OpenSSH server. The scp sink on Windows refuses paths that look
// ambiguous (e.g. "e:/github" is reported as "scp: ambiguous target"), so
// the only safe form is the bare drive letter ("e:") with no subpath. The
// caller is expected to mkdir -p the full target directory separately and,
// for any non-root destination, move the uploaded file into place via a
// follow-up SSH session.
func toWindowsScpDir(p string) string {
	if len(p) >= 2 && p[1] == ':' && isAlpha(p[0]) {
		return string(p[0]) + ":"
	}
	if len(p) >= 3 && p[0] == '/' && p[2] == ':' && isAlpha(p[1]) {
		return string(p[1]) + ":"
	}
	return p
}

// scpDownloadCommand builds the remote command to invoke scp -f. For
// Windows drive-letter paths we must go through cmd /c with the
// Windows-native scp.exe and a backslash path; otherwise the regular
// `scp -f` lookup works fine for POSIX targets.
func scpDownloadCommand(remotePath string) string {
	if isWindowsDrivePath(remotePath) {
		winPath := strings.ReplaceAll(remotePath, "/", `\`)
		return fmt.Sprintf(`cmd /c "C:\Windows\System32\OpenSSH\scp.exe -f %s"`, winPath)
	}
	return "scp -f " + shellQuote(remotePath)
}

// isWindowsDrivePath reports whether p starts with a Windows drive prefix
// like "C:" or "/C:" or "C:/..." or "/C:/...".
func isWindowsDrivePath(p string) bool {
	if len(p) >= 2 && p[1] == ':' && isAlpha(p[0]) {
		return true
	}
	if len(p) >= 3 && p[0] == '/' && p[2] == ':' && isAlpha(p[1]) {
		return true
	}
	return false
}

// baseNameAny returns the final path component, splitting on both POSIX "/"
// and Windows "\". filepath.Base alone only handles "/", so for Windows
// drive-letter paths it returns the whole string.
func baseNameAny(p string) string {
	idx := strings.LastIndexAny(p, `/\`)
	if idx < 0 {
		return p
	}
	return p[idx+1:]
}

func scpUploadFile(ctx context.Context, client *ssh.Client, localPath, remotePath string, info os.FileInfo, preserve bool) error {
	// Windows OpenSSH scp refuses any -t argument that looks ambiguous,
	// including bare Windows drive paths with a subpath ("e:/foo") and
	// absolute drive-prefixed paths ("/e:/foo"). The only universally safe
	// target on Windows is /tmp/... (mapped to %TEMP% by sshd). For any
	// destination that contains a drive prefix, we upload to a unique
	// /tmp staging path and then move the file into place via PowerShell.
	targetName := filepath.Base(localPath)
	if remotePath == "" {
		remotePath = targetName
	}
	// We always upload via a `.usque_tmp` staging file in the same parent
	// directory and then atomically rename it into place. This keeps the
	// implementation uniform across Windows and POSIX, and gives us crash-
	// safety: a partial upload never overwrites the final file.
	var staging string
	var finalBase string
	var parent string
	windowsPath := isWindowsDrivePath(remotePath)
	if strings.HasSuffix(remotePath, "/") {
		// Trailing slash: target is a directory.
		finalBase = targetName
		if windowsPath {
			parent = strings.TrimRight(remotePath, `/\`)
		} else {
			parent = strings.TrimRight(remotePath, "/")
		}
	} else {
		finalBase = baseNameAny(remotePath)
		if finalBase == "" {
			finalBase = targetName
		}
		parent = remoteDirParent(remotePath)
	}
	if err := scpRemoteMkdir(ctx, client, parent); err != nil {
		return fmt.Errorf("scp: create remote dir %q: %w", parent, err)
	}
	if windowsPath {
		parentWin := strings.ReplaceAll(parent, "/", `\`)
		staging = fmt.Sprintf(`%s\%s.usque_tmp`, parentWin, finalBase)
	} else {
		staging = parent + "/" + finalBase + ".usque_tmp"
	}
	log.Printf("scp: staging %s -> rename to %s", staging, finalBase)

	if err := scpRunUploadSession(client, staging, localPath, info); err != nil {
		return err
	}

	log.Printf("scp: renaming %s -> %s", staging, finalBase)
	if err := scpRemoteRename(ctx, client, staging, finalBase, parent); err != nil {
		return fmt.Errorf("scp: rename %s -> %s: %w", staging, finalBase, err)
	}
	return nil
}

// scpRunUploadSession runs a single `scp -t <staging>` session and streams
// the local file into it, performing the standard source-side handshake.
//
// On Windows, the standard scp -t invocation has multiple well-known
// problems:
//  1. The mingw/MSYS shim scp (D:\ProgramFiles\MinGW\msys\1.0\bin\scp.exe)
//     mis-handles Windows drive-letter paths with a subpath, reporting
//     "ambiguous target" or hanging on stat.
//  2. The Windows-native OpenSSH scp (C:\Windows\System32\OpenSSH\scp.exe)
//     does not accept forward-slash paths ("e:/foo") and requires
//     backslash form ("e:\foo").
//  3. Even when the protocol succeeds, scp -t can return spurious
//     "No such file or directory" errors when the target directory is
//     actually reachable, because of the way mingw shim layers stat.
//
// We sidestep these by always invoking the Windows-native scp via
// `cmd /c` and using backslash paths. This is the configuration that
// the Windows OpenSSH team tests end-to-end.
func scpRunUploadSession(client *ssh.Client, staging, localPath string, info os.FileInfo) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return err
	}
	// Drain remote stderr so a non-zero scp exit doesn't deadlock the channel.
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				log.Printf("scp remote stderr: %s", strings.TrimRight(string(buf[:n]), "\r\n"))
			}
			if err != nil {
				return
			}
		}
	}()

	mode := uint32(info.Mode().Perm())
	// For Windows drive-letter paths, Go's filepath.Base treats the whole
	// string as a single name (since "\" is not a path separator in Go).
	// We need the basename after both "/" and "\".
	targetName := baseNameAny(staging)
	header := fmt.Sprintf("C%04o %d %s\n", mode, info.Size(), targetName)

	// Build the command. On Windows drive-rooted paths we MUST route
	// through cmd /c with the native scp.exe and a backslash path.
	// Otherwise, fall back to the regular `scp -t` lookup, which works
	// for POSIX targets.
	var cmd string
	if isWindowsDrivePath(staging) {
		// Convert any forward slashes in the target to backslashes for
		// the Windows-native scp.
		winPath := strings.ReplaceAll(staging, "/", `\`)
		cmd = fmt.Sprintf(`cmd /c "C:\Windows\System32\OpenSSH\scp.exe -t %s"`, winPath)
	} else {
		cmd = "scp -t " + shellQuote(staging)
	}
	if err := scpRunSink(sess, cmd); err != nil {
		return err
	}
	// The OpenSSH scp sink does not emit any response until it has
	// received and processed a header from the source. We must therefore
	// send the "C" header first and then read the resulting ACK.
	if _, err := io.WriteString(stdin, header); err != nil {
		return err
	}
	if err := scpReadAck(stdout); err != nil {
		log.Printf("scp: header ack error: %v", err)
		return err
	}
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(stdin, f); err != nil {
		return err
	}
	if _, err := stdin.Write([]byte{0}); err != nil {
		return err
	}
	// Close stdin to signal end-of-file to the remote scp. The Windows
	// native scp.exe waits for the source to close its write side
	// before emitting the final ACK, while the mingw shim may emit
	// the ACK eagerly. Closing stdin lets both styles terminate.
	_ = stdin.Close()
	// Final ACK: Windows OpenSSH scp -t may exit immediately after
	// writing the file without emitting the trailing \x00; treat EOF
	// as a successful termination in that case.
	if err := scpReadAckOrEOF(stdout); err != nil {
		log.Printf("scp: final ack error: %v (file may still have been written)", err)
		return err
	}
	return sess.Wait()
}

// remoteDirParent returns the directory portion of a remote path suitable
// for passing to `scp -t`. It is separator-aware: on POSIX the separator is
// "/", on Windows it is "/" or "\". A trailing slash means "this is already
// a directory", so we return it unchanged.
func remoteDirParent(p string) string {
	if p == "" {
		return "."
	}
	// Treat trailing separator as a directory hint: keep the path.
	if strings.HasSuffix(p, "/") || strings.HasSuffix(p, `\`) {
		return strings.TrimRight(p, `/\`)
	}
	// Find the last separator, supporting both "/" and "\".
	idx := strings.LastIndexAny(p, `/\`)
	if idx < 0 {
		// No separator -> file in current dir.
		return "."
	}
	// Preserve Windows drive-letter prefix (e.g. "e:/foo" -> "e:/").
	if idx == 2 && len(p) >= 3 && p[1] == ':' && isAlpha(p[0]) {
		return p[:3]
	}
	if idx == 0 {
		return p[:idx+1] // keep leading "/"
	}
	return p[:idx]
}

func scpDownload(ctx context.Context, client *ssh.Client, remotePath, localPath string, recursive, preserve bool) error {
	// First query remote metadata via a quick session.
	remoteInfo, err := scpStat(ctx, client, remotePath)
	if err != nil {
		return err
	}
	if remoteInfo.IsDir {
		if !recursive {
			return fmt.Errorf("%s: is a directory (use -r)", remotePath)
		}
		if err := os.MkdirAll(localPath, 0o755); err != nil {
			return err
		}
		return scpDownloadDir(ctx, client, remotePath, localPath, preserve)
	}
	return scpDownloadFile(ctx, client, remotePath, localPath, preserve)
}

func scpDownloadDir(ctx context.Context, client *ssh.Client, remoteDir, localDir string, preserve bool) error {
	entries, err := scpList(ctx, client, remoteDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		r := remoteDir + "/" + e.Name
		l := filepath.Join(localDir, e.Name)
		if e.IsDir {
			if err := os.MkdirAll(l, 0o755); err != nil {
				return err
			}
			if err := scpDownloadDir(ctx, client, r, l, preserve); err != nil {
				return err
			}
		} else {
			if err := scpDownloadFile(ctx, client, r, l, preserve); err != nil {
				return err
			}
		}
	}
	return nil
}

func scpDownloadFile(ctx context.Context, client *ssh.Client, remotePath, localPath string, preserve bool) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return err
	}
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				log.Printf("scp remote stderr: %s", strings.TrimRight(string(buf[:n]), "\r\n"))
			}
			if err != nil {
				return
			}
		}
	}()

	if err := scpRunSink(sess, scpDownloadCommand(remotePath)); err != nil {
		return err
	}
	if err := scpWriteAck(stdin); err != nil {
		return err
	}

	// Read header line.
	header, size, err := scpReadHeaderLine(stdout)
	if err != nil {
		return err
	}
	_ = header // contains mode/size/name; we use parsed size below

	if err := scpWriteAck(stdin); err != nil {
		return err
	}

	f, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, io.LimitReader(stdout, int64(size))); err != nil {
		return err
	}
	// Consume trailing 0 byte.
	buf := make([]byte, 1)
	if _, err := io.ReadFull(stdout, buf); err != nil {
		return err
	}
	if buf[0] != 0 {
		return fmt.Errorf("scp: expected trailing 0, got %q", buf)
	}
	if err := scpWriteAck(stdin); err != nil {
		return err
	}
	os.Exit(0)
	return sess.Wait()
}

type scpRemoteInfo struct {
	IsDir bool
	Size  int64
}

func scpStat(ctx context.Context, client *ssh.Client, remotePath string) (scpRemoteInfo, error) {
	sess, err := client.NewSession()
	if err != nil {
		return scpRemoteInfo{}, err
	}
	defer sess.Close()
	// Use the right tool for the remote: PowerShell on Windows
	// (because the mingw shim stat is unreliable on Windows OpenSSH),
	// GNU `stat` on POSIX.
	var out []byte
	var cmdErr error
	if isWindowsDrivePath(remotePath) {
		psCmd := fmt.Sprintf(`powershell -NoProfile -Command "$x = Get-Item -LiteralPath %s -ErrorAction SilentlyContinue; if ($x) { if ($x.PSIsContainer) { 'dir' } else { 'file ' + $x.Length } } else { '' }"`, shellQuote(remotePath))
		out, cmdErr = sess.CombinedOutput(psCmd)
	} else {
		// POSIX: use `stat -c '%F %s'` and let the caller map the
		// "regular file"/"directory" prefixes.
		out, cmdErr = sess.CombinedOutput("stat -c '%F %s' -- " + shellQuote(remotePath))
	}
	if cmdErr == nil {
		s := strings.TrimSpace(string(out))
		if strings.HasPrefix(s, "dir") || strings.HasPrefix(strings.ToLower(s), "directory") {
			return scpRemoteInfo{IsDir: true}, nil
		}
		if strings.HasPrefix(s, "file ") || strings.HasPrefix(strings.ToLower(s), "regular") {
			// Parse the trailing size token from either form.
			fields := strings.Fields(s)
			if len(fields) >= 2 {
				size, _ := strconv.ParseInt(fields[len(fields)-1], 10, 64)
				return scpRemoteInfo{IsDir: false, Size: size}, nil
			}
			return scpRemoteInfo{IsDir: false}, nil
		}
	}
	return scpRemoteInfo{}, fmt.Errorf("cannot stat remote path %s", remotePath)
}

type scpListEntry struct {
	Name  string
	IsDir bool
}

func scpList(ctx context.Context, client *ssh.Client, remoteDir string) ([]scpListEntry, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	// Pick the right enumeration tool for the remote platform.
	// Windows drive-letter paths use PowerShell (mingw shim `find`/`ls`
	// misbehaves on Windows OpenSSH); POSIX paths use `find` and fall
	// back to `ls -1` if find is unavailable.
	var out []byte
	if isWindowsDrivePath(remoteDir) {
		psCmd := fmt.Sprintf(`powershell -NoProfile -Command "Get-ChildItem -LiteralPath %s -Force | ForEach-Object { if ($_.PSIsContainer) { 'D ' + $_.Name } else { 'F ' + $_.Name } }"`, shellQuote(remoteDir))
		out, err = sess.Output(psCmd)
	} else {
		cmd := "if command -v find >/dev/null 2>&1; then find " + shellQuote(remoteDir) +
			" -mindepth 1 -maxdepth 1 -printf 'D %f\\n' -type d -o -printf 'F %f\\n' -type f; else ls -1 " + shellQuote(remoteDir) + "; fi"
		out, err = sess.Output(cmd)
	}
	if err != nil {
		return nil, err
	}
	var entries []scpListEntry
	for _, line := range strings.Split(strings.TrimRight(string(out), "\r\n"), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, " ", 2)
		if len(fields) != 2 {
			entries = append(entries, scpListEntry{Name: line})
			continue
		}
		entries = append(entries, scpListEntry{
			IsDir: fields[0] == "D",
			Name:  fields[1],
		})
	}
	return entries, nil
}

// scpRunSink starts a remote scp sink/source with the given args. stdout is the
// remote process's stdout; reads from it must consume the SCP protocol.
func scpRunSink(sess *ssh.Session, cmd string) error {
	log.Printf("scp: starting remote %q", cmd)
	if err := sess.Start(cmd); err != nil {
		return err
	}
	return nil
}

func scpReadAck(r io.Reader) error {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	switch b[0] {
	case 0:
		return nil
	case 1, 2:
		// Read error message until newline.
		msg, _ := io.ReadAll(io.LimitReader(r, 1024))
		return fmt.Errorf("scp remote error: %s", string(msg))
	default:
		return fmt.Errorf("scp: unexpected ack byte %d", b[0])
	}
}

// scpReadAckOrEOF is like scpReadAck but treats a clean EOF as success.
// Windows OpenSSH scp.exe may close stdout after the final write without
// emitting the trailing \x00, so accept EOF as normal completion.
func scpReadAckOrEOF(r io.Reader) error {
	var b [1]byte
	n, err := io.ReadFull(r, b[:])
	if err == io.EOF || (n == 0 && err == io.ErrUnexpectedEOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("scp: read ack: %w", err)
	}
	switch b[0] {
	case 0:
		return nil
	case 1, 2:
		msg, _ := io.ReadAll(io.LimitReader(r, 1024))
		return fmt.Errorf("scp remote error: %s", string(msg))
	default:
		return fmt.Errorf("scp: unexpected ack byte %d", b[0])
	}
}

func scpWriteAck(w io.Writer) error {
	_, err := w.Write([]byte{0})
	return err
}

func scpReadHeaderLine(r io.Reader) (string, int64, error) {
	line, err := readLine(r)
	if err != nil {
		return "", 0, err
	}
	if len(line) < 1 || line[0] != 'C' {
		return "", 0, fmt.Errorf("scp: unexpected header %q", line)
	}
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return "", 0, fmt.Errorf("scp: malformed header %q", line)
	}
	size, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("scp: bad size in header: %w", err)
	}
	return line, size, nil
}

func readLine(r io.Reader) (string, error) {
	var buf []byte
	one := make([]byte, 1)
	for {
		n, err := r.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				return string(buf), nil
			}
			buf = append(buf, one[0])
		}
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				return string(buf), nil
			}
			return "", err
		}
	}
}

// readPassword prompts for a password with echo disabled, matching the
// behaviour used by the `ssh` subcommand.
func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Fprintln(os.Stderr)
	return string(pwBytes), nil
}

func init() {
	rootCmd.AddCommand(scpCmd)

	scpCmd.Flags().BoolP("recursive", "r", false, "Recursively copy directories")
	scpCmd.Flags().Bool("preserve", false, "Placeholder for compatibility (preservation not implemented)")
	scpCmd.Flags().StringP("user", "l", "", "SSH username (overrides user in target)")
	scpCmd.Flags().IntP("port", "p", 0, "SSH port (overrides port in target; 0 means parsed or 22)")
	scpCmd.Flags().IntP("connect-port", "P", 443, "Used port for MASQUE connection")
	scpCmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 for MASQUE connection")
	scpCmd.Flags().BoolP("no-tunnel-ipv4", "F", false, "Disable IPv4 inside the MASQUE tunnel")
	scpCmd.Flags().BoolP("no-tunnel-ipv6", "S", false, "Disable IPv6 inside the MASQUE tunnel")
	scpCmd.Flags().StringP("sni-address", "s", internal.ConnectSNI, "SNI address to use for MASQUE connection")
	scpCmd.Flags().DurationP("keepalive-period", "k", 30*time.Second, "Keepalive period for MASQUE connection")
	scpCmd.Flags().IntP("mtu", "m", 1280, "MTU for MASQUE connection")
	scpCmd.Flags().Uint16P("initial-packet-size", "i", 0, "Custom initial packet size for MASQUE connection (default: auto with PMTU discovery)")
	scpCmd.Flags().Duration("reconnect-delay", 1*time.Second, "Delay between reconnect attempts")
	scpCmd.Flags().Bool("always-reconnect", false, "Always reconnect after tunnel loss, even when idle")
	scpCmd.Flags().Bool("http2", false, "Use HTTP/2 over TCP+TLS instead of HTTP/3 over QUIC."+config.EndpointHelpSuffixH2)
	scpCmd.Flags().Bool("insecure", false, "Disable endpoint certificate pinning and trust any certificate")
	scpCmd.Flags().String("on-connect", "", "Path to an executable to run after each successful tunnel connect (no args; context via USQUE_* env vars)")
	scpCmd.Flags().String("on-disconnect", "", "Path to an executable to run after each tunnel disconnect (no args; context via USQUE_* env vars)")
	scpCmd.Flags().StringP("password", "w", "", "SSH password for authentication")
}
