package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/pkg/sftp"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// sftpCmd implements `usque sftp` as a SFTP-protocol alternative to
// `usque scp`. SFTP runs over the SSH subsystem channel rather than
// shelling out to a remote `scp` binary, so:
//
//   - the remote only needs sftp-server (default-enabled on OpenSSH
//     and Windows OpenSSH), and
//   - Windows drive-letter paths (e.g. "e:/github/test/foo.txt") work
//     uniformly without any PowerShell, mingw shim, or Windows-native
//     scp.exe fallback.
//
// The MASQUE tunnel and SSH handshake are shared with `usque scp`
// through `establishSSHTunnel`; the protocol layer above the SSH client
// is what differs.
//
// NOTE: dropbear (the default SSH server on OpenWrt and many other
// embedded Linux distributions) does NOT include an SFTP subsystem by
// default. On such targets `usque sftp` will fail at the
// `sftp.NewClient` step with "server unexpectedly closed connection".
// For dropbear targets, use `usque scp` instead.
var sftpCmd = &cobra.Command{
	Use:   "sftp [flags] [[user@]host:]source ... [[user@]host:]dest",
	Short: "SFTP file transfer through the MASQUE tunnel",
	Long: `Copy files between the local machine and a host reachable through
the MASQUE tunnel, using the SSH File Transfer Protocol (SFTP).

Operands follow the same mixed local/remote syntax as 'scp': exactly one
operand must be on the remote side; all others must be local. Use -r
to recurse into directories. -w supplies the SSH password inline;
otherwise the password is prompted for on the terminal.

Remote paths may be POSIX form (/home/user/file.txt) or Windows
drive-letter form (e.g. e:/github/test/file.txt or C:\\Users\\me\\file.txt).`,
	RunE: runSFTP,
}

func init() {
	sftpCmd.Flags().StringP("password", "w", "", "SSH password (prompt if empty)")
	sftpCmd.Flags().BoolP("recursive", "r", false, "recursively copy directories")
	sftpCmd.Flags().BoolP("preserve", "p", false, "preserve modification times and permissions")
	// Flags shared with the rest of the MASQUE subcommands. The values
	// mirror scp.go / ssh.go so a single config.json can be reused
	// across all modes.
	sftpCmd.Flags().StringP("user", "l", "", "SSH username (overrides user in target)")
	sftpCmd.Flags().IntP("port", "P", 0, "SSH port (overrides port in target; 0 means parsed or 22)")
	sftpCmd.Flags().Int("connect-port", 443, "Used port for MASQUE connection")
	sftpCmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 for MASQUE connection")
	sftpCmd.Flags().Bool("no-tunnel-ipv4", false, "Disable IPv4 inside the MASQUE tunnel")
	sftpCmd.Flags().Bool("no-tunnel-ipv6", false, "Disable IPv6 inside the MASQUE tunnel")
	sftpCmd.Flags().String("sni-address", internal.ConnectSNI, "SNI address to use for MASQUE connection")
	sftpCmd.Flags().Duration("keepalive-period", 30*time.Second, "Keepalive period for MASQUE connection")
	sftpCmd.Flags().Int("mtu", 1280, "MTU for MASQUE connection")
	sftpCmd.Flags().Uint16("initial-packet-size", 0, "Custom initial packet size for MASQUE connection")
	sftpCmd.Flags().Duration("reconnect-delay", 1*time.Second, "Delay between reconnect attempts")
	sftpCmd.Flags().Bool("always-reconnect", false, "Always reconnect after tunnel loss, even when idle")
	sftpCmd.Flags().Bool("http2", false, "Use HTTP/2 over TCP+TLS instead of HTTP/3 over QUIC."+config.EndpointHelpSuffixH2)
	sftpCmd.Flags().Bool("insecure", false, "Disable endpoint certificate pinning and trust any certificate")
	sftpCmd.Flags().String("on-connect", "", "Path to an executable to run after each successful tunnel connect (no args; context via USQUE_* env vars)")
	sftpCmd.Flags().String("on-disconnect", "", "Path to an executable to run after each tunnel disconnect (no args; context via USQUE_* env vars)")
	rootCmd.AddCommand(sftpCmd)
}

func runSFTP(cmd *cobra.Command, args []string) error {
	recursive, _ := cmd.Flags().GetBool("recursive")
	preserve, _ := cmd.Flags().GetBool("preserve")

	// The SFTP mode intentionally omits the "preserve" implementation
	// for now: SFTP does support preserving modes/times via Chmod /
	// Chtimes, but only on filesystems that back them. The flag is
	// accepted for parity with `usque scp` and silently no-op'd.
	_ = preserve

	if len(args) < 2 {
		return errors.New("usage: usque sftp [-w password] [-r] source ... dest")
	}

	// 1. 先解析参数，准确找出远程主机信息
	// Classify operands as local or remote. Mixed form is the only
	// form supported (mirrors OpenSSH scp).
	parsed, err := parseSCPArgs(args)
	if err != nil {
		return err
	}
	sources := parsed[:len(parsed)-1]
	target := &parsed[len(parsed)-1]

	// The remote side is whichever side is *not* fully local. We need
	// its host/user/port to dial the tunnel.
	var remote *scpEntry
	if target.Kind == scpRemote {
		remote = target
		for _, s := range sources {
			if s.Kind != scpLocal {
				return errors.New("sftp: at most one remote operand is allowed")
			}
		}
	} else {
		for _, s := range sources {
			if s.Kind == scpRemote {
				remote = &s
				break
			}
		}
	}
	if remote == nil {
		return errors.New("sftp: exactly one operand must be on the remote side")
	}

	// 检查用户是否通过 -P / --port 显式指定了端口
	if p, err := cmd.Flags().GetInt("port"); err == nil && p != 0 {
    	remote.Port = p
    }

	// 2. 使用解析出来的 remote 信息来拼接友好的提示文案
	// Resolve the password. -w takes precedence; otherwise we prompt
	// on the terminal (echo disabled) so the password never appears
	// in shell history.
	password, _ := cmd.Flags().GetString("password")
	if password == "" {
		displayTarget := remote.Host
		if remote.User != "" {
			displayTarget = fmt.Sprintf("%s@%s", remote.User, remote.Host)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "SFTP password for %s: ", displayTarget)
		pw, err := readPasswordForSFTP(cmd)
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		password = pw
	}
    
	log.Printf("Establishing MASQUE connection to %s:%d", remote.Host, remote.Port)
	client, cleanup, err := establishSSHTunnel(cmd, remote.User, remote.Host, remote.Port, password, "sftp")
	if err != nil {
		return err
	}
	defer cleanup()

	// Early detection of incompatible SSH servers via the SSH-2.0
	// banner captured during the handshake. dropbear (the default
	// SSH server on OpenWrt and most embedded Linux) does not
	// provide an SFTP subsystem, so we fail fast with a clear hint
	// rather than waiting for sftp.NewClient to time out.
	if isDropbearServer() {
		return fmt.Errorf("sftp: the remote SSH server is dropbear (%s), which does not provide an sftp-server subsystem. Use `usque scp` instead — dropbear ships its own scp binary", sshServerBanner)
	}

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		// Fallback hint: even if we didn't recognise the banner
		// ahead of time (e.g. some other minimal SSH server), the
		// failure pattern is identical to the dropbear case.
		if strings.Contains(err.Error(), "unexpectedly closed") || strings.Contains(err.Error(), "unexpected EOF") {
			return fmt.Errorf("sftp subsystem: %w\nhint: the remote SSH server appears not to support SFTP (dropbear does not provide sftp-server by default). Use `usque scp` instead, which works with any SSH server that has a `scp` binary", err)
		}
		return fmt.Errorf("sftp subsystem: %w", err)
	}
	defer sftpClient.Close()

	ctx := cmd.Context()

	// Dispatch: upload or download, based on which side is remote.
	if target.Kind == scpRemote {
		// Local -> remote. The single remote target is the destination.
		// If multiple sources are given, the target must be a directory
		// (existing or to be created).
		if len(sources) > 1 {
			if err := sftpEnsureRemoteDir(ctx, sftpClient, target.Path); err != nil {
				return err
			}
		}
		for _, src := range sources {
			localSrc := src.Path
			// If the remote target is an existing directory, place
			// each source inside it using the local basename,
			// matching OpenSSH scp semantics.
			remoteDst := target.Path
			if info, err := sftpClient.Stat(target.Path); err == nil && info.IsDir() {
				remoteDst = joinRemoteDir(target.Path, filepath.Base(localSrc))
			} else if len(sources) > 1 {
				return fmt.Errorf("sftp: target %q is not a directory", target.Path)
			}
			if err := sftpUpload(ctx, sftpClient, localSrc, remoteDst, recursive); err != nil {
				return fmt.Errorf("sftp: upload %s: %w", localSrc, err)
			}
		}
		log.Printf("SFTP upload done (%d source(s))", len(sources))
		os.Exit(0)
		return nil
	}

	// Remote -> local. The single remote source is the source; the
	// local target is the destination.
	if len(sources) > 1 {
		return errors.New("sftp: at most one remote source is allowed")
	}
	remoteSrc := ""
	for _, s := range sources {
		if s.Kind == scpRemote {
			remoteSrc = s.Path
		}
	}
	if remoteSrc == "" {
		return errors.New("sftp: no remote source given")
	}
	localDst := target.Path
	// Mirror OpenSSH scp: if local target is a directory, place the
	// file inside it using the remote basename.
	if info, err := os.Stat(localDst); err == nil && info.IsDir() {
		localDst = filepath.Join(localDst, filepath.Base(toRemoteSlash(remoteSrc)))
	} else if strings.HasSuffix(localDst, "/") || strings.HasSuffix(localDst, `\`) {
		localDst = filepath.Join(strings.TrimRight(localDst, "/\\"), filepath.Base(toRemoteSlash(remoteSrc)))
	}
	if err := sftpDownload(ctx, sftpClient, remoteSrc, localDst, recursive); err != nil {
		return fmt.Errorf("sftp: download %s: %w", remoteSrc, err)
	}
	log.Printf("SFTP download done -> %s", localDst)
	os.Exit(0)
	return nil
}

// sftpParseArgs was previously a separate helper but the same parsing
// logic already exists in scp.go as parseSCPArgs; we just delegate to
// it now to keep a single source of truth for operand classification.

// sftpUpload copies a local path to a remote path via SFTP. Recurses
// into directories when recursive is true. All writes go to a
// .usque_tmp staging file in the same parent directory, then rename
// into place — this gives the same atomic-promotion guarantee the scp
// path provides and avoids half-written files at the destination.
func sftpUpload(ctx context.Context, c *sftp.Client, localPath, remotePath string, recursive bool) error {
	info, err := os.Stat(localPath)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if !recursive {
			return fmt.Errorf("%s: is a directory (use -r)", localPath)
		}
		// remotePath is the final remote directory we want to populate.
		// The caller is responsible for appending the local basename
		// (see runSFTP), so sftpUpload just uses the path as-is.
		if err := sftpEnsureRemoteDir(ctx, c, remotePath); err != nil {
			return err
		}
		entries, err := os.ReadDir(localPath)
		if err != nil {
			return err
		}
		for _, e := range entries {
			src := filepath.Join(localPath, e.Name())
			dst := joinRemoteDir(remotePath, e.Name())
			if err := sftpUpload(ctx, c, src, dst, recursive); err != nil {
				return err
			}
		}
		return nil
	}
	return sftpUploadFile(ctx, c, localPath, remotePath, info)
}

func sftpUploadFile(ctx context.Context, c *sftp.Client, localPath, remotePath string, info os.FileInfo) error {
	// Decide the parent directory and target filename. If the remote
	// target is itself a directory (or ends in a separator), the
	// final filename is the local basename. Otherwise the user
	// specified a full path; we keep its basename.
	var parent, base string
	if strings.HasSuffix(remotePath, "/") || strings.HasSuffix(remotePath, `\`) {
		parent = strings.TrimRight(remotePath, "/\\")
		base = filepath.Base(localPath)
	} else {
		// Could be a dir or a full file path. Stat to find out.
		if st, err := c.Stat(remotePath); err == nil && st.IsDir() {
			parent = remotePath
			base = filepath.Base(localPath)
		} else {
			parent = remoteDirParentAny(remotePath)
			base = filepath.Base(toRemoteSlash(remotePath))
			if base == "" || base == "." || base == "/" || base == `\` {
				base = filepath.Base(localPath)
			}
		}
	}
	if err := sftpEnsureRemoteDir(ctx, c, parent); err != nil {
		return err
	}
	staging := joinRemoteDir(parent, base) + ".usque_tmp"

	log.Printf("sftp: uploading %s -> %s (%d bytes)", localPath, remotePath, info.Size())
	src, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := c.OpenFile(staging, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return fmt.Errorf("sftp: open staging %s: %w", staging, err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		_ = c.Remove(staging)
		return fmt.Errorf("sftp: write %s: %w", staging, err)
	}
	if err := dst.Close(); err != nil {
		_ = c.Remove(staging)
		return fmt.Errorf("sftp: close %s: %w", staging, err)
	}
	// sftp.OpenFile doesn't accept a mode argument (the server picks the
	// umask-derived default), so we apply the source file's mode
	// explicitly after closing the handle. SFTP Chmod on the staging
	// file before the rename propagates the mode to the final path.
	_ = c.Chmod(staging, info.Mode().Perm())

	// Atomic-promote: if a file at the final path exists, remove it
	// first so Rename acts as an overwrite. Same-volume renames are
	// atomic on POSIX file systems and NTFS.
	if _, err := c.Stat(remotePath); err == nil {
		if err := c.Remove(remotePath); err != nil {
			return fmt.Errorf("sftp: remove existing %s: %w", remotePath, err)
		}
	}
	if err := c.Rename(staging, remotePath); err != nil {
		return fmt.Errorf("sftp: rename %s -> %s: %w", staging, remotePath, err)
	}
	return nil
}

// sftpDownload is the mirror of sftpUpload for the remote-to-local
// direction.
func sftpDownload(ctx context.Context, c *sftp.Client, remotePath, localPath string, recursive bool) error {
	info, err := c.Stat(remotePath)
	if err != nil {
		return fmt.Errorf("sftp: stat %s: %w", remotePath, err)
	}
	if info.IsDir() {
		if !recursive {
			return fmt.Errorf("%s: is a directory (use -r)", remotePath)
		}
		if err := os.MkdirAll(localPath, 0o755); err != nil {
			return err
		}
		entries, err := c.ReadDir(remotePath)
		if err != nil {
			return err
		}
		for _, e := range entries {
			r := joinRemoteDir(remotePath, e.Name())
			l := filepath.Join(localPath, e.Name())
			if e.IsDir() {
				if err := sftpDownload(ctx, c, r, l, recursive); err != nil {
					return err
				}
			} else {
				if err := sftpDownloadFile(ctx, c, r, l); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return sftpDownloadFile(ctx, c, remotePath, localPath)
}

func sftpDownloadFile(ctx context.Context, c *sftp.Client, remotePath, localPath string) error {
	log.Printf("sftp: downloading %s -> %s", remotePath, localPath)
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return err
	}
	src, err := c.Open(remotePath)
	if err != nil {
		return fmt.Errorf("sftp: open %s: %w", remotePath, err)
	}
	defer src.Close()
	dst, err := os.OpenFile(localPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return err
	}
	return dst.Close()
}

// sftpEnsureRemoteDir is the SFTP equivalent of `mkdir -p`. SFTP's
// MkdirAll does the recursion itself, so the platform detection that
// the scp path needed (PowerShell vs. mkdir -p) is unnecessary here.
func sftpEnsureRemoteDir(ctx context.Context, c *sftp.Client, remoteDir string) error {
	if remoteDir == "" || remoteDir == "." || remoteDir == "/" || remoteDir == `\` {
		return nil
	}
	// SFTP's MkdirAll returns nil on success and an error if any
	// component already exists. We pre-stat so idempotent retries
	// don't print a spurious "already exists" log; this keeps the
	// SFTP path quiet in the common case.
	if _, err := c.Stat(remoteDir); err == nil {
		return nil
	}
	return c.MkdirAll(remoteDir)
}

// readPasswordForSFTP reads a password from the terminal with echo
// disabled. On non-interactive stdin (CI, pipe) it returns an error
// rather than echoing the password back.
func readPasswordForSFTP(cmd *cobra.Command) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("sftp: -w is required when stdin is not a terminal")
	}
	pw, err := term.ReadPassword(fd)
	if err != nil {
		return "", err
	}
	fmt.Fprintln(cmd.ErrOrStderr())
	return string(pw), nil
}

// joinRemoteDir joins two path components using "/", which is what the
// SFTP protocol expects regardless of the remote file system.
func joinRemoteDir(dir, name string) string {
	if dir == "" {
		return "/" + name
	}
	if strings.HasSuffix(dir, "/") {
		return dir + name
	}
	return dir + "/" + name
}

// toRemoteSlash converts a Windows-style backslash path to forward
// slashes, which is the form SFTP paths conventionally use.
func toRemoteSlash(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// remoteDirParentAny returns the parent directory portion of a remote
// path, handling both "/" and "\" as separators (SFTP servers on
// Windows commonly accept either).
func remoteDirParentAny(p string) string {
	p = strings.TrimRight(p, "/\\")
	idx := strings.LastIndexAny(p, "/\\")
	if idx < 0 {
		return "."
	}
	parent := p[:idx]
	if parent == "" {
		return "/"
	}
	return parent
}
