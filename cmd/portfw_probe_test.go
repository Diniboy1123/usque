package cmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Diniboy1123/usque/config"
	"github.com/quic-go/quic-go/quicvarint"
)

// A subprocess gives the unchanged, non-cancellable command a bounded lifetime.
func TestPortfwProbeChild(t *testing.T) {
	if os.Getenv("USQUE_PROBE_CHILD") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			rootCmd.SetArgs(os.Args[i+1:])
			if err := rootCmd.Execute(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	}
	t.Fatal("missing child command arguments")
}

func probePeer(t *testing.T) (string, string, <-chan struct{}, <-chan []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	opened, packets := make(chan struct{}, 1), make(chan []byte, 32)
	peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case opened <- struct{}{}:
		default:
		}
		reader := quicvarint.NewReader(r.Body)
		for {
			kind, err := quicvarint.Read(reader)
			if err != nil {
				return
			}
			size, err := quicvarint.Read(reader)
			if err != nil || size > 65536 {
				return
			}
			payload := make([]byte, int(size))
			if _, err := io.ReadFull(reader, payload); err != nil {
				return
			}
			if kind == 0 && len(payload) > 0 {
				select {
				case packets <- payload:
				default:
				}
			}
		}
	}))
	peer.EnableHTTP2 = true
	peer.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	peer.StartTLS()
	t.Cleanup(peer.Close)
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{PrivateKey: base64.StdEncoding.EncodeToString(private), EndpointPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})), EndpointV4: "127.0.0.1", EndpointH2V4: "127.0.0.1", IPv4: "100.64.0.2", IPv6: "fd00::2"}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "dummy-config.json")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	return path, fmt.Sprint(peer.Listener.Addr().(*net.TCPAddr).Port), opened, packets
}

func runProbeChild(t *testing.T, args []string) (context.Context, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	exe, err := os.Executable()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, exe, append([]string{"-test.run=^TestPortfwProbeChild$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "USQUE_PROBE_CHILD=1", "HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "NO_PROXY=*")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	ready, exited := make(chan struct{}, 1), make(chan struct{})
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "Virtual tunnel created") {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
		}
		_ = cmd.Wait()
		close(exited)
	}()
	t.Cleanup(func() { cancel(); <-exited })
	select {
	case <-ready:
	case <-exited:
		t.Fatal("child exited before forwarding startup")
	case <-ctx.Done():
		t.Fatal("child did not reach forwarding startup")
	}
	return ctx, exited
}

func TestPortfwStartupProbe(t *testing.T) {
	cases := []struct {
		name                string
		local, remote, idle bool
	}{
		{name: "local", local: true},
		{name: "local-idle", local: true, idle: true},
		{name: "remote", remote: true},
		{name: "mixed", local: true, remote: true},
		{name: "no-mappings"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, endpointPort, opened, packets := probePeer(t)
			args := []string{"--config", cfg, "portfw", "--http2", "--connect-port", endpointPort, "--no-tunnel-ipv6"}
			var localAddr string
			if tc.local {
				reservation, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				localAddr = reservation.Addr().String()
				port := reservation.Addr().(*net.TCPAddr).Port
				if err := reservation.Close(); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-L", fmt.Sprintf("127.0.0.1:%d:100.64.0.3:8443", port))
			}
			if tc.remote {
				args = append(args, "-R", "100.64.0.2:8443:127.0.0.1:8443")
			}
			if tc.idle {
				args = append(args, "--dont-always-reconnect")
			}
			ctx, exited := runProbeChild(t, args)
			localOnly := tc.local && !tc.remote
			if localOnly {
				if !tc.idle {
					select {
					case <-opened:
					case <-ctx.Done():
						t.Fatal("default tunnel never connected")
					}
				}
				select {
				case packet := <-packets:
					t.Fatalf("local-only startup sent a probe packet: %x", packet)
				case <-time.After(150 * time.Millisecond):
				}
				if tc.idle {
					select {
					case <-opened:
						t.Fatal("idle tunnel started before client activity")
					default:
					}
				}
				var conn net.Conn
				var err error
				for ctx.Err() == nil {
					conn, err = net.DialTimeout("tcp", localAddr, 100*time.Millisecond)
					if err == nil {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if conn == nil {
					t.Fatalf("local listener unavailable: %v", err)
				}
				defer func() { _ = conn.Close() }()
			}
			for {
				select {
				case packet := <-packets:
					if len(packet) < 24 || packet[0]>>4 != 4 {
						continue
					}
					header := int(packet[0]&15) * 4
					if len(packet) < header+8 {
						continue
					}
					port := binary.BigEndian.Uint16(packet[header+2 : header+4])
					if localOnly {
						if packet[9] == 17 && port == 53 {
							t.Fatal("local-only forwarding sent a DNS probe")
						}
						if packet[9] == 6 && port == 8443 && net.IP(packet[16:20]).Equal(net.IPv4(100, 64, 0, 3)) {
							return
						}
					} else if packet[9] == 17 && port == 53 && bytes.Contains(packet[header+8:], []byte("\x0ccloudflareok\x03com\x00")) {
						return // Remote and zero-mapping modes retain the startup activation attempt.
					}
				case <-exited:
					t.Fatal("child exited before expected forwarding activity")
				case <-ctx.Done():
					t.Fatal("expected tunnel packet was not observed")
				}
			}
		})
	}
}
