package internal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/txthinking/runnergroup"
	"github.com/txthinking/socks5"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// SOCKS5Config holds listen address, auth, tunnel dialers, and timeouts for [SOCKS5Server].
type SOCKS5Config struct {
	Addr       string
	Username   string
	Password   string
	Resolver   *TunnelDNSResolver
	TunNet     *netstack.Net
	TCPTimeout time.Duration // 0 = no deadline on TCP CONNECT relay
	UDPTimeout time.Duration // 0 = no deadline on remote UDP reads
	Logger     *log.Logger
	// DialTimeout bounds how long dialTCP/dialUDP wait for a connection through
	// the tunnel. Without this, a broken tunnel causes netstack TCP SYN retransmits
	// that can block for minutes. 0 means no timeout (not recommended).
	DialTimeout time.Duration
	// UDPBindAddr is the address the UDP relay socket listens on. When empty,
	// it defaults to Addr (same as TCP). Use this when TCP is behind a TLS
	// proxy (e.g. stunnel) on localhost but UDP must be directly reachable
	// from the outside. Example: Addr="127.0.0.1:6012", UDPBindAddr="0.0.0.0:3328".
	UDPBindAddr string
	// UDPAdvertiseAddr is the address returned to clients in the UDP ASSOCIATE
	// reply (BND.ADDR). When empty, the server's TCP listen address is used,
	// which is correct for local/LAN use. Set this to the server's public IP
	// (and optionally port) when the server is behind NAT or on a remote host,
	// so clients can reach the UDP relay socket from the outside.
	// Accepted formats: "1.2.3.4", "1.2.3.4:1080", "[::1]", "[::1]:1080".
	// When no port is given, the port from Addr is used.
	UDPAdvertiseAddr string
}

// SOCKS5Server wraps txthinking/socks5; DialTCP/DialUDP are package globals (last NewSOCKS5Server wins).
type SOCKS5Server struct {
	cfg    SOCKS5Config
	server *socks5.Server
}

func NewSOCKS5Server(cfg SOCKS5Config) (*SOCKS5Server, error) {
	if cfg.Resolver == nil {
		return nil, errors.New("socks5: Resolver is required")
	}
	if cfg.TunNet == nil {
		return nil, errors.New("socks5: TunNet is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}

	if cfg.UDPAdvertiseAddr != "" {
		if _, err := resolveAdvertiseAddr(cfg.UDPAdvertiseAddr, cfg.Addr); err != nil {
			return nil, fmt.Errorf("socks5: invalid udp-advertise-addr: %w", err)
		}
	}

	// BND.ADDR for UDP ASSOCIATE is set in TCPHandle via c.LocalAddr(), not here.
	srv, err := socks5.NewClassicServer(
		cfg.Addr,
		"",
		cfg.Username,
		cfg.Password,
		int(cfg.TCPTimeout/time.Second),
		int(cfg.UDPTimeout/time.Second),
	)
	if err != nil {
		return nil, err
	}

	s := &SOCKS5Server{cfg: cfg, server: srv}
	socks5.DialTCP = s.dialTCP
	socks5.DialUDP = s.dialUDP
	return s, nil
}

// udpReadBufPool avoids allocating 64 KiB per SOCKS5 UDP datagram. The stock
// txthinking ListenAndServe uses make([]byte, 65507) every ReadFromUDP, which
// drives heap growth proportional to DHT/uTP packet rate (statviz stays high
// until a full GC cycle, and can look like a leak under load).
var udpReadBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65507)
		return &b
	},
}

// udpWireBufPool holds SOCKS5 UDP encapsulation frames for replies to the client.
// socks5.Datagram.Bytes() allocates a fresh slice every call; that dominated heap
// under uTP/DHT when multiplied by packet rate.
var udpWireBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 65507)
		return &b
	},
}

var tcpRelayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// Each SOCKS5 UDP datagram from the client is handled in a goroutine that must
// keep the pooled read buffer until UDPHandle returns. Without a bound, DHT/uTP
// packet rate creates unbounded concurrency and the pool grows one ~64 KiB buffer
// per in-flight handler (see heap: flat on udpReadBufPool.Get in listenAndServe).
const maxConcurrentUDPClientHandlers = 256

var udpClientHandleSem = make(chan struct{}, maxConcurrentUDPClientHandlers)

// Remote UDP relay goroutines (one per distinct client→dst flow) also pin a 64 KiB
// udpReadBufPool buffer. DHT opens many flows; cap relays so heap stays bounded.
const maxConcurrentUDPRelayHandlers = 256

var udpRelaySem = make(chan struct{}, maxConcurrentUDPRelayHandlers)

func (s *SOCKS5Server) Start() error {
	return s.listenAndServe()
}

// dialContext returns a context (and cancel func) bounded by DialTimeout.
// The caller must call cancel when the dial completes.
func (s *SOCKS5Server) dialContext() (context.Context, context.CancelFunc) {
	if s.cfg.DialTimeout > 0 {
		return context.WithTimeout(context.Background(), s.cfg.DialTimeout)
	}
	return context.Background(), func() {}
}

// udpListenAddr returns the address the UDP relay should bind to.
// Falls back to the TCP listen address when UDPBindAddr is not set.
func (s *SOCKS5Server) udpListenAddr() string {
	if s.cfg.UDPBindAddr != "" {
		return s.cfg.UDPBindAddr
	}
	return s.server.Addr
}

// listenAndServe mirrors socks5.Server.ListenAndServe but the UDP relay uses
// udpReadBufPool. Datagrams reference the buffer until UDPHandle returns.
func (s *SOCKS5Server) listenAndServe() error {
	srv := s.server
	srv.Handle = socks5.Handler(s)

	addr, err := net.ResolveTCPAddr("tcp", srv.Addr)
	if err != nil {
		return err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	srv.RunnerGroup.Add(&runnergroup.Runner{
		Start: func() error {
			for {
				c, err := l.AcceptTCP()
				if err != nil {
					return err
				}
				go func(c *net.TCPConn) {
					defer func() { _ = c.Close() }()
					if err := srv.Negotiate(c); err != nil {
						log.Println(err)
						return
					}
					r, err := srv.GetRequest(c)
					if err != nil {
						log.Println(err)
						return
					}
					if err := srv.Handle.TCPHandle(srv, c, r); err != nil {
						log.Println(err)
					}
				}(c)
			}
		},
		Stop: func() error {
			return l.Close()
		},
	})
	addr1, err := net.ResolveUDPAddr("udp", s.udpListenAddr())
	if err != nil {
		_ = l.Close()
		return err
	}
	s.cfg.Logger.Printf("UDP relay listening on %s", addr1)
	srv.UDPConn, err = net.ListenUDP("udp", addr1)
	if err != nil {
		_ = l.Close()
		return err
	}
	srv.RunnerGroup.Add(&runnergroup.Runner{
		Start: func() error {
			for {
				bp := udpReadBufPool.Get().(*[]byte)
				buf := *bp
				n, addr, err := srv.UDPConn.ReadFromUDP(buf)
				if err != nil {
					udpReadBufPool.Put(bp)
					return err
				}
				udpClientHandleSem <- struct{}{}
				go func(addr *net.UDPAddr, bp *[]byte, n int) {
					defer func() {
						udpReadBufPool.Put(bp)
						<-udpClientHandleSem
					}()
					payload := (*bp)[:n]
					d, err := socks5.NewDatagramFromBytes(payload)
					if err != nil {
						log.Println(err)
						return
					}
					if d.Frag != 0x00 {
						return
					}
					if err := srv.Handle.UDPHandle(srv, addr, d); err != nil {
						log.Println(err)
					}
				}(addr, bp, n)
			}
		},
		Stop: func() error {
			return srv.UDPConn.Close()
		},
	})
	return srv.RunnerGroup.Wait()
}

func (s *SOCKS5Server) dialTCP(network, _, raddr string) (net.Conn, error) {
	ctx, cancel := s.dialContext()
	defer cancel()

	// Default (tunnel DNS): one netstack lookup + dial, same as the old things-go WithDial path.
	if s.cfg.Resolver.TunNet != nil {
		return s.cfg.TunNet.DialContext(ctx, network, raddr)
	}
	host, port, err := net.SplitHostPort(raddr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		addr, err := net.ResolveTCPAddr(network, raddr)
		if err != nil {
			return nil, err
		}
		return s.cfg.TunNet.DialContextTCP(ctx, addr)
	}
	rctx, resIP, err := s.cfg.Resolver.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	addr, err := net.ResolveTCPAddr(network, net.JoinHostPort(resIP.String(), port))
	if err != nil {
		return nil, err
	}
	return s.cfg.TunNet.DialContextTCP(rctx, addr)
}

func (s *SOCKS5Server) dialUDP(network, laddr, raddr string) (net.Conn, error) {
	ctx, cancel := s.dialContext()
	defer cancel()

	if s.cfg.Resolver.TunNet != nil {
		c, err := s.cfg.TunNet.DialContext(ctx, network, raddr)
		if err != nil {
			if strings.Contains(err.Error(), "port is in use") {
				return nil, &net.AddrError{Err: "address already in use", Addr: laddr}
			}
			return nil, err
		}
		return c, nil
	}
	host, port, err := net.SplitHostPort(raddr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		addr, err := net.ResolveUDPAddr(network, raddr)
		if err != nil {
			return nil, err
		}
		return s.cfg.TunNet.DialUDP(nil, addr)
	}
	_, resIP, err := s.cfg.Resolver.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	addr, err := net.ResolveUDPAddr(network, net.JoinHostPort(resIP.String(), port))
	if err != nil {
		return nil, err
	}
	rc, err := s.cfg.TunNet.DialUDP(nil, addr)
	if err != nil {
		if strings.Contains(err.Error(), "port is in use") {
			return nil, &net.AddrError{Err: "address already in use", Addr: laddr}
		}
		return nil, err
	}
	return rc, nil
}

func (s *SOCKS5Server) TCPHandle(srv *socks5.Server, c *net.TCPConn, r *socks5.Request) error {
	switch r.Cmd {
	case socks5.CmdConnect:
		rc, err := r.Connect(c)
		if err != nil {
			return err
		}
		defer func() { _ = rc.Close() }()

		done := make(chan struct{})

		// rc → c: when the remote closes, signal the client side.
		go func() {
			defer close(done)
			bp := tcpRelayBufPool.Get().(*[]byte)
			buf := *bp
			defer tcpRelayBufPool.Put(bp)
			for {
				if srv.TCPTimeout != 0 {
					if err := rc.SetDeadline(time.Now().Add(time.Duration(srv.TCPTimeout) * time.Second)); err != nil {
						return
					}
				}
				n, err := rc.Read(buf)
				if err != nil {
					// Remote closed — half-close the client write direction
					// so the client learns immediately instead of hanging.
					_ = c.CloseWrite()
					return
				}
				if _, err := c.Write(buf[:n]); err != nil {
					return
				}
			}
		}()

		// c → rc
		bp := tcpRelayBufPool.Get().(*[]byte)
		buf := *bp
		defer tcpRelayBufPool.Put(bp)
		for {
			if srv.TCPTimeout != 0 {
				if err := c.SetDeadline(time.Now().Add(time.Duration(srv.TCPTimeout) * time.Second)); err != nil {
					return nil
				}
			}
			n, err := c.Read(buf)
			if err != nil {
				return nil
			}
			if _, err := rc.Write(buf[:n]); err != nil {
				return nil
			}
		}

	case socks5.CmdUDP:
		udpAddr := net.Addr(c.LocalAddr())
		if s.cfg.UDPAdvertiseAddr != "" {
			advertised, err := resolveAdvertiseAddr(s.cfg.UDPAdvertiseAddr, s.server.Addr)
			if err != nil {
				return fmt.Errorf("failed to resolve udp-advertise-addr: %w", err)
			}
			udpAddr = advertised
		}
		caddr, err := r.UDP(c, udpAddr)
		if err != nil {
			return err
		}
		ch := make(chan byte)
		defer close(ch)
		srv.AssociatedUDP.Set(caddr.String(), ch, -1)
		defer srv.AssociatedUDP.Delete(caddr.String())
		_, _ = io.Copy(io.Discard, c)
		return nil
	}

	return socks5.ErrUnsupportCmd
}

// UDPHandle is like txthinking DefaultHandle.UDPHandle but does not use srv.UDPSrc.
func (s *SOCKS5Server) UDPHandle(srv *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	src := addr.String()
	dst := d.Address()
	var ch chan byte
	if srv.LimitUDP {
		any, ok := srv.AssociatedUDP.Get(src)
		if !ok {
			return fmt.Errorf("udp address %s is not associated with tcp", src)
		}
		ch = any.(chan byte)
	}
	send := func(ue *socks5.UDPExchange, data []byte) error {
		select {
		case <-ch:
			return fmt.Errorf("udp address %s is not associated with tcp", src)
		default:
			_, err := ue.RemoteConn.Write(data)
			return err
		}
	}

	if iue, ok := srv.UDPExchanges.Get(src + dst); ok {
		return send(iue.(*socks5.UDPExchange), d.Data)
	}

	rc, err := socks5.DialUDP("udp", "", dst)
	if err != nil {
		return err
	}
	ue := &socks5.UDPExchange{
		ClientAddr: addr,
		RemoteConn: rc,
	}
	if err := send(ue, d.Data); err != nil {
		_ = ue.RemoteConn.Close()
		return err
	}
	srv.UDPExchanges.Set(src+dst, ue, -1)

	// Block if too many relay goroutines; each holds a pooled read buffer until exit.
	udpRelaySem <- struct{}{}
	go func(ue *socks5.UDPExchange, dst string) {
		defer func() {
			_ = ue.RemoteConn.Close()
			srv.UDPExchanges.Delete(ue.ClientAddr.String() + dst)
			<-udpRelaySem
		}()
		// A stack [65507]byte here escapes to the heap per goroutine (~64 KiB each);
		// with hundreds of DHT peers that dominates inuse_space.
		rbp := udpReadBufPool.Get().(*[]byte)
		b := *rbp
		defer udpReadBufPool.Put(rbp)
		for {
			select {
			case <-ch:
				return
			default:
				// Use full time.Duration (NewClassicServer only gets whole seconds).
				// int(cfg.UDPTimeout/time.Second) truncates e.g. 500ms to 0 → no deadline → stuck relays.
				if t := s.cfg.UDPTimeout; t > 0 {
					if err := ue.RemoteConn.SetReadDeadline(time.Now().Add(t)); err != nil {
						s.cfg.Logger.Printf("set read deadline on %s: %v", dst, err)
						return
					}
				}
				n, err := ue.RemoteConn.Read(b)
				if err != nil {
					return
				}
				a, haddr, hport, err := socks5.ParseAddress(dst)
				if err != nil {
					s.cfg.Logger.Printf("parse address %s: %v", dst, err)
					return
				}
				if a == socks5.ATYPDomain {
					haddr = haddr[1:]
				}
				dg := socks5.NewDatagram(a, haddr, hport, b[:n])
				wp := udpWireBufPool.Get().(*[]byte)
				w := (*wp)[:0]
				w = append(w, dg.Rsv...)
				w = append(w, dg.Frag)
				w = append(w, dg.Atyp)
				w = append(w, dg.DstAddr...)
				w = append(w, dg.DstPort...)
				w = append(w, dg.Data...)
				_, err = srv.UDPConn.WriteToUDP(w, ue.ClientAddr)
				*wp = w
				udpWireBufPool.Put(wp)
				if err != nil {
					return
				}
			}
		}
	}(ue, dst)

	return nil
}

// resolveAdvertiseAddr resolves the user-supplied UDP advertise address into a
// *net.UDPAddr. advertise may be:
//   - bare IP:           "1.2.3.4"  or  "::1"
//   - IP+port:           "1.2.3.4:5000"  or  "[::1]:5000"
//
// When no port is present in advertise, the port is taken from listenAddr
// (the server's TCP/UDP bind address, e.g. "0.0.0.0:1080").
func resolveAdvertiseAddr(advertise, listenAddr string) (*net.UDPAddr, error) {
	// Try parsing as host:port first.
	host, port, err := net.SplitHostPort(advertise)
	if err != nil {
		// No port — treat the whole string as a bare IP/host.
		host = advertise
		port = ""
	}

	if port == "" {
		// Fall back to the port from the listen address.
		_, listenPort, err := net.SplitHostPort(listenAddr)
		if err != nil {
			return nil, fmt.Errorf("cannot determine port from listen address %q: %w", listenAddr, err)
		}
		port = listenPort
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("udp-advertise-addr %q is not a valid IP address", host)
	}

	return net.ResolveUDPAddr("udp", net.JoinHostPort(ip.String(), port))
}
