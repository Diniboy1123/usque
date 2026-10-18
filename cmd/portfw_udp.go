package cmd

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Diniboy1123/usque/internal"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const maxUDPPacketSize = 65535

// udpSession represents a single client UDP flow. The socket is connected to
// the remote destination, while lastSeen drives idle expiry.
type udpSession struct {
	conn     net.Conn
	lastSeen atomic.Int64
}

func (s *udpSession) touch() {
	s.lastSeen.Store(time.Now().UnixNano())
}

func (s *udpSession) idleFor() time.Duration {
	return time.Since(time.Unix(0, s.lastSeen.Load()))
}

// udpSessionTable maps client addresses to UDP flows and expires idle ones.
type udpSessionTable struct {
	mu        sync.Mutex
	sessions  map[string]*udpSession
	timeout   time.Duration
	writeBack func([]byte, net.Addr) error
	done      chan struct{}
	closeOnce sync.Once
}

func newUDPSessionTable(timeout time.Duration, writeBack func([]byte, net.Addr) error) *udpSessionTable {
	table := &udpSessionTable{
		sessions:  make(map[string]*udpSession),
		timeout:   timeout,
		writeBack: writeBack,
		done:      make(chan struct{}),
	}
	reapInterval := timeout / 2
	if reapInterval <= 0 {
		reapInterval = time.Millisecond
	}
	go table.reap(reapInterval)
	return table
}

// get returns the flow for client, creating it with dial when needed.
func (t *udpSessionTable) get(key string, client net.Addr, dial func() (net.Conn, error)) (*udpSession, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if session, ok := t.sessions[key]; ok {
		return session, nil
	}

	conn, err := dial()
	if err != nil {
		return nil, err
	}

	session := &udpSession{conn: conn}
	session.touch()
	t.sessions[key] = session
	go t.readResponses(key, client, session)
	return session, nil
}

// readResponses forwards datagrams coming back over the flow to the client.
func (t *udpSessionTable) readResponses(key string, client net.Addr, session *udpSession) {
	buf := make([]byte, maxUDPPacketSize)
	for {
		n, err := session.conn.Read(buf)
		if err != nil {
			t.remove(key, session)
			return
		}
		session.touch()
		if err := t.writeBack(buf[:n], client); err != nil {
			log.Printf("UDP response write to %s failed: %v", client, err)
			t.remove(key, session)
			return
		}
	}
}

func (t *udpSessionTable) remove(key string, session *udpSession) {
	t.mu.Lock()
	if t.sessions[key] == session {
		delete(t.sessions, key)
	}
	t.mu.Unlock()
	_ = session.conn.Close()
}

func (t *udpSessionTable) reap(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
		}

		var expired []*udpSession
		t.mu.Lock()
		for key, session := range t.sessions {
			if session.idleFor() > t.timeout {
				delete(t.sessions, key)
				expired = append(expired, session)
			}
		}
		t.mu.Unlock()

		for _, session := range expired {
			_ = session.conn.Close()
		}
	}
}

func (t *udpSessionTable) closeAll() {
	t.closeOnce.Do(func() { close(t.done) })

	t.mu.Lock()
	sessions := t.sessions
	t.sessions = make(map[string]*udpSession)
	t.mu.Unlock()

	for _, session := range sessions {
		_ = session.conn.Close()
	}
}

// forwardUDPPortLocal listens for UDP datagrams on the local machine and
// forwards each client flow through the MASQUE tunnel.
func forwardUDPPortLocal(tunNet *netstack.Net, pm internal.PortMapping, udpTimeout time.Duration) error {
	localAddr := net.JoinHostPort(pm.BindAddress, strconv.Itoa(pm.LocalPort))
	listener, err := net.ListenPacket("udp", localAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", localAddr, err)
	}
	defer func() { _ = listener.Close() }()

	remoteAddrPort, err := netip.ParseAddrPort(net.JoinHostPort(pm.RemoteIP, strconv.Itoa(pm.RemotePort)))
	if err != nil {
		return fmt.Errorf("invalid remote address: %w", err)
	}

	sessions := newUDPSessionTable(udpTimeout, func(payload []byte, client net.Addr) error {
		_, err := listener.WriteTo(payload, client)
		return err
	})
	defer sessions.closeAll()

	log.Printf("Local UDP forwarding: Listening on %s, forwarding to remote %s", localAddr, remoteAddrPort)

	buf := make([]byte, maxUDPPacketSize)
	for {
		n, client, err := listener.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("UDP read error on %s: %w", localAddr, err)
		}

		key := client.String()
		session, err := sessions.get(key, client, func() (net.Conn, error) {
			return tunNet.DialContext(context.Background(), "udp", remoteAddrPort.String())
		})
		if err != nil {
			log.Printf("Failed to open UDP flow to %s for client %s: %v", remoteAddrPort, client, err)
			continue
		}

		session.touch()
		if _, err := session.conn.Write(buf[:n]); err != nil {
			log.Printf("UDP write to %s failed: %v", remoteAddrPort, err)
			sessions.remove(key, session)
		}
	}
}

// forwardUDPPortRemote listens for UDP datagrams inside the MASQUE tunnel and
// forwards each client flow to a local UDP service.
func forwardUDPPortRemote(tunNet *netstack.Net, pm internal.PortMapping, udpTimeout time.Duration) error {
	localAddrPort, err := netip.ParseAddrPort(net.JoinHostPort(pm.BindAddress, strconv.Itoa(pm.LocalPort)))
	if err != nil {
		return fmt.Errorf("invalid local address: %w", err)
	}

	listener, err := tunNet.ListenUDPAddrPort(localAddrPort)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", localAddrPort, err)
	}
	defer func() { _ = listener.Close() }()

	remoteAddr := net.JoinHostPort(pm.RemoteIP, strconv.Itoa(pm.RemotePort))

	sessions := newUDPSessionTable(udpTimeout, func(payload []byte, client net.Addr) error {
		_, err := listener.WriteTo(payload, client)
		return err
	})
	defer sessions.closeAll()

	log.Printf("Remote UDP forwarding: Listening on MASQUE network %s, forwarding to local %s", localAddrPort, remoteAddr)

	buf := make([]byte, maxUDPPacketSize)
	for {
		n, client, err := listener.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("UDP read error on %s: %w", localAddrPort, err)
		}

		key := client.String()
		session, err := sessions.get(key, client, func() (net.Conn, error) {
			return net.Dial("udp", remoteAddr)
		})
		if err != nil {
			log.Printf("Failed to open UDP flow to %s for client %s: %v", remoteAddr, client, err)
			continue
		}

		session.touch()
		if _, err := session.conn.Write(buf[:n]); err != nil {
			log.Printf("UDP write to %s failed: %v", remoteAddr, err)
			sessions.remove(key, session)
		}
	}
}
