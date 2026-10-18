package cmd

import (
	"net"
	"testing"
	"time"
)

func echoUDP(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	buf := make([]byte, 64)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if _, err := conn.WriteToUDP(buf[:n], addr); err != nil {
			return
		}
	}
}

func TestUDPSessionTableForwardsResponses(t *testing.T) {
	t.Parallel()

	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("failed to start echo server: %v", err)
	}
	defer func() { _ = echo.Close() }()
	go echoUDP(t, echo)

	// listener stands in for the forwarding socket facing clients.
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	client, err := net.Dial("udp", listener.LocalAddr().String())
	if err != nil {
		t.Fatalf("failed to dial forwarding listener: %v", err)
	}
	defer func() { _ = client.Close() }()

	table := newUDPSessionTable(time.Second, func(payload []byte, clientAddr net.Addr) error {
		_, err := listener.WriteTo(payload, clientAddr)
		return err
	})
	defer table.closeAll()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("failed to send datagram: %v", err)
	}

	buf := make([]byte, 64)
	_ = listener.(*net.UDPConn).SetReadDeadline(time.Now().Add(2 * time.Second))
	n, src, err := listener.ReadFrom(buf)
	if err != nil {
		t.Fatalf("failed to read datagram: %v", err)
	}

	session, err := table.get(src.String(), src, func() (net.Conn, error) {
		return net.Dial("udp", echo.LocalAddr().String())
	})
	if err != nil {
		t.Fatalf("failed to create UDP session: %v", err)
	}
	if _, err := session.conn.Write(buf[:n]); err != nil {
		t.Fatalf("failed to forward datagram: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = client.Read(buf)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if got := string(buf[:n]); got != "ping" {
		t.Fatalf("response = %q, want %q", got, "ping")
	}
}

func TestUDPSessionTableExpiresIdleSessions(t *testing.T) {
	t.Parallel()

	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	table := newUDPSessionTable(100*time.Millisecond, func([]byte, net.Addr) error {
		return nil
	})
	defer table.closeAll()

	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	session, err := table.get("client", client, func() (net.Conn, error) {
		return net.Dial("udp", listener.LocalAddr().String())
	})
	if err != nil {
		t.Fatalf("failed to create UDP session: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		table.mu.Lock()
		_, exists := table.sessions["client"]
		table.mu.Unlock()
		if !exists {
			_ = session.conn.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("idle UDP session was not expired")
}
