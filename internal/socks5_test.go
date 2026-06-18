package internal

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/txthinking/runnergroup"
	"github.com/txthinking/socks5"
)

func TestIsZeroUDPAssociateRequest(t *testing.T) {
	tests := []struct {
		name string
		req  *socks5.Request
		want bool
	}{
		{
			name: "ipv4 zero",
			req: &socks5.Request{
				Atyp:    socks5.ATYPIPv4,
				DstAddr: []byte{0, 0, 0, 0},
				DstPort: []byte{0, 0},
			},
			want: true,
		},
		{
			name: "ipv6 zero",
			req: &socks5.Request{
				Atyp:    socks5.ATYPIPv6,
				DstAddr: net.IPv6zero,
				DstPort: []byte{0, 0},
			},
			want: true,
		},
		{
			name: "explicit source port",
			req: &socks5.Request{
				Atyp:    socks5.ATYPIPv4,
				DstAddr: []byte{0, 0, 0, 0},
				DstPort: []byte{0x12, 0x34},
			},
			want: false,
		},
		{
			name: "explicit source address",
			req: &socks5.Request{
				Atyp:    socks5.ATYPIPv4,
				DstAddr: []byte{192, 0, 2, 10},
				DstPort: []byte{0, 0},
			},
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isZeroUDPAssociateRequest(test.req); got != test.want {
				t.Fatalf("isZeroUDPAssociateRequest() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestUDPHandleRejectsUnassociatedUDPInStrictMode(t *testing.T) {
	server := newTestSocksServer()
	handler := &SOCKS5Server{
		cfg:        SOCKS5Config{},
		server:     server,
		pendingUDP: make(map[string][]*udpAssociation),
	}

	err := handler.UDPHandle(server, udpAddr("192.0.2.10", 40000), testDatagram())
	if err == nil {
		t.Fatal("expected unassociated UDP packet to fail")
	}
}

func TestUDPHandleClaimsPendingZeroAssociateInLooseMode(t *testing.T) {
	server := newTestSocksServer()
	assoc := &udpAssociation{ch: make(chan byte)}
	handler := &SOCKS5Server{
		cfg: SOCKS5Config{
			LooseUDPAssociate: true,
		},
		server: server,
		pendingUDP: map[string][]*udpAssociation{
			"192.0.2.10": {assoc},
		},
	}

	conn := &recordingPacketConn{}
	oldDialUDP := socks5.DialUDP
	socks5.DialUDP = func(_, _, _ string) (net.Conn, error) {
		return conn, nil
	}
	t.Cleanup(func() { socks5.DialUDP = oldDialUDP })

	err := handler.UDPHandle(server, udpAddr("192.0.2.10", 40000), testDatagram())
	if err != nil {
		t.Fatalf("UDPHandle() error = %v", err)
	}
	if source := assoc.getSource(); source != "192.0.2.10:40000" {
		t.Fatalf("assoc.source = %q, want %q", source, "192.0.2.10:40000")
	}
	if _, ok := server.AssociatedUDP.Get("192.0.2.10:40000"); !ok {
		t.Fatal("claimed UDP association was not registered")
	}
	if _, ok := handler.pendingUDP["192.0.2.10"]; ok {
		t.Fatal("pending UDP association was not removed")
	}
	if !bytes.Equal(conn.written.Bytes(), []byte("payload")) {
		t.Fatalf("remote UDP payload = %q, want %q", conn.written.String(), "payload")
	}
}

func newTestSocksServer() *socks5.Server {
	return &socks5.Server{
		AssociatedUDP: cache.New(cache.NoExpiration, cache.NoExpiration),
		UDPExchanges:  cache.New(cache.NoExpiration, cache.NoExpiration),
		LimitUDP:      true,
		RunnerGroup:   runnergroup.New(),
	}
}

func udpAddr(ip string, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
}

func testDatagram() *socks5.Datagram {
	return &socks5.Datagram{
		Rsv:     []byte{0, 0},
		Frag:    0,
		Atyp:    socks5.ATYPIPv4,
		DstAddr: []byte{1, 1, 1, 1},
		DstPort: []byte{0, 53},
		Data:    []byte("payload"),
	}
}

type recordingPacketConn struct {
	written bytes.Buffer
}

func (c *recordingPacketConn) Read(_ []byte) (int, error) {
	select {}
}

func (c *recordingPacketConn) Write(p []byte) (int, error) {
	return c.written.Write(p)
}

func (c *recordingPacketConn) Close() error {
	return nil
}

func (c *recordingPacketConn) LocalAddr() net.Addr {
	return udpAddr("100.64.0.2", 12345)
}

func (c *recordingPacketConn) RemoteAddr() net.Addr {
	return udpAddr("1.1.1.1", 53)
}

func (c *recordingPacketConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *recordingPacketConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *recordingPacketConn) SetWriteDeadline(_ time.Time) error {
	return nil
}
