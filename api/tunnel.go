package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/Diniboy1123/usque/internal"
	"golang.zx2c4.com/wireguard/tun"
)

// NetBuffer is a pool of byte slices with a fixed capacity.
// Helps to reduce memory allocations and improve performance.
// It uses a sync.Pool to manage the byte slices.
// The capacity of the byte slices is set when the pool is created.
type NetBuffer struct {
	capacity int
	buf      sync.Pool
}

// Get returns a byte slice from the pool.
func (n *NetBuffer) Get() []byte {
	return *(n.buf.Get().(*[]byte))
}

// Put places a byte slice back into the pool.
// It checks if the capacity of the byte slice matches the pool's capacity.
// If it doesn't match, the byte slice is not returned to the pool.
func (n *NetBuffer) Put(buf []byte) {
	if cap(buf) != n.capacity {
		return
	}
	n.buf.Put(&buf)
}

// NewNetBuffer creates a new NetBuffer with the specified capacity.
// The capacity must be greater than 0.
func NewNetBuffer(capacity int) *NetBuffer {
	if capacity <= 0 {
		panic("capacity must be greater than 0")
	}
	return &NetBuffer{
		capacity: capacity,
		buf: sync.Pool{
			New: func() interface{} {
				b := make([]byte, capacity)
				return &b
			},
		},
	}
}

// TunnelDevice abstracts a TUN device so that we can use the same tunnel-maintenance code
// regardless of the underlying implementation.
type TunnelDevice interface {
	// ReadPacket reads a packet from the device (using the given mtu) and returns its contents.
	ReadPacket(buf []byte) (int, error)
	// WritePacket writes a packet to the device.
	WritePacket(pkt []byte) error
}

// see https://github.com/WireGuard/wireguard-go/blob/f333402bd9cbe0f3eeb02507bd14e23d7d639280/tun/offload_linux.go#L27
// for details on how this is calculated
const virtioNetHdrLen = 10

// NetstackAdapter wraps a tun.Device (e.g. from netstack) to satisfy TunnelDevice.
type NetstackAdapter struct {
	dev             tun.Device
	tunnelBufPool   sync.Pool
	tunnelSizesPool sync.Pool
}

func (n *NetstackAdapter) ReadPacket(buf []byte) (int, error) {
	packetBufsPtr := n.tunnelBufPool.Get().(*[][]byte)
	sizesPtr := n.tunnelSizesPool.Get().(*[]int)

	defer func() {
		(*packetBufsPtr)[0] = nil
		n.tunnelBufPool.Put(packetBufsPtr)
		n.tunnelSizesPool.Put(sizesPtr)
	}()

	(*packetBufsPtr)[0] = buf
	(*sizesPtr)[0] = 0

	_, err := n.dev.Read(*packetBufsPtr, *sizesPtr, 0)
	if err != nil {
		return 0, err
	}

	return (*sizesPtr)[0], nil
}

func (n *NetstackAdapter) WritePacket(pkt []byte) error {
	if len(pkt) < virtioNetHdrLen {
		return fmt.Errorf("buffer too small for virtio header")
	}
	_, err := n.dev.Write([][]byte{pkt}, virtioNetHdrLen)
	return err
}

// NewNetstackAdapter creates a new NetstackAdapter.
func NewNetstackAdapter(dev tun.Device) TunnelDevice {
	return &NetstackAdapter{
		dev: dev,
		tunnelBufPool: sync.Pool{
			New: func() interface{} {
				buf := make([][]byte, 1)
				return &buf
			},
		},
		tunnelSizesPool: sync.Pool{
			New: func() interface{} {
				sizes := make([]int, 1)
				return &sizes
			},
		},
	}
}

// MaintainTunnel continuously connects to the MASQUE server, then starts two
// forwarding goroutines: one forwarding from the device to the IP connection (and handling
// any ICMP reply), and the other forwarding from the IP connection to the device.
// If an error occurs in either loop, the connection is closed and a reconnect is attempted.
//
// Parameters:
//   - ctx: context.Context - The context for the connection.
//   - tlsConfig: *tls.Config - The TLS configuration for secure communication.
//   - keepalivePeriod: time.Duration - The keepalive period for the QUIC connection.
//   - initialPacketSize: uint16 - The initial packet size for the QUIC connection.
//   - endpoint: *net.UDPAddr - The UDP address of the MASQUE server.
//   - device: TunnelDevice - The TUN device to forward packets to and from.
//   - mtu: int - The MTU of the TUN device.
//   - reconnectDelay: time.Duration - The delay between reconnect attempts.
func MaintainTunnel(ctx context.Context, tlsConfig *tls.Config, keepalivePeriod time.Duration, initialPacketSize uint16, endpoint *net.UDPAddr, device TunnelDevice, mtu int, reconnectDelay time.Duration) {
	packetBufferPool := NewNetBuffer(mtu + virtioNetHdrLen)
	for {
		log.Printf("Establishing MASQUE connection to %s:%d", endpoint.IP, endpoint.Port)
		udpConn, tr, ipConn, rsp, err := ConnectTunnel(
			ctx,
			tlsConfig,
			internal.DefaultQuicConfig(keepalivePeriod, initialPacketSize),
			internal.ConnectURI,
			endpoint,
		)
		if err != nil {
			log.Printf("Failed to connect tunnel: %v", err)
			time.Sleep(reconnectDelay)
			continue
		}
		if rsp.StatusCode != 200 {
			log.Printf("Tunnel connection failed: %s", rsp.Status)
			ipConn.Close()
			if udpConn != nil {
				udpConn.Close()
			}
			if tr != nil {
				tr.Close()
			}
			time.Sleep(reconnectDelay)
			continue
		}

		log.Println("Connected to MASQUE server")
		errChan := make(chan error, 2)

		go func() {
			for {
				buf := packetBufferPool.Get()
				n, err := device.ReadPacket(buf[virtioNetHdrLen:])
				if err != nil {
					packetBufferPool.Put(buf)
					errChan <- fmt.Errorf("failed to read from TUN device: %v", err)
					return
				}
				icmp, err := ipConn.WritePacket(buf[virtioNetHdrLen : virtioNetHdrLen+n])
				if err != nil {
					packetBufferPool.Put(buf)
					errChan <- fmt.Errorf("failed to write to IP connection: %v", err)
					return
				}
				if len(icmp) > 0 {
					copy(buf[virtioNetHdrLen:], icmp)
					_ = device.WritePacket(buf[:virtioNetHdrLen+len(icmp)])
				}
				packetBufferPool.Put(buf)
			}
		}()

		go func() {
			buf := packetBufferPool.Get()
			defer packetBufferPool.Put(buf)
			for {
				n, err := ipConn.ReadPacket(buf[virtioNetHdrLen:], true)
				if err != nil {
					errChan <- fmt.Errorf("failed to read from IP connection: %v", err)
					return
				}
				if err := device.WritePacket(buf[:virtioNetHdrLen+n]); err != nil {
					errChan <- fmt.Errorf("failed to write to TUN device: %v", err)
					return
				}
			}
		}()

		err = <-errChan
		log.Printf("Tunnel connection lost: %v. Reconnecting...", err)
		ipConn.Close()
		if udpConn != nil {
			udpConn.Close()
		}
		if tr != nil {
			tr.Close()
		}
		time.Sleep(reconnectDelay)
	}
}
