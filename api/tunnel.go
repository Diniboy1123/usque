package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/internal"
	"github.com/songgao/water"
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

// NetstackAdapter wraps a tun.Device (for example wireguard-go/tun) to satisfy
// TunnelDevice. Some platforms — notably the BSDs (FreeBSD, macOS) — require a
// small packet headroom when using tun.Device.Read/Write because the
// kernel-facing device carries a 4-byte address-family header. The offset field
// lets platform-specific callers request that headroom while keeping the tunnel
// pump raw-IP-only.
type NetstackAdapter struct {
	dev             tun.Device
	offset          int
	tunnelBufPool   sync.Pool
	tunnelSizesPool sync.Pool
	packetBufPool   sync.Pool
}

func (n *NetstackAdapter) ReadPacket(buf []byte) (int, error) {
	packetBufsPtr := n.tunnelBufPool.Get().(*[][]byte)
	sizesPtr := n.tunnelSizesPool.Get().(*[]int)

	defer func() {
		(*packetBufsPtr)[0] = nil
		n.tunnelBufPool.Put(packetBufsPtr)
		n.tunnelSizesPool.Put(sizesPtr)
	}()

	readBuf := buf
	var pooledBufPtr *[]byte
	if n.offset > 0 {
		pooledBufPtr = n.packetBufPool.Get().(*[]byte)
		pooledBuf := *pooledBufPtr
		needed := len(buf) + n.offset
		if cap(pooledBuf) < needed {
			pooledBuf = make([]byte, needed)
		}
		readBuf = pooledBuf[:needed]
	}

	(*packetBufsPtr)[0] = readBuf
	(*sizesPtr)[0] = 0

	_, err := n.dev.Read(*packetBufsPtr, *sizesPtr, n.offset)
	if err != nil {
		if pooledBufPtr != nil {
			*pooledBufPtr = readBuf[:0]
			n.packetBufPool.Put(pooledBufPtr)
		}
		return 0, err
	}

	size := (*sizesPtr)[0]
	if n.offset > 0 {
		copy(buf, readBuf[n.offset:n.offset+size])
		*pooledBufPtr = readBuf[:0]
		n.packetBufPool.Put(pooledBufPtr)
	}

	return size, nil
}

func (n *NetstackAdapter) WritePacket(pkt []byte) error {
	packetBufsPtr := n.tunnelBufPool.Get().(*[][]byte)
	defer func() {
		(*packetBufsPtr)[0] = nil
		n.tunnelBufPool.Put(packetBufsPtr)
	}()

	writeBuf := pkt
	var pooledBufPtr *[]byte
	if n.offset > 0 {
		pooledBufPtr = n.packetBufPool.Get().(*[]byte)
		pooledBuf := *pooledBufPtr
		needed := len(pkt) + n.offset
		if cap(pooledBuf) < needed {
			pooledBuf = make([]byte, needed)
		}
		writeBuf = pooledBuf[:needed]
		copy(writeBuf[n.offset:], pkt)
	}

	(*packetBufsPtr)[0] = writeBuf
	_, err := n.dev.Write(*packetBufsPtr, n.offset)

	if pooledBufPtr != nil {
		*pooledBufPtr = writeBuf[:0]
		n.packetBufPool.Put(pooledBufPtr)
	}

	return err
}

// NewNetstackAdapter creates a new NetstackAdapter without packet headroom
// (offset 0), suitable for Linux/Windows tun devices.
func NewNetstackAdapter(dev tun.Device) TunnelDevice {
	return NewNetstackAdapterWithOffset(dev, 0)
}

// NewNetstackAdapterWithOffset creates a NetstackAdapter with platform-specific
// packet headroom for tun.Device.Read/Write. Use offset 4 on the BSDs (FreeBSD,
// macOS), whose utun/tun devices carry a 4-byte address-family header.
func NewNetstackAdapterWithOffset(dev tun.Device, offset int) TunnelDevice {
	if offset < 0 {
		panic("offset must not be negative")
	}

	return &NetstackAdapter{
		dev:    dev,
		offset: offset,
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
		packetBufPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 0)
				return &buf
			},
		},
	}
}

// WaterAdapter wraps a *water.Interface so it satisfies TunnelDevice.
type WaterAdapter struct {
	iface *water.Interface
}

func (w *WaterAdapter) ReadPacket(buf []byte) (int, error) {
	n, err := w.iface.Read(buf)
	if err != nil {
		return 0, err
	}

	return n, nil
}

func (w *WaterAdapter) WritePacket(pkt []byte) error {
	_, err := w.iface.Write(pkt)
	return err
}

// NewWaterAdapter creates a new WaterAdapter.
func NewWaterAdapter(iface *water.Interface) TunnelDevice {
	return &WaterAdapter{iface: iface}
}

// pumpShutdownGrace bounds how long the supervisor waits for both forwarding
// pumps to exit after an error before spawning a fresh pair. A device-side
// pump may still be parked in a blocking TUN read during this window; the
// readMu serializes any overlap with the next cycle's device reader.
const pumpShutdownGrace = 2 * time.Second

// CONNECT-IP context ID 0 is encoded as a one-byte QUIC varint. Reserving this
// byte before packets lets connect-ip-go send outbound datagrams in place.
const datagramContextIDHeadroom = 1

// MaintainTunnelConfig contains runtime settings for tunnel maintenance.
type MaintainTunnelConfig struct {
	TLSConfig         *tls.Config
	KeepalivePeriod   time.Duration
	InitialPacketSize uint16
	Endpoint          net.Addr
	Device            TunnelDevice
	MTU               int
	ReconnectDelay    time.Duration
	AlwaysReconnect   bool
	UseHTTP2          bool
	// OnConnect is a path to an executable run after every successful tunnel
	// connect. It is exec'd directly (no shell, no args) and runs fire-and-forget.
	OnConnect string
	// OnDisconnect is a path to an executable run after every tunnel loss.
	// It is exec'd directly (no shell, no args) and runs fire-and-forget.
	OnDisconnect string
	// HookEnv is a set of USQUE_* environment variables layered on top of the
	// parent process env for OnConnect / OnDisconnect invocations. USQUE_EVENT
	// and USQUE_ENDPOINT are set by MaintainTunnel itself.
	HookEnv map[string]string
}

// cloneHookEnv returns a shallow copy of src so concurrent hook invocations
// do not share a map.
func cloneHookEnv(src map[string]string) map[string]string {
	out := make(map[string]string, len(src)+2)
	for k, v := range src {
		out[k] = v
	}
	return out
}

// sleepCtx sleeps for d or until ctx is cancelled, whichever comes first.
// Returns ctx.Err() on cancellation and nil on normal completion.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// MaintainTunnel continuously connects to the MASQUE server, then starts two
// forwarding goroutines: one forwarding from the device to the IP connection (and handling
// any ICMP reply), and the other forwarding from the IP connection to the device.
// If an error occurs in either loop, the connection is closed and a reconnect is attempted.
//
// Parameters:
//   - ctx: context.Context - The context for the connection.
//   - cfg: MaintainTunnelConfig - Tunnel maintenance runtime configuration.
func MaintainTunnel(ctx context.Context, cfg MaintainTunnelConfig) {
	if cfg.UseHTTP2 {
		if _, ok := cfg.Endpoint.(*net.TCPAddr); !ok {
			log.Fatalf("MaintainTunnel: HTTP/2 mode requires a *net.TCPAddr endpoint, got %T", cfg.Endpoint)
		}
	} else {
		if _, ok := cfg.Endpoint.(*net.UDPAddr); !ok {
			log.Fatalf("MaintainTunnel: HTTP/3 mode requires a *net.UDPAddr endpoint, got %T", cfg.Endpoint)
		}
	}

	packetBufferPool := NewNetBuffer(cfg.MTU + datagramContextIDHeadroom)

	for {
		if ctx.Err() != nil {
			return
		}

		if !cfg.AlwaysReconnect {
			log.Println("Tunnel idle. Waiting for outbound activity before reconnecting...")
			buf := packetBufferPool.Get()
			n, err := cfg.Device.ReadPacket(buf[datagramContextIDHeadroom:])
			if err != nil {
				packetBufferPool.Put(buf)
				log.Printf("Failed to read from TUN device while waiting for activity: %v", err)
				if sleepErr := sleepCtx(ctx, cfg.ReconnectDelay); sleepErr != nil {
					return
				}
				continue
			}
			packetBufferPool.Put(buf)
			log.Printf("Detected outbound activity (%d bytes). Reconnecting...", n)
		}

		log.Printf("Establishing MASQUE connection to %s", cfg.Endpoint)
		udpConn, tr, ipConn, rsp, err := ConnectTunnel(
			ctx,
			cfg.TLSConfig,
			internal.DefaultQuicConfig(cfg.KeepalivePeriod, cfg.InitialPacketSize),
			internal.ConnectURI,
			cfg.Endpoint,
			cfg.UseHTTP2,
		)
		if err != nil {
			log.Printf("Failed to connect tunnel: %v", err)
			if ipConn != nil {
				_ = ipConn.Close()
			}
			if tr != nil {
				_ = tr.Close()
			}
			if udpConn != nil {
				_ = udpConn.Close()
			}
			if sleepErr := sleepCtx(ctx, cfg.ReconnectDelay); sleepErr != nil {
				return
			}
			continue
		}
		if rsp.StatusCode != 200 {
			log.Printf("Tunnel connection failed: %s", rsp.Status)
			_ = ipConn.Close()
			if tr != nil {
				_ = tr.Close()
			}
			if udpConn != nil {
				_ = udpConn.Close()
			}
			if sleepErr := sleepCtx(ctx, cfg.ReconnectDelay); sleepErr != nil {
				return
			}
			continue
		}

		log.Println("Connected to MASQUE server")

		if cfg.OnConnect != "" {
			env := cloneHookEnv(cfg.HookEnv)
			env["USQUE_EVENT"] = "connect"
			env["USQUE_ENDPOINT"] = cfg.Endpoint.String()
			RunHook(cfg.OnConnect, env)
		}

		errChan := make(chan error, 2)
		pumpCtx, cancelPumps := context.WithCancel(ctx)
		var wg sync.WaitGroup
		var readMu sync.Mutex

		wg.Add(2)

		go func() {
			defer wg.Done()
			for {
				if pumpCtx.Err() != nil {
					return
				}
				buf := packetBufferPool.Get()
				readMu.Lock()
				n, err := cfg.Device.ReadPacket(buf[datagramContextIDHeadroom:])
				readMu.Unlock()
				if err != nil {
					packetBufferPool.Put(buf)
					errChan <- fmt.Errorf("failed to read from TUN device: %w", err)
					return
				}
				if pumpCtx.Err() != nil {
					packetBufferPool.Put(buf)
					return
				}
				icmp, err := ipConn.WritePacketBuffer(buf, datagramContextIDHeadroom, n)
				if err != nil {
					packetBufferPool.Put(buf)
					if errors.As(err, new(*connectip.CloseError)) {
						errChan <- fmt.Errorf("connection closed while writing to IP connection: %w", err)
						return
					}
					log.Printf("Error writing to IP connection: %v, continuing...", err)
					continue
				}
				packetBufferPool.Put(buf)

				if len(icmp) > 0 {
					if err := cfg.Device.WritePacket(icmp); err != nil {
						if errors.As(err, new(*connectip.CloseError)) {
							errChan <- fmt.Errorf("connection closed while writing ICMP to TUN device: %w", err)
							return
						}
						log.Printf("Error writing ICMP to TUN device: %v, continuing...", err)
					}
				}
			}
		}()

		go func() {
			defer wg.Done()
			for {
				packet, err := ipConn.ReadPacketZeroCopy(true)
				if err != nil {
					if cfg.UseHTTP2 {
						errChan <- fmt.Errorf("connection closed while reading from IP connection: %w", err)
						return
					}
					if errors.As(err, new(*connectip.CloseError)) {
						errChan <- fmt.Errorf("connection closed while reading from IP connection: %w", err)
						return
					}
					log.Printf("Error reading from IP connection: %v, continuing...", err)
					continue
				}
				if err := cfg.Device.WritePacket(packet); err != nil {
					errChan <- fmt.Errorf("failed to write to TUN device: %w", err)
					return
				}
			}
		}()

		err = <-errChan
		log.Printf("Tunnel connection lost: %v. Reconnecting...", err)

		if cfg.OnDisconnect != "" {
			env := cloneHookEnv(cfg.HookEnv)
			env["USQUE_EVENT"] = "disconnect"
			env["USQUE_ENDPOINT"] = cfg.Endpoint.String()
			RunHook(cfg.OnDisconnect, env)
		}

		cancelPumps()
		_ = ipConn.Close()

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(pumpShutdownGrace):
			log.Printf("Pump shutdown grace of %s expired; a stale TUN reader may still be parked (readMu will serialize next cycle)", pumpShutdownGrace)
		}

		if tr != nil {
			_ = tr.Close()
		}
		if udpConn != nil {
			_ = udpConn.Close()
		}
		if sleepErr := sleepCtx(ctx, cfg.ReconnectDelay); sleepErr != nil {
			return
		}
	}
}
