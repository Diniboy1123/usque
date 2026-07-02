package api

import (
	"bytes"
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

// fakeTun drives NetstackAdapter without a real device. Read hands back a queued
// IP packet placed at the requested offset; Write records the bytes it received
// at the offset. This mirrors the contract NetstackAdapter relies on from
// wireguard-go/tun: the IP packet lives at bufs[0][offset:], sizes[0] is its length.
type fakeTun struct {
	readQueue       [][]byte
	lastWrite       []byte
	lastReadOffset  int
	lastWriteOffset int
}

func (f *fakeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	f.lastReadOffset = offset
	if len(f.readQueue) == 0 {
		return 0, os.ErrClosed
	}
	pkt := f.readQueue[0]
	f.readQueue = f.readQueue[1:]
	sizes[0] = copy(bufs[0][offset:], pkt)
	return 1, nil
}

func (f *fakeTun) Write(bufs [][]byte, offset int) (int, error) {
	f.lastWriteOffset = offset
	f.lastWrite = append([]byte(nil), bufs[0][offset:]...)
	return len(bufs), nil
}

func (f *fakeTun) File() *os.File           { return nil }
func (f *fakeTun) MTU() (int, error)        { return 1280, nil }
func (f *fakeTun) Name() (string, error)    { return "faketun", nil }
func (f *fakeTun) Events() <-chan tun.Event { return nil }
func (f *fakeTun) Close() error             { return nil }
func (f *fakeTun) BatchSize() int           { return 1 }

func pattern(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i%251 + 1)
	}
	return p
}

// TestNetstackAdapterRoundTrip verifies read and write move the raw IP packet
// intact for both the offset-0 path (Linux/Windows/SOCKS) and the offset-4 path
// (BSD/macOS), across empty, small, and full-MTU packets.
func TestNetstackAdapterRoundTrip(t *testing.T) {
	for _, offset := range []int{0, 4} {
		for _, size := range []int{0, 1, 20, 1280} {
			pkt := pattern(size)

			dev := &fakeTun{readQueue: [][]byte{append([]byte(nil), pkt...)}}
			a := NewNetstackAdapterWithOffset(dev, offset)

			buf := make([]byte, 1500)
			n, err := a.ReadPacket(buf)
			if err != nil {
				t.Fatalf("offset=%d size=%d: ReadPacket: %v", offset, size, err)
			}
			if dev.lastReadOffset != offset {
				t.Fatalf("offset=%d: device Read got offset %d", offset, dev.lastReadOffset)
			}
			if n != size || !bytes.Equal(buf[:n], pkt) {
				t.Fatalf("offset=%d size=%d: read back %d bytes, content mismatch", offset, size, n)
			}

			if err := a.WritePacket(pkt); err != nil {
				t.Fatalf("offset=%d size=%d: WritePacket: %v", offset, size, err)
			}
			if dev.lastWriteOffset != offset {
				t.Fatalf("offset=%d: device Write got offset %d", offset, dev.lastWriteOffset)
			}
			if !bytes.Equal(dev.lastWrite[:size], pkt) {
				t.Fatalf("offset=%d size=%d: device received wrong bytes", offset, size)
			}
		}
	}
}

// TestNetstackAdapterZeroOffsetPassthrough pins the invariant that matters most
// for existing platforms: with offset 0, the caller's buffer is handed straight
// to the device (no headroom copy), so behaviour is unchanged by the offset
// generalization.
func TestNetstackAdapterZeroOffsetPassthrough(t *testing.T) {
	pkt := pattern(64)
	dev := &fakeTun{readQueue: [][]byte{append([]byte(nil), pkt...)}}
	a := NewNetstackAdapter(dev)

	buf := make([]byte, 1500)
	n, err := a.ReadPacket(buf)
	if err != nil || n != 64 || !bytes.Equal(buf[:n], pkt) {
		t.Fatalf("zero-offset read mismatch: n=%d err=%v", n, err)
	}
	if dev.lastReadOffset != 0 {
		t.Fatalf("zero-offset used device offset %d, want 0", dev.lastReadOffset)
	}
}
