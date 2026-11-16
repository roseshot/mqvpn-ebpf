package p2mp

import (
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/l3"
)

type fakeDevice struct {
	mu  sync.Mutex
	out [][]byte
}

func (d *fakeDevice) Read([]byte) (int, error) { return 0, io.EOF }
func (d *fakeDevice) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.out = append(d.out, append([]byte(nil), p...))
	return len(p), nil
}
func (d *fakeDevice) Close() error { return nil }
func (d *fakeDevice) count() int   { d.mu.Lock(); defer d.mu.Unlock(); return len(d.out) }

type fakeStream struct{ out chan []byte }

func (f *fakeStream) SendDatagram(p []byte) error {
	f.out <- append([]byte(nil), p...)
	return nil
}
func (f *fakeStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func ip4(src, dst [4]byte) []byte {
	p := make([]byte, 20)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], 20)
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	return p
}
func prepare(t *testing.T) (*Hub, *fakeDevice, *Session, *Session, *fakeStream, *fakeStream, context.CancelFunc) {
	t.Helper()
	cfg, err := Parse(FileConfig{Peers: []PeerConfig{
		{ID: "A", Routes: []string{"10.77.0.2/32"}},
		{ID: "B", Routes: []string{"10.77.0.3/32"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	dev := &fakeDevice{}
	h, err := New(dev, cfg, 1160, discardTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	as := &fakeStream{out: make(chan []byte, 8)}
	bs := &fakeStream{out: make(chan []byte, 8)}
	A, err := h.AttachWithTrafficRole(ctx, cfg.Peers[0], as, false, false, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	B, err := h.AttachWithTrafficRole(ctx, cfg.Peers[1], bs, false, false, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	return h, dev, A, B, as, bs, cancel
}
func mustFrame(t *testing.T, packet []byte) []byte {
	t.Helper()
	f, err := l3.Wrap(packet)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func waitFrame(t *testing.T, s *fakeStream) []byte {
	t.Helper()
	select {
	case p := <-s.out:
		return p
	case <-time.After(time.Second):
		t.Fatal("timed out forwarding datagram")
	}
	return nil
}

func TestUnicastAndNoSourceACL(t *testing.T) {
	h, dev, a, b, as, bs, cancel := prepare(t)
	defer cancel()
	defer h.Detach(a)
	defer h.Detach(b)
	p := ip4([4]byte{10, 77, 0, 1}, [4]byte{10, 77, 0, 3})
	h.egress(p)
	got, err := l3.Unwrap(waitFrame(t, bs))
	if err != nil || string(got) != string(p) {
		t.Fatalf("wrong unicast: %v", err)
	}
	select {
	case <-as.out:
		t.Fatal("unicast incorrectly fanned out")
	default:
	}
	// Inner IP is not subject to per-peer source filtering: the host
	// kernel/network administrator owns firewall and anti-spoof rules.
	h.ingress(a, mustFrame(t, ip4([4]byte{192, 0, 2, 5}, [4]byte{10, 77, 0, 1})))
	if dev.count() != 1 {
		t.Fatal("IP packet unexpectedly blocked by peer source rule")
	}
}

func TestMulticastAndIPBroadcastFanout(t *testing.T) {
	h, dev, a, b, as, bs, cancel := prepare(t)
	defer cancel()
	defer h.Detach(a)
	defer h.Detach(b)
	for _, dst := range [][4]byte{{224, 0, 0, 251}, {239, 20, 30, 40}, {255, 255, 255, 255}} {
		p := ip4([4]byte{10, 77, 0, 1}, dst)
		h.egress(p)
		ga, err := l3.Unwrap(waitFrame(t, as))
		if err != nil || string(ga) != string(p) {
			t.Fatalf("A did not receive %v: %v", dst, err)
		}
		gb, err := l3.Unwrap(waitFrame(t, bs))
		if err != nil || string(gb) != string(p) {
			t.Fatalf("B did not receive %v: %v", dst, err)
		}
	}
	// Peer A -> all *other* peers and hub's local TUN; no source reflexion.
	p := ip4([4]byte{203, 0, 113, 9}, [4]byte{224, 0, 0, 251})
	h.ingress(a, mustFrame(t, p))
	got, err := l3.Unwrap(waitFrame(t, bs))
	if err != nil || string(got) != string(p) {
		t.Fatalf("peer multicast not propagated: %v", err)
	}
	if dev.count() != 1 {
		t.Fatal("local TUN did not receive multicast")
	}
	select {
	case <-as.out:
		t.Fatal("peer multicast reflected to source")
	default:
	}
	if h.cfg.Destination(netip.MustParseAddr("224.0.0.251")) != nil {
		t.Fatal("multicast destination resolved as unicast")
	}
}
