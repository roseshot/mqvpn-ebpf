package qos

import (
	"context"
	"testing"
)

func ipv4(proto byte, dscp, src, dst uint16) []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	pkt[1] = byte(dscp << 2)
	pkt[3] = byte(len(pkt))
	pkt[9] = proto
	pkt[20], pkt[21] = byte(src>>8), byte(src)
	pkt[22], pkt[23] = byte(dst>>8), byte(dst)
	return pkt
}

func TestPriority(t *testing.T) {
	if !Priority(ipv4(17, 46, 40000, 50000)) {
		t.Fatal("DSCP EF RTP should be prioritized")
	}
	if !Priority(ipv4(17, 0, 5060, 40000)) {
		t.Fatal("SIP UDP should be prioritized")
	}
	if !Priority(ipv4(6, 0, 50000, 5061)) {
		t.Fatal("SIP TLS should be prioritized")
	}
	if Priority(ipv4(17, 0, 40000, 50000)) {
		t.Fatal("unmarked UDP should remain normal priority")
	}
	pkt := ipv4(17, 0, 5060, 40000)
	pkt[6] = 0x00
	pkt[7] = 0x01
	if Priority(pkt) {
		t.Fatal("non-initial IPv4 fragment must not be parsed as SIP")
	}
	v6 := make([]byte, 48)
	v6[0] = 0x60 | byte((46<<2)>>4)
	v6[1] = byte((46<<2)&0x0f) << 4
	v6[5] = 8
	v6[6] = 17
	if !Priority(v6) {
		t.Fatal("IPv6 EF not classified as realtime")
	}
}

func TestNextPrefersRealtimeWithoutStarvingBulk(t *testing.T) {
	urgent, normal := make(chan []byte, 8), make(chan []byte, 2)
	for i := 0; i < 6; i++ {
		urgent <- []byte{byte(i)}
	}
	normal <- []byte{99}
	burst := 0
	for i := 0; i < 4; i++ {
		b, ok := Next(context.Background(), urgent, normal, &burst)
		if !ok || b[0] != byte(i) {
			t.Fatalf("priority %d: %v", i, b)
		}
	}
	b, ok := Next(context.Background(), urgent, normal, &burst)
	if !ok || b[0] != 99 {
		t.Fatalf("bulk starved: %v", b)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := Next(ctx, urgent, normal, &burst); ok {
		t.Fatal("retired queue was consumed")
	}
}

func TestNextContinuousLoadBoundedPriorityBurst(t *testing.T) {
	// Both queues are kept permanently nonempty. Verify fair dispatch
	// remains 4 high priority to 1 normal over a long busy session.
	urgent, normal := make(chan []byte, 8), make(chan []byte, 8)
	for i := 0; i < cap(urgent); i++ {
		urgent <- []byte{1}
		normal <- []byte{2}
	}
	burst := 0
	var realTime, bulk int
	for i := 0; i < 5000; i++ {
		item, ok := Next(context.Background(), urgent, normal, &burst)
		if !ok {
			t.Fatal("active session sender unexpectedly stopped")
		}
		expected := byte(1)
		if i%5 == 4 {
			expected = 2
		}
		if len(item) != 1 || item[0] != expected {
			t.Fatalf("packet %d: got %v, wanted priority class %d", i, item, expected)
		}
		if item[0] == 1 {
			realTime++
			urgent <- []byte{1}
		} else {
			bulk++
			normal <- []byte{2}
		}
	}
	if realTime != 4000 || bulk != 1000 {
		t.Fatalf("unexpected sustained load distribution: realtime=%d bulk=%d", realTime, bulk)
	}
}
