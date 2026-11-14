package qos

import (
	"context"
	"encoding/binary"
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

func ipv6Packet(nextHeader byte, body []byte) []byte {
	packet := make([]byte, 40+len(body))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(body)))
	packet[6] = nextHeader
	copy(packet[40:], body)
	return packet
}

func sipPorts(src, dst uint16) []byte {
	p := make([]byte, 8)
	binary.BigEndian.PutUint16(p[0:2], src)
	binary.BigEndian.PutUint16(p[2:4], dst)
	return p
}

func ipv6Options(next byte) []byte {
	p := make([]byte, 8)
	p[0] = next
	return p
}

func ipv6Fragment(next byte, fragmentOffset uint16) []byte {
	p := make([]byte, 8)
	p[0] = next
	binary.BigEndian.PutUint16(p[2:4], fragmentOffset<<3)
	return p
}

func TestPriorityIPv6SIPWithExtensionHeaders(t *testing.T) {
	chain := append(ipv6Options(43), ipv6Options(60)...)
	chain = append(chain, ipv6Options(51)...)
	ah := make([]byte, 12)
	ah[0], ah[1] = 17, 1 // AH length = (1 + 2) * 4 = 12 bytes
	chain = append(chain, ah...)
	chain = append(chain, sipPorts(40000, 5061)...)

	cases := []struct {
		name     string
		packet   []byte
		priority bool
	}{
		{"direct UDP SIP", ipv6Packet(17, sipPorts(5060, 40000)), true},
		{"direct TCP SIP TLS", ipv6Packet(6, sipPorts(40000, 5061)), true},
		{"destination options SIP", ipv6Packet(60, append(ipv6Options(17), sipPorts(5060, 40000)...)), true},
		{"hop by hop routing destination and AH", ipv6Packet(0, chain), true},
		{"first IPv6 fragment has ports", ipv6Packet(44, append(ipv6Fragment(17, 0), sipPorts(40000, 5060)...)), true},
		{"noninitial IPv6 fragment hides ports", ipv6Packet(44, append(ipv6Fragment(17, 1), sipPorts(40000, 5060)...)), false},
		{"noninitial fragment without ports", ipv6Packet(44, ipv6Fragment(17, 2)), false},
		{"extension chain bulk UDP", ipv6Packet(60, append(ipv6Options(17), sipPorts(40000, 40002)...)), false},
		{"unknown next header", ipv6Packet(60, append(ipv6Options(50), sipPorts(5060, 40000)...)), false},
		{"truncated destination options", ipv6Packet(60, []byte{17}), false},
		{"declared extension exceeds packet", ipv6Packet(60, []byte{17, 2, 0, 0, 0, 0, 0, 0}), false},
		{"truncated fragment", ipv6Packet(44, []byte{17, 0, 0, 0}), false},
		{"invalid short AH", ipv6Packet(51, append([]byte{17, 0, 0, 0, 0, 0, 0, 0}, sipPorts(5060, 40000)...)), false},
		{"truncated transport ports", ipv6Packet(60, append(ipv6Options(17), []byte{0x13, 0xc4, 0}...)), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Priority(tc.packet); got != tc.priority {
				t.Fatalf("Priority() = %v, want %v", got, tc.priority)
			}
		})
	}

	long := make([]byte, 17*8+8)
	for i := 0; i < 17; i++ {
		long[i*8] = 60 // loop to another Destination Options header
	}
	copy(long[17*8:], sipPorts(5060, 40000))
	if Priority(ipv6Packet(60, long)) {
		t.Fatal("overlong IPv6 extension chain should not be classified as SIP")
	}

	// Keep the EF fast path independent of extension-header parsing,
	// including noninitial fragments whose UDP ports cannot be inspected.
	ef := ipv6Packet(44, append(ipv6Fragment(17, 1), sipPorts(40000, 40002)...))
	ef[0] = 0x60 | byte((46<<2)>>4)
	ef[1] = byte((46<<2)&0x0f) << 4
	if !Priority(ef) {
		t.Fatal("EF must remain sticky even for IPv6 noninitial fragments")
	}

	invalidLength := ipv6Packet(17, sipPorts(5060, 40000))
	invalidLength[5]--
	if Priority(invalidLength) {
		t.Fatal("invalid IPv6 payload length must not be prioritized")
	}
}

func TestQoSClassifyAFAndControlPlane(t *testing.T) {
	for _, tc := range []struct {
		name string
		pkt []byte
		want Class
	}{
		{"EF is realtime", ipv4(17, 46, 40000, 40001), Realtime},
		{"SIP is realtime even unmarked", ipv4(6, 0, 5061, 9000), Realtime},
		{"AF11 assured", ipv4(17, 10, 9000, 9001), Assured},
		{"AF31 assured", ipv4(17, 26, 9000, 9001), Assured},
		{"AF41 assured", ipv4(17, 34, 9000, 9001), Assured},
		{"AF43 assured", ipv4(17, 38, 9000, 9001), Assured},
		{"CS5 assured", ipv4(17, 40, 9000, 9001), Assured},
		{"CS6 routing control assured", ipv4(89, 48, 0, 0), Assured},
		{"CS7 routing control assured", ipv4(89, 56, 0, 0), Assured},
		{"best effort", ipv4(17, 0, 9000, 9001), BestEffort},
		{"unknown DSCP best effort", ipv4(17, 7, 9000, 9001), BestEffort},
		{"empty best effort", nil, BestEffort},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.pkt); got != tc.want {
				t.Fatalf("Classify() = %d, want %d", got, tc.want)
			}
		})
	}
	v6 := ipv6Packet(17, sipPorts(9000, 9001))
	v6[0] = 0x60 | byte((34<<2)>>4)
	v6[1] = byte((34<<2)&0x0f) << 4
	if got := Classify(v6); got != Assured {
		t.Fatalf("IPv6 AF41 classified %d, want assured", got)
	}
	v6[5]--
	if got := Classify(v6); got != BestEffort {
		t.Fatalf("malformed IPv6 AF41 classified %d, want best effort", got)
	}
	v4 := ipv4(17, 34, 9000, 9001)
	v4[2] = 0
	v4[3] = 21
	if got := Classify(v4); got != BestEffort {
		t.Fatalf("malformed IPv4 AF41 classified %d, want best effort", got)
	}
}

func TestNextTierSustainedWeightedFairness(t *testing.T) {
	urgent, assured, bulk := make(chan []byte, 8), make(chan []byte, 8), make(chan []byte, 8)
	for i := 0; i < cap(urgent); i++ {
		urgent <- []byte{1}
		assured <- []byte{2}
		bulk <- []byte{3}
	}
	cursor := 0
	want := []byte{1, 1, 2, 1, 2, 1, 3}
	var counts [4]int
	for i := 0; i < 700; i++ {
		pkt, ok := NextTier(context.Background(), urgent, assured, bulk, &cursor)
		if !ok || len(pkt) != 1 || pkt[0] != want[i%len(want)] {
			t.Fatalf("packet %d: got %v, want class %d", i, pkt, want[i%len(want)])
		}
		counts[pkt[0]]++
		switch pkt[0] {
		case 1:
			urgent <- pkt
		case 2:
			assured <- pkt
		case 3:
			bulk <- pkt
		}
	}
	if counts[1] != 400 || counts[2] != 200 || counts[3] != 100 {
		t.Fatalf("weighted service ratio drifted: realtime=%d assured=%d bulk=%d", counts[1], counts[2], counts[3])
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := NextTier(ctx, urgent, assured, bulk, &cursor); ok {
		t.Fatal("cancelled sender consumed a packet")
	}
}

func TestNextTierEmptyLaneDoesNotBlock(t *testing.T) {
	urgent, assured, bulk := make(chan []byte, 2), make(chan []byte, 2), make(chan []byte, 2)
	bulk <- []byte{3}
	assured <- []byte{2}
	cursor := 0
	if pkt, ok := NextTier(context.Background(), urgent, assured, bulk, &cursor); !ok || pkt[0] != 2 {
		t.Fatalf("assured lane was blocked by empty realtime lane: %v", pkt)
	}
	if pkt, ok := NextTier(context.Background(), urgent, assured, bulk, &cursor); !ok || pkt[0] != 3 {
		t.Fatalf("best effort lane was blocked by empty higher lanes: %v", pkt)
	}
}
