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
    v6[1] = byte((46 << 2) & 0x0f) << 4
    v6[5] = 8
    v6[6] = 17
    if !Priority(v6) {
        t.Fatal("IPv6 EF not classified as realtime")
    }
}

func TestNextPrefersRealtimeWithoutStarvingBulk(t *testing.T) {
    urgent, normal := make(chan []byte, 8), make(chan []byte, 2)
    for i := 0; i < 6; i++ { urgent <- []byte{byte(i)} }
    normal <- []byte{99}
    burst := 0
    for i := 0; i < 4; i++ {
        b, ok := Next(context.Background(), urgent, normal, &burst)
        if !ok || b[0] != byte(i) { t.Fatalf("priority %d: %v", i, b) }
    }
    b, ok := Next(context.Background(), urgent, normal, &burst)
    if !ok || b[0] != 99 { t.Fatalf("bulk starved: %v", b) }
    ctx, cancel := context.WithCancel(context.Background())
    cancel()
    if _, ok := Next(ctx, urgent, normal, &burst); ok {
        t.Fatal("retired queue was consumed")
    }
}
