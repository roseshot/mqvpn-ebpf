package p2mp

import (
	"encoding/binary"
	"testing"

	"github.com/roseshot/mqvpn-ebpf/internal/l3"
)

func TestHubVoIPMetricsPerAuthenticatedPeer(t *testing.T) {
	h, _, a, b, _, _, cancel := prepare(t)
	defer cancel()
	defer h.Detach(a)
	defer h.Detach(b)

	pkt := make([]byte, 40)
	pkt[0], pkt[1] = 0x45, 46<<2
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = 17
	copy(pkt[12:16], []byte{10, 77, 0, 2})
	copy(pkt[16:20], []byte{10, 77, 0, 1})
	binary.BigEndian.PutUint16(pkt[20:22], 30000)
	binary.BigEndian.PutUint16(pkt[22:24], 30002)
	binary.BigEndian.PutUint16(pkt[24:26], 20)
	pkt[28], pkt[29] = 0x80, 96
	binary.BigEndian.PutUint32(pkt[36:40], 0x1234)

	encoded, err := l3.Wrap(pkt)
	if err != nil {
		t.Fatal(err)
	}
	for _, seq := range []uint16{12, 14} {
		binary.BigEndian.PutUint16(pkt[30:32], seq)
		encoded, err = l3.Wrap(pkt)
		if err != nil {
			t.Fatal(err)
		}
		h.ingress(a, encoded)
	}
	aStats := a.VoIPStats()
	if aStats.RTPPackets != 2 || aStats.RTPSequenceGapEvents != 1 ||
		aStats.EstimatedMissing != 1 {
		t.Fatalf("incorrect per-peer counters: %+v", aStats)
	}
	if got := b.VoIPStats().RTPPackets; got != 0 {
		t.Fatalf("other peer received unrelated voice stats: %d", got)
	}
	snap := h.PeerVoIPStats()
	if len(snap) != 2 || snap["A"].RTPPackets != 2 || snap["B"].RTPPackets != 0 {
		t.Fatalf("hub snapshot isolation failed: %+v", snap)
	}
}
