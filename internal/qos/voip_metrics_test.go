package qos

import (
	"encoding/binary"
	"sync"
	"testing"
)

func fakeVoIP4(seq uint16, dscp byte) []byte {
	pkt := make([]byte, 20+8+12)
	pkt[0], pkt[1] = 0x45, dscp<<2
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = 17
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(pkt[20:22], 30000)
	binary.BigEndian.PutUint16(pkt[22:24], 30002)
	binary.BigEndian.PutUint16(pkt[24:26], 20)
	pkt[28], pkt[29] = 0x80, 96
	binary.BigEndian.PutUint16(pkt[30:32], seq)
	binary.BigEndian.PutUint32(pkt[36:40], 0x12345678)
	return pkt
}

func TestVoIPMetricsRTPGapAndLatePackets(t *testing.T) {
	var monitor VoIPMonitor
	for _, seq := range []uint16{1, 4, 3, 5} {
		monitor.Observe(fakeVoIP4(seq, 46))
	}
	monitor.Observe(fakeVoIP4(6, 0)) // Unmarked RTP is intentionally excluded.
	s := monitor.Snapshot()
	if s.RTPPackets != 4 || s.RTPSequenceGapEvents != 1 ||
		s.EstimatedMissing != 2 || s.LateOrDuplicate != 1 {
		t.Fatalf("unexpected RTP indicators %+v", s)
	}
}

func TestVoIPMetricsRTPSequenceWrap(t *testing.T) {
	var monitor VoIPMonitor
	for _, seq := range []uint16{65534, 65535, 0, 1} {
		monitor.Observe(fakeVoIP4(seq, 46))
	}
	s := monitor.Snapshot()
	if s.RTPPackets != 4 || s.RTPSequenceGapEvents != 0 ||
		s.LateOrDuplicate != 0 {
		t.Fatalf("RTP rollover was counted as loss %+v", s)
	}
}

func TestVoIPMetricsRTCPReceiverReport(t *testing.T) {
	pkt := fakeVoIP4(5, 46)
	pkt = append(pkt[:28], make([]byte, 32)...)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[24:26], 40)
	pkt[28], pkt[29] = 0x81, 201
	binary.BigEndian.PutUint16(pkt[30:32], 7)
	binary.BigEndian.PutUint32(pkt[32:36], 123)
	block := pkt[36:60]
	binary.BigEndian.PutUint32(block[0:4], 0x12345678)
	block[4], block[5], block[6], block[7] = 64, 0, 0, 9
	binary.BigEndian.PutUint32(block[12:16], 1920)
	var monitor VoIPMonitor
	monitor.Observe(pkt)
	s := monitor.Snapshot()
	if s.RTCPPackets != 1 || s.RTCPReportBlocks != 1 ||
		s.LatestFractionLost != 64 || s.LatestCumulativeLost != 9 ||
		s.LatestJitterTicks != 1920 || s.RTPPackets != 0 {
		t.Fatalf("wrong RTCP report extraction %+v", s)
	}
}

func TestVoIPMetricsIgnoreMalformedAndUnmarked(t *testing.T) {
	var monitor VoIPMonitor
	pkt := fakeVoIP4(1, 46)
	monitor.Observe(pkt[:15])
	pkt = fakeVoIP4(1, 46)
	pkt[6] = 0x20 // IPv4 MF: must not parse partial UDP contents.
	monitor.Observe(pkt)
	pkt = fakeVoIP4(1, 0)
	monitor.Observe(pkt)
	pkt = fakeVoIP4(1, 46)
	binary.BigEndian.PutUint16(pkt[24:26], 400)
	monitor.Observe(pkt)
	if s := monitor.Snapshot(); s.RTPPackets != 0 || s.RTCPPackets != 0 {
		t.Fatalf("malformed packet was classified as voice %+v", s)
	}
}

func TestVoIPMetricsConcurrentSnapshotsAndBoundedFlows(t *testing.T) {
	var monitor VoIPMonitor
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 400; i++ {
			pkt := fakeVoIP4(uint16(i), 46)
			binary.BigEndian.PutUint32(pkt[36:40], uint32(i))
			monitor.Observe(pkt)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 400; i++ {
			_ = monitor.Snapshot()
		}
	}()
	wg.Wait()
	if len(monitor.flows) > maxVoIPStreams {
		t.Fatalf("unbounded SSRC map: %d", len(monitor.flows))
	}
	if monitor.Snapshot().RTPPackets != 400 {
		t.Fatal("concurrent RTP packets lost from statistics")
	}
}
