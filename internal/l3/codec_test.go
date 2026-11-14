package l3

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func compressibleIPv4(n int) []byte {
	pkt := make([]byte, n)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(n))
	pkt[8], pkt[9] = 64, 17
	copy(pkt[12:16], []byte{10, 1, 0, 1})
	copy(pkt[16:20], []byte{10, 2, 0, 1})
	return pkt
}
func TestZstdNegotiationAndRoundTrip(t *testing.T) {
	pkt := compressibleIPv4(1500)
	codec := Codec{Compression: true, MaxFrame: 1514}
	frame, err := codec.Wrap(pkt, false)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(frame[13:15]) != zstdEtherType {
		t.Fatal("compressible IP was not encoded with zstd")
	}
	got, err := codec.Unwrap(frame)
	if err != nil || !bytes.Equal(got, pkt) {
		t.Fatalf("compressed roundtrip failed: %v", err)
	}
	if _, err := (Codec{MaxFrame: 1514}).Unwrap(frame); err == nil {
		t.Fatal("legacy client accepted unnegotiated compressed frame")
	}
	if _, err := (Codec{Compression: true, MaxFrame: 1400}).Unwrap(frame); err == nil {
		t.Fatal("oversized decompressed frame accepted")
	}
	plain, err := codec.Wrap(pkt, true)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(plain[13:15]) != 0x0800 {
		t.Fatal("priority packet must bypass compression")
	}
	if _, err := codec.Unwrap(plain); err != nil {
		t.Fatal(err)
	}
}
func TestZstdRejectsMalformedFrames(t *testing.T) {
	pkt := compressibleIPv4(1500)
	codec := Codec{Compression: true, MaxFrame: 1514}
	frame, err := codec.Wrap(pkt, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, corrupt := range [][]byte{
		frame[:16],
		append([]byte(nil), frame[:17]...),
	} {
		if _, err := codec.Unwrap(corrupt); err == nil {
			t.Fatal("accepted malformed zstd frame")
		}
	}
	invalid := append([]byte(nil), frame...)
	invalid[15], invalid[16] = 0, 20
	if _, err := codec.Unwrap(invalid); err == nil {
		t.Fatal("accepted lying decoded length")
	}
}
