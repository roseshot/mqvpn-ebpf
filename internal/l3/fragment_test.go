package l3

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
	"time"
)

func mtuPacket(size int) []byte {
	p := make([]byte, size)
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:4], uint16(size))
	copy(p[12:16], []byte{10, 10, 0, 1})
	copy(p[16:20], []byte{10, 10, 0, 2})
	// Ensure this packet will not Zstd-compress trivially.
	rng := rand.New(rand.NewSource(19))
	_, _ = rng.Read(p[20:])
	return p
}

func TestFragmentMTU1500OutOfOrderAndDup(t *testing.T) {
	pkt := mtuPacket(1500)
	frame, err := (Codec{MaxFrame: 1514}).Wrap(pkt, false)
	if err != nil {
		t.Fatal(err)
	}
	sender := &Fragmenter{Enabled: true}
	parts, err := sender.Split(frame)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 2 {
		t.Fatalf("expected 2 fragments, got %d", len(parts))
	}
	for _, p := range parts {
		if len(p) > FragmentPayloadBudget {
			t.Fatalf("fragment exceeds budget: %d", len(p))
		}
	}
	r := &Reassembler{Enabled: true, MaxFrame: 1514}
	if _, ready, err := r.Accept(parts[1]); ready || err != nil {
		t.Fatalf("out-of-order incomplete result = %v, %v", ready, err)
	}
	if _, ready, err := r.Accept(parts[1]); ready || err != nil {
		t.Fatalf("duplicate incomplete result = %v, %v", ready, err)
	}
	complete, ready, err := r.Accept(parts[0])
	if !ready || err != nil || !bytes.Equal(frame, complete) {
		t.Fatalf("reassembly failed: ready=%v, err=%v", ready, err)
	}
	out, err := (Codec{MaxFrame: 1514}).Unwrap(complete)
	if err != nil || !bytes.Equal(out, pkt) {
		t.Fatalf("IP payload mismatch: %v", err)
	}
	if r.buffered != 0 || len(r.partials) != 0 {
		t.Fatal("completed frames must release cached fragments")
	}
}

func TestFragmentCompressedAndPriorityTraffic(t *testing.T) {
	codec := Codec{Compression: true, MaxFrame: 1514}
	pkt := make([]byte, 1500)
	pkt[0] = 0x45
	pkt[8], pkt[9] = 64, 17
	binary.BigEndian.PutUint16(pkt[2:4], 1500)
	frame, err := codec.Wrap(pkt, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) > FragmentPayloadBudget {
		t.Fatal("highly compressible 1500-byte packet should not need fragments")
	}
	parts, err := (&Fragmenter{Enabled: true}).Split(frame)
	if err != nil || len(parts) != 1 || !bytes.Equal(parts[0], frame) {
		t.Fatalf("compressed frame changed: %v", err)
	}
	out, err := codec.Unwrap(parts[0])
	if err != nil || !bytes.Equal(pkt, out) {
		t.Fatalf("compressed frame corrupted: %v", err)
	}
	// Small VoIP packets stay in a single ordinary, uncompressed frame.
	voice, err := codec.Wrap(mtuPacket(200), true)
	if err != nil {
		t.Fatal(err)
	}
	parts, err = (&Fragmenter{Enabled: true}).Split(voice)
	if err != nil || len(parts) != 1 {
		t.Fatalf("VoIP small packet fragmented: %v", err)
	}
	if binary.BigEndian.Uint16(parts[0][13:15]) != 0x0800 {
		t.Fatal("priority traffic must bypass compression")
	}
}

func TestFragmentRequiresCapabilityAndValidRanges(t *testing.T) {
	frame, err := (Codec{MaxFrame: 1514}).Wrap(mtuPacket(1500), false)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := (&Fragmenter{Enabled: true}).Split(frame)
	if err != nil {
		t.Fatal(err)
	}
	r := &Reassembler{MaxFrame: 1514}
	if _, ready, err := r.Accept(parts[0]); ready || err == nil {
		t.Fatal("unnegotiated extension accepted")
	}
	r = &Reassembler{Enabled: true, MaxFrame: 1400}
	if _, ready, err := r.Accept(parts[0]); ready || err == nil {
		t.Fatal("frame larger than negotiated max_frame accepted")
	}
	r = &Reassembler{Enabled: true, MaxFrame: 1514}
	if _, ready, err := r.Accept(parts[0]); ready || err != nil {
		t.Fatal("first fragment must remain incomplete")
	}
	corrupted := append([]byte(nil), parts[1]...)
	binary.BigEndian.PutUint32(corrupted[23:27], 500)
	if _, ready, err := r.Accept(corrupted); ready || err == nil {
		t.Fatal("overlapping data accepted")
	}
	if len(r.partials) != 0 || r.buffered != 0 {
		t.Fatal("overlapping data did not clear reassembly state")
	}
	malformed := append([]byte(nil), parts[1]...)
	binary.BigEndian.PutUint32(malformed[19:23], 999999)
	if _, ready, err := r.Accept(malformed); ready || err == nil {
		t.Fatal("invalid total accepted")
	}
}

func TestFragmentExpiryAndEviction(t *testing.T) {
	frame, err := (Codec{MaxFrame: 1514}).Wrap(mtuPacket(1500), false)
	if err != nil {
		t.Fatal(err)
	}
	f := &Fragmenter{Enabled: true}
	r := &Reassembler{Enabled: true, MaxFrame: 1514}
	for i := 0; i < maxPendingFragments+5; i++ {
		parts, err := f.Split(frame)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = r.Accept(parts[0])
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(r.partials) != maxPendingFragments {
		t.Fatalf("unbounded in-flight reassembly: %d", len(r.partials))
	}
	for _, p := range r.partials {
		p.created = time.Now().Add(-3 * fragmentTimeout)
	}
	parts, err := f.Split(frame)
	if err != nil {
		t.Fatal(err)
	}
	if _, ready, err := r.Accept(parts[0]); ready || err != nil {
		t.Fatalf("expired fragment test: %v", err)
	}
	if len(r.partials) != 1 {
		t.Fatalf("expired entries retained: %d", len(r.partials))
	}
}

func TestUnnegotiatedFragmenterPreservesPlainFrame(t *testing.T) {
	frame, err := (Codec{MaxFrame: 1514}).Wrap(mtuPacket(1500), false)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := (&Fragmenter{}).Split(frame)
	if err != nil || len(parts) != 1 || !bytes.Equal(parts[0], frame) {
		t.Fatalf("unfragmented frame changed: %v", err)
	}
	r := &Reassembler{}
	got, ready, err := r.Accept(frame)
	if !ready || err != nil || !bytes.Equal(got, frame) {
		t.Fatalf("ordinary frame changed: %v", err)
	}
}
