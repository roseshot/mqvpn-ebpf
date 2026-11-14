package p2mp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	quic "github.com/qoke/mp-quic-go"
	"github.com/roseshot/mqvpn-ebpf/internal/l3"
)

type limitedDatagramStream struct {
	limit     int
	afterOne  int
	written   [][]byte
	attempted int
}

func (s *limitedDatagramStream) SendDatagram(p []byte) error {
	s.attempted++
	if len(p) > s.limit {
		// QUIC's bound includes the HTTP/3 stream ID.
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(s.limit + 8)}
	}
	s.written = append(s.written, append([]byte(nil), p...))
	if s.afterOne > 0 && len(s.written) == 1 {
		s.limit = s.afterOne
	}
	return nil
}

func (*limitedDatagramStream) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, io.EOF
}

func TestAdaptiveDATAGRAMBudgetAndReassembly(t *testing.T) {
	frame, err := l3.Wrap(testLargeIP([4]byte{10, 5, 0, 1}, [4]byte{10, 5, 0, 2}))
	if err != nil {
		t.Fatal(err)
	}
	f := &l3.Fragmenter{Enabled: true}
	s := &limitedDatagramStream{limit: 750}
	sent, reductions, err := sendEncodedFrame(context.Background(), s, f, frame)
	if err != nil {
		t.Fatal(err)
	}
	if reductions != 1 || sent < 3 || f.Budget() >= 750 {
		t.Fatalf("unexpected adaptation: sent=%d reductions=%d budget=%d",
			sent, reductions, f.Budget())
	}
	r := &l3.Reassembler{Enabled: true, MaxFrame: 1514}
	var assembled []byte
	for _, packet := range s.written {
		if len(packet) > s.limit {
			t.Fatalf("oversized transport payload: %d", len(packet))
		}
		value, complete, err := r.Accept(packet)
		if err != nil {
			t.Fatal(err)
		}
		if complete {
			assembled = value
		}
	}
	if !bytes.Equal(assembled, frame) {
		t.Fatal("adaptive fragments failed to reassemble")
	}
}

func TestAdaptiveDATAGRAMBudgetAfterPathCapacityDrop(t *testing.T) {
	frame, err := l3.Wrap(testLargeIP([4]byte{10, 7, 0, 1}, [4]byte{10, 7, 0, 2}))
	if err != nil {
		t.Fatal(err)
	}
	f := &l3.Fragmenter{Enabled: true}
	s := &limitedDatagramStream{limit: 1024, afterOne: 400}
	sent, reductions, err := sendEncodedFrame(context.Background(), s, f, frame)
	if err != nil {
		t.Fatal(err)
	}
	if reductions != 1 || sent < 4 || f.Budget() >= 400 {
		t.Fatalf("mid-flight path shrink not retried: sent=%d reduced=%d budget=%d",
			sent, reductions, f.Budget())
	}
	r := &l3.Reassembler{Enabled: true, MaxFrame: 1514}
	var complete []byte
	for _, frag := range s.written {
		value, ready, err := r.Accept(frag)
		if err != nil {
			t.Fatal(err)
		}
		if ready {
			complete = value
		}
	}
	if !bytes.Equal(complete, frame) {
		t.Fatal("restart after path change did not reconstruct original frame")
	}
}

func TestAdaptiveDATAGRAMDoesNotRetryWithoutNegotiation(t *testing.T) {
	frame, err := l3.Wrap(testLargeIP([4]byte{10, 9, 0, 1}, [4]byte{10, 9, 0, 2}))
	if err != nil {
		t.Fatal(err)
	}
	s := &limitedDatagramStream{limit: 750}
	f := &l3.Fragmenter{}
	_, reductions, err := sendEncodedFrame(context.Background(), s, f, frame)
	if err == nil || reductions != 0 || s.attempted != 1 {
		t.Fatal("unnegotiated session retried with extension framing")
	}
	if f.Budget() != l3.FragmentPayloadBudget {
		t.Fatal("legacy session budget changed")
	}
}

func TestAdaptiveDATAGRAMDoesNotResendOnNonSizeError(t *testing.T) {
	frame, err := l3.Wrap(testLargeIP([4]byte{10, 9, 0, 1}, [4]byte{10, 9, 0, 2}))
	if err != nil {
		t.Fatal(err)
	}
	expected := errors.New("transport closed")
	stream := &rejectDatagramStream{err: expected}
	_, reductions, err := sendEncodedFrame(context.Background(), stream,
		&l3.Fragmenter{Enabled: true}, frame)
	if !errors.Is(err, expected) || reductions != 0 || stream.calls != 1 {
		t.Fatalf("non-size error must not retry: error=%v reductions=%d calls=%d",
			err, reductions, stream.calls)
	}
}

type rejectDatagramStream struct {
	err   error
	calls int
}

func (s *rejectDatagramStream) SendDatagram([]byte) error {
	s.calls++
	return s.err
}
func (s *rejectDatagramStream) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, io.EOF
}

func TestAdaptiveDATAGRAMAbortsTooSmallLimit(t *testing.T) {
	frame, err := l3.Wrap(testLargeIP([4]byte{10, 9, 0, 1}, [4]byte{10, 9, 0, 2}))
	if err != nil {
		t.Fatal(err)
	}
	s := &limitedDatagramStream{limit: 130}
	f := &l3.Fragmenter{Enabled: true}
	_, reductions, err := sendEncodedFrame(context.Background(), s, f, frame)
	if err == nil || reductions != 0 || s.attempted != 1 {
		t.Fatalf("tiny budget must fail closed: reductions=%d attempts=%d", reductions, s.attempted)
	}
}
