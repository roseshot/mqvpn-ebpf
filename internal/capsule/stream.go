// Package capsule implements the RFC 9297 DATAGRAM Capsule transport used
// by CONNECT-ETHERNET over HTTP/1.1 Upgrade. It carries exactly the same
// Context ID 0 + Ethernet frame payload as the QUIC DATAGRAM backend.
package capsule

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// Stream sends and receives complete, bounded HTTP Datagram payloads over an
// already authenticated and upgraded TLS connection. Reader can be the
// buffered reader returned by HTTP response parsing or server Hijack.
type Stream struct {
	conn     net.Conn
	reader   *bufio.Reader
	writeMu  sync.Mutex
	maxFrame int
}

func New(conn net.Conn, reader *bufio.Reader, maxFrame int) (*Stream, error) {
	if conn == nil {
		return nil, errors.New("capsule connection required")
	}
	if maxFrame < 64 || maxFrame > 65535 {
		return nil, fmt.Errorf("invalid max Ethernet frame %d", maxFrame)
	}
	if reader == nil {
		reader = bufio.NewReader(conn)
	}
	return &Stream{conn: conn, reader: reader, maxFrame: maxFrame}, nil
}

func (s *Stream) Close() error { return s.conn.Close() }

// DATAGRAM Capsule = type varint(0), length varint, HTTP Datagram payload.
// The HTTP Datagram payload is a Context ID 0 followed by a full Ethernet
// frame. The Context ID is already encoded by l3.Wrap; do not add it twice.
func (s *Stream) SendDatagram(payload []byte) error {
	if len(payload) == 0 || len(payload) > s.maxFrame+1 {
		return fmt.Errorf("capsule datagram size %d exceeds max %d", len(payload), s.maxFrame+1)
	}
	data := make([]byte, 0, 1+8+len(payload))
	data = append(data, 0) // Capsule Type 0x00: DATAGRAM
	data = appendVarint(data, uint64(len(payload)))
	data = append(data, payload...)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	for len(data) > 0 {
		n, err := s.conn.Write(data)
		if err != nil {
			return fmt.Errorf("write DATAGRAM capsule: %w", err)
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// ReceiveDatagram skips unknown capsule types as required by RFC 9297.
// A canceled session closes its connection so blocking reads are interruptible.
func (s *Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = s.conn.Close() })
	defer stop()
	for {
		typ, err := readVarint(s.reader)
		if err != nil {
			return nil, err
		}
		size, err := readVarint(s.reader)
		if err != nil {
			return nil, err
		}
		if typ != 0 {
			// Skip unknown extensions without allocating untrusted lengths.
			if _, err := io.CopyN(io.Discard, s.reader, int64(size)); err != nil {
				return nil, err
			}
			continue
		}
		if size == 0 || size > uint64(s.maxFrame+1) {
			return nil, fmt.Errorf("DATAGRAM capsule size %d outside limit %d", size, s.maxFrame+1)
		}
		result := make([]byte, int(size))
		if _, err := io.ReadFull(s.reader, result); err != nil {
			return nil, err
		}
		return result, nil
	}
}

// QUIC variable-length integer encoding (RFC 9000, Section 16).
func appendVarint(dst []byte, x uint64) []byte {
	switch {
	case x < (1 << 6):
		return append(dst, byte(x))
	case x < (1 << 14):
		var buf [2]byte
		binary.BigEndian.PutUint16(buf[:], uint16(x)|0x4000)
		return append(dst, buf[:]...)
	case x < (1 << 30):
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], uint32(x)|0x80000000)
		return append(dst, buf[:]...)
	default:
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], x|0xc000000000000000)
		return append(dst, buf[:]...)
	}
}

func readVarint(r *bufio.Reader) (uint64, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	n := 1 << uint(b>>6)
	v := uint64(b & 0x3f)
	for i := 1; i < n; i++ {
		b, err = r.ReadByte()
		if err != nil {
			return 0, err
		}
		v = (v << 8) | uint64(b)
	}
	return v, nil
}
