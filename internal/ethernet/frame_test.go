package ethernet

import (
	"bytes"
	"errors"
	"testing"
)

func TestContextZeroRoundTrip(t *testing.T) {
	frame := []byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
		0x81, 0x00, 0, 7, 0x08, 0, 1, 2, 3, 4, // 802.1Q VLAN tag preserved
	}
	payload, err := Encode(frame)
	if err != nil { t.Fatal(err) }
	if payload[0] != 0 { t.Fatalf("wrong context byte: %x", payload[0]) }
	got, err := Decode(payload)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(got, frame) { t.Fatalf("frame changed: %x != %x", got, frame) }
}

func TestBadFramesAndUnknownContext(t *testing.T) {
	if _, err := Encode(make([]byte, 13)); !errors.Is(err, ErrInvalidFrame) { t.Fatal(err) }
	if _, err := Decode([]byte{0, 1}); !errors.Is(err, ErrInvalidFrame) { t.Fatal(err) }
	if _, err := Decode([]byte{1, 2, 3}); !errors.Is(err, ErrUnsupportedContext) { t.Fatal(err) }
	if _, err := Decode(nil); !errors.Is(err, ErrUnsupportedContext) { t.Fatal(err) }
}
