//go:build linux

package wan

import (
	"context"
	"net"
	"testing"
)

func TestDialTCPBoundToExplicitLoopback(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback TCP unavailable: %v", err)
	}
	defer ln.Close()
	remote := ln.Addr().(*net.TCPAddr)
	conn, source, err := DialTCP(context.Background(), "127.0.0.1", "", remote)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if source.String() != "127.0.0.1" {
		t.Fatalf("unexpected source %v", source)
	}
	accepted, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
}
