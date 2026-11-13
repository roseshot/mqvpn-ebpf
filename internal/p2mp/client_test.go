package p2mp

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestClientGroups(t *testing.T){
	g,err:=GroupList("224.0.0.251,239.1.2.3")
	if err!=nil||!g[netip.MustParseAddr("224.0.0.251")]{t.Fatal(g,err)}
	if _,err:=GroupList("not-an-ip");err==nil{t.Fatal("bad group accepted")}
	packet:=make([]byte,28)
	packet[0]=0x45;packet[8]=255;packet[9]=17
	binary.BigEndian.PutUint16(packet[2:4],28)
	copy(packet[16:20],[]byte{224,0,0,251})
	binary.BigEndian.PutUint16(packet[22:24],5353)
	if !allowedDestination(netip.MustParseAddr("224.0.0.251"),packet,g,newRateLimit(20)){t.Fatal("mDNS should be allowed")}
	packet[8]=1
	if allowedDestination(netip.MustParseAddr("224.0.0.251"),packet,g,newRateLimit(20)){t.Fatal("invalid mDNS TTL allowed")}
	if allowedDestination(netip.MustParseAddr("224.0.0.1"),packet,g,newRateLimit(20)){t.Fatal("unconfigured group allowed")}
}
