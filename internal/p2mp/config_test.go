package p2mp

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
)

func TestConfigDestinationAndAuthentication(t *testing.T) {
	a:=sha256.Sum256([]byte("peer-a"))
	b:=sha256.Sum256([]byte("peer-b"))
	c,err:=Parse(FileConfig{Peers:[]PeerConfig{
		{ID:"A",CertificateSHA256:hex.EncodeToString(a[:]),Routes:[]string{"10.77.0.2/32","192.168.20.0/24"}},
		{ID:"B",CertificateSHA256:hex.EncodeToString(b[:]),Routes:[]string{"10.77.0.3/32","192.168.30.0/24"}},
	}})
	if err!=nil{t.Fatal(err)}
	if c.Destination(netip.MustParseAddr("10.77.0.3")).ID!="B"{t.Fatal("wrong session")}
	if c.Destination(netip.MustParseAddr("192.168.20.44")).ID!="A"{t.Fatal("wrong LAN prefix")}
	if c.PeerByCertificate([]byte("peer-a"))!=c.Peers[0]{t.Fatal("peer A not authenticated")}
	if c.PeerByCertificate([]byte("unknown"))!=nil{t.Fatal("unknown certificate accepted")}
	if c.Destination(netip.MustParseAddr("224.0.0.251"))!=nil{t.Fatal("multicast must use replication")}
}
func TestAmbiguousPeerDestinationsRejected(t *testing.T){
	a:=strings.Repeat("a",64)
	b:=strings.Repeat("b",64)
	_,err:=Parse(FileConfig{Peers:[]PeerConfig{
		{ID:"A",CertificateSHA256:a,Routes:[]string{"10.77.0.0/24"}},
		{ID:"B",CertificateSHA256:b,Routes:[]string{"10.77.0.3/32"}},
	}})
	if err==nil{t.Fatal("overlapping destinations ambiguous")}
}
func TestDefaultRouteIsValidSessionDestination(t *testing.T){
	_,err:=Parse(FileConfig{Peers:[]PeerConfig{
		{ID:"all",CertificateSHA256:strings.Repeat("a",64),Routes:[]string{"0.0.0.0/0"}},
	}})
	if err!=nil{t.Fatal(err)}
}
