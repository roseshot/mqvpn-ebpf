package p2mp

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
)

func TestConfigPermissions(t *testing.T){
	a:=sha256.Sum256([]byte("peer-a"))
	b:=sha256.Sum256([]byte("peer-b"))
	conf,err:=Parse(FileConfig{Peers:[]PeerConfig{
		{ID:"A",CertificateSHA256:hex.EncodeToString(a[:]),Routes:[]string{"10.77.0.2/32","192.168.20.0/24"},MulticastGroups:[]string{"224.0.0.251"}},
		{ID:"B",CertificateSHA256:hex.EncodeToString(b[:]),Routes:[]string{"10.77.0.3/32","192.168.30.0/24"},MulticastGroups:[]string{"224.0.0.251"}},
	}})
	if err!=nil{t.Fatal(err)}
	if conf.Destination(netip.MustParseAddr("192.168.20.20")).ID!="A"{t.Fatal("bad site lookup")}
	if conf.Destination(netip.MustParseAddr("10.77.0.3")).ID!="B"{t.Fatal("bad peer lookup")}
	if !conf.Peers[0].Owns(netip.MustParseAddr("10.77.0.2")){t.Fatal("route ownership")}
	if conf.Peers[0].Owns(netip.MustParseAddr("10.77.0.3")){t.Fatal("spoofed source allowed")}
	if conf.PeerByCertificate([]byte("peer-a"))!=conf.Peers[0]{t.Fatal("fingerprint lookup")}
	if conf.PeerByCertificate([]byte("unknown"))!=nil{t.Fatal("unauthorized peer allowed")}
}

func TestDuplicatePrefixesRejected(t *testing.T){
	a:=strings.Repeat("a",64)
	b:=strings.Repeat("b",64)
	_,err:=Parse(FileConfig{Peers:[]PeerConfig{
		{ID:"A",CertificateSHA256:a,Routes:[]string{"10.77.0.0/24"}},
		{ID:"B",CertificateSHA256:b,Routes:[]string{"10.77.0.3/32"}},
	}})
	if err==nil{t.Fatal("overlap must fail")}
}
