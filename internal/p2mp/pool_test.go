package p2mp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	"github.com/roseshot/mqvpn-ebpf/internal/l3"
)

func dynamicPeerConfig(t *testing.T,n int)*Config{
	t.Helper()
	var peers []PeerConfig
	for i:=0;i<n;i++{
		id:=string(rune('A'+i))
		fp:=sha256.Sum256([]byte(id))
		peers=append(peers,PeerConfig{ID:id,CertificateSHA256:hex.EncodeToString(fp[:]),DynamicTunnelIP:true})
	}
	c,err:=Parse(FileConfig{Peers:peers})
	if err!=nil{t.Fatal(err)}
	return c
}

func TestTunnelPoolLeaseUniquenessAndRelease(t *testing.T){
	cfg:=dynamicPeerConfig(t,2)
	pool,err:=NewTunnelPool("10.77.0.0/29","10.77.0.1/29",cfg)
	if err!=nil{t.Fatal(err)}
	h,err:=New(&fakeDevice{},cfg,1160,nil)
	if err!=nil{t.Fatal(err)}
	if err:=h.SetTunnelPool(pool);err!=nil{t.Fatal(err)}
	ctx,cancel:=context.WithCancel(context.Background())
	defer cancel()
	as:=&fakeStream{out:make(chan []byte,8)}
	bs:=&fakeStream{out:make(chan []byte,8)}
	if _,err:=h.Attach(ctx,cfg.Peers[0],as);err==nil{t.Fatal("dynamic peer attached without negotiation")}
	a,err:=h.AttachWithTunnelIP(ctx,cfg.Peers[0],as,true)
	if err!=nil{t.Fatal(err)}
	b,err:=h.AttachWithTunnelIP(ctx,cfg.Peers[1],bs,true)
	if err!=nil{t.Fatal(err)}
	if a.TunnelAddress()!="10.77.0.0/29"||b.TunnelAddress()!="10.77.0.2/29"{
		t.Fatalf("wrong leases %q %q",a.TunnelAddress(),b.TunnelAddress())
	}
	packet:=ip4([4]byte{10,77,0,1},[4]byte{10,77,0,2})
	h.egress(packet)
	got,err:=l3.Unwrap(waitFrame(t,bs))
	if err!=nil||string(got)!=string(packet){t.Fatalf("wrong dynamic host forwarding: %v",err)}
	h.Detach(a)
	a2,err:=h.AttachWithTunnelIP(ctx,cfg.Peers[0],as,true)
	if err!=nil{t.Fatal(err)}
	if a2.TunnelAddress()!="10.77.0.0/29"{t.Fatal("lease was not released for reuse")}
	if _,err:=h.AttachWithTunnelIP(ctx,cfg.Peers[0],as,true);err==nil{t.Fatal("duplicate session allowed")}
	h.Detach(a2)
	h.Detach(b)
}

func TestTunnelPoolRejectsOverlapCapacityAndUnconfiguredPeers(t *testing.T){
	cfg:=dynamicPeerConfig(t,2)
	for _,tc:=range []struct{pool,server string}{
		{"10.77.0.0/32","10.77.0.0/32"},
		{"10.78.0.0/24","10.77.0.1/24"},
		{"10.77.0.1/24","10.77.0.1/24"},
		{"10.77.0.0/31","10.77.0.1/31"},
		{"","10.77.0.1/24"},
	}{
		if _,err:=NewTunnelPool(tc.pool,tc.server,cfg);err==nil{t.Fatalf("invalid tunnel_pool %q allowed",tc.pool)}
	}
	fp:=sha256.Sum256([]byte("static"))
	mixed,err:=Parse(FileConfig{Peers:[]PeerConfig{
		{ID:"dynamic",CertificateSHA256:strings.Repeat("a",64),DynamicTunnelIP:true},
		{ID:"static",CertificateSHA256:hex.EncodeToString(fp[:]),Routes:[]string{"10.77.0.2/32"}},
	}})
	if err!=nil{t.Fatal(err)}
	pool,err:=NewTunnelPool("10.77.0.0/24","10.77.0.1/24",mixed)
	if err!=nil{t.Fatalf("static host reservation must coexist with dynamic pool: %v",err)}
	if lease,err:=pool.allocate(map[string]*Session{});err!=nil || lease.String()!="10.77.0.0/24"{
		t.Fatalf("static host address was assigned dynamically: %s %v",lease,err)
	}
	if mixed.Destination(netip.MustParseAddr("10.77.0.2")).ID!="static"{t.Fatal("static forwarding broken")}
	broad,err:=Parse(FileConfig{Peers:[]PeerConfig{
		{ID:"dynamic",CertificateSHA256:strings.Repeat("a",64),DynamicTunnelIP:true},
		{ID:"static",CertificateSHA256:hex.EncodeToString(fp[:]),Routes:[]string{"10.77.0.0/25"}},
	}})
	if err!=nil{t.Fatal(err)}
	if _,err:=NewTunnelPool("10.77.0.0/24","10.77.0.1/24",broad);err==nil{t.Fatal("overlapping static subnet accepted")}
}

func TestTunnelPoolExhaustedAndTenantIsolation(t *testing.T){
	cfg:=dynamicPeerConfig(t,1)
	pool,err:=NewTunnelPool("10.77.0.0/31","10.77.0.1/31",cfg)
	if err!=nil{t.Fatal(err)}
	h,err:=New(&fakeDevice{},cfg,1160,nil)
	if err!=nil{t.Fatal(err)}
	_ = h.SetTunnelPool(pool)
	stream:=&fakeStream{out:make(chan []byte,4)}
	a,err:=h.AttachWithTunnelIP(context.Background(),cfg.Peers[0],stream,true)
	if err!=nil{t.Fatal(err)}
	if a.TunnelAddress()!="10.77.0.0/31"{t.Fatal(a.TunnelAddress())}
	if _,err:=pool.allocate(h.peers);err==nil{t.Fatal("duplicate address allocated")}
	other,err:=New(&fakeDevice{},cfg,1160,nil)
	if err!=nil{t.Fatal(err)}
	_ = other.SetTunnelPool(pool)
	b,err:=other.AttachWithTunnelIP(context.Background(),cfg.Peers[0],&fakeStream{out:make(chan []byte,4)},true)
	if err!=nil{t.Fatal(err)}
	if b.TunnelAddress()!=a.TunnelAddress(){t.Fatal("tenant allocation must be independent")}
	h.Detach(a);other.Detach(b)
}

func TestTunnelPoolReusesNetworkAndSubnetBroadcastAddresses(t *testing.T) {
	cfg:=dynamicPeerConfig(t,3)
	pool,err:=NewTunnelPool("10.77.0.0/30","10.77.0.1/30",cfg)
	if err!=nil{t.Fatalf("all three remaining /30 IPs should be usable: %v",err)}
	h,err:=New(&fakeDevice{},cfg,1160,nil)
	if err!=nil{t.Fatal(err)}
	if err:=h.SetTunnelPool(pool);err!=nil{t.Fatal(err)}
	leases:=[]string{"10.77.0.0/30","10.77.0.2/30","10.77.0.3/30"}
	var sessions []*Session
	for i,peer:=range cfg.Peers {
		s,err:=h.AttachWithTunnelIP(context.Background(),peer,&fakeStream{out:make(chan []byte,4)},true)
		if err!=nil{t.Fatal(err)}
		if s.TunnelAddress()!=leases[i] {t.Fatalf("peer %s got %s, want %s",peer.ID,s.TunnelAddress(),leases[i])}
		sessions=append(sessions,s)
	}
	for _,s:=range sessions {h.Detach(s)}
	// Fully reuse /31: one host is the Server and the other is a client.
	small:=dynamicPeerConfig(t,1)
	if _,err:=NewTunnelPool("10.77.0.0/31","10.77.0.1/31",small);err!=nil{t.Fatal(err)}
}
func TestTunnelPoolRefusesUniversalBroadcast(t *testing.T){
	cfg:=dynamicPeerConfig(t,1)
	// 255.255.255.255 is never a unicast destination, even with routed TUN.
	p:=&TunnelPool{prefix:netip.MustParsePrefix("255.255.255.254/31"),serverIP:netip.MustParseAddr("255.255.255.254")}
	if p.usable(netip.MustParseAddr("255.255.255.255")){t.Fatal("limited broadcast used for lease")}
	if p.usable(netip.MustParseAddr("255.255.255.254")){t.Fatal("server IP used for lease")}
	_ = cfg
}
