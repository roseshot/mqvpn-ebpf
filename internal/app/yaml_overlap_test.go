package app

import (
    "crypto/sha256"
    "encoding/hex"
    "os"
    "net/netip"
    "strings"
    "path/filepath"
    "testing"

    "github.com/roseshot/mqvpn-ebpf/internal/p2mp"
    "gopkg.in/yaml.v3"
)

// Two independent VPN instances can use identical IP prefixes and tunnel
// subnets: each hub has a private destination table and certificate namespace.
func TestTwoInstancesAcceptIdenticalSubnets(t *testing.T) {
    cfg,_:=testServerFiles(t)
    base:=cfg.Instances[0]
    base.Name="customer-a"
    base.Listen="0.0.0.0:4433"
    base.TUN="mq0"
    second:=base
    second.Name="customer-b"
    second.Listen="0.0.0.0:4434"
    second.TUN="mq1"
    dir:=t.TempDir()
    for i,inst:=range []*ServerInstance{&base,&second} {
        digest:=sha256.Sum256([]byte(inst.Name))
        peers:=p2mp.FileConfig{Peers:[]p2mp.PeerConfig{{
            ID:inst.Name+"-site-1",
            CertificateSHA256:hex.EncodeToString(digest[:]),
            Routes:[]string{"10.77.0.2/32","192.168.20.0/24"},
        }}}
        bytes,err:=yaml.Marshal(peers)
        if err!=nil{t.Fatal(err)}
        path:=filepath.Join(dir,[]string{"peers-a.yaml","peers-b.yaml"}[i])
        if err:=os.WriteFile(path,bytes,0600);err!=nil{t.Fatal(err)}
        inst.Peers=path
    }
    config:=ServerConfig{Instances:[]ServerInstance{base,second}}
    path:=filepath.Join(dir,"server.yaml")
    bytes,err:=yaml.Marshal(config)
    if err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(path,bytes,0600);err!=nil{t.Fatal(err)}
    prepared,err:=prepareConfigFile(path)
    if err!=nil{t.Fatal(err)}
    a:=prepared.instances["customer-a"]
    b:=prepared.instances["customer-b"]
    if a.spec.TUN==b.spec.TUN{t.Fatal("shared TUN unexpectedly accepted")}
    if a.peers==b.peers{t.Fatal("peer tables share pointers")}
    address:="192.168.20.77"
    check:=func(name string,p preparedInstance){
        t.Helper()
        ip:=netip.MustParseAddr(address)
        got:=p.peers.Destination(ip)
        if got==nil||got.ID!=name+"-site-1"{
            t.Fatalf("instance %s wrong lookup: %+v",name,got)
        }
    }
    check("customer-a",a)
    check("customer-b",b)
}

func TestRejectAmbiguousOverlapsWithinOneInstance(t *testing.T){
    f:=p2mp.FileConfig{Peers:[]p2mp.PeerConfig{
        {ID:"a",CertificateSHA256:strings.Repeat("a",64),Routes:[]string{"192.168.20.0/24"}},
        {ID:"b",CertificateSHA256:strings.Repeat("b",64),Routes:[]string{"192.168.20.1/32"}},
    }}
    if _,err:=p2mp.Parse(f);err==nil{t.Fatal("overlapping peer destinations inside the same instance must be rejected")}
}
