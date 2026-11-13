package app

import (
    "crypto/sha256"
    "encoding/hex"
    "os"
    "path/filepath"
    "strings"
    "testing"

    "github.com/roseshot/mqvpn-ebpf/internal/p2mp"
    "gopkg.in/yaml.v3"
)

func TestYAMLInstanceCLIUpsertAndDelete(t *testing.T){
    cfg,_:=testServerFiles(t)
    cfg.Instances[0].Name="vpn-a"
    path:=filepath.Join(t.TempDir(),"server.yaml")
    data,err:=yaml.Marshal(cfg)
    if err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(path,data,0640);err!=nil{t.Fatal(err)}
    if err:=os.Chmod(path,0640);err!=nil{t.Fatal(err)}
    ref:=cfg.Instances[0]
    if err:=runInstanceCLI([]string{
        "upsert","--config",path,"--name","vpn-b",
        "--listen","0.0.0.0:4434","--tun","mq1",
        "--peers",ref.Peers,"--cert",ref.Cert,
        "--key",ref.Key,"--client-ca",ref.ClientCA,
    },nil);err!=nil{t.Fatal(err)}
    loaded,err:=loadServerConfig(path)
    if err!=nil{t.Fatal(err)}
    if len(loaded.Instances)!=2{t.Fatal("YAML upsert failed")}
    if err:=runInstanceCLI([]string{"upsert","--config",path,"--name","vpn-b","--listen",":4435"},nil);err!=nil{t.Fatal(err)}
    loaded,err=loadServerConfig(path)
    if err!=nil||loaded.Instances[1].Listen!=":4435"||loaded.Instances[1].TUN!="mq1"{t.Fatalf("partial YAML edit: %+v %v",loaded,err)}
    after,err:=os.ReadFile(path)
    if err!=nil{t.Fatal(err)}
    if !strings.HasPrefix(string(after),"instances:"){t.Fatalf("output not YAML: %q",after)}
    stat,err:=os.Stat(path)
    if err!=nil||stat.Mode().Perm()!=0640{t.Fatalf("file mode changed: %v, %v",stat,err)}
    if err:=runInstanceCLI([]string{"delete","--config",path,"--name","vpn-b"},nil);err!=nil{t.Fatal(err)}
    loaded,err=loadServerConfig(path)
    if err!=nil||len(loaded.Instances)!=1{t.Fatalf("YAML delete failed: %+v %v",loaded,err)}
}

func TestYAMLPeerFileHotReloadNoListenerRestart(t *testing.T){
    cfg,_:=testServerFiles(t)
    peerPath:=filepath.Join(t.TempDir(),"peers.yaml")
    sum:=sha256.Sum256([]byte("client-yaml"))
    write:=func(routes []string){
        t.Helper()
        data,err:=yaml.Marshal(p2mp.FileConfig{Peers:[]p2mp.PeerConfig{{
            ID:"vpn-a-client",CertificateSHA256:hex.EncodeToString(sum[:]),Routes:routes,
        }}})
        if err!=nil{t.Fatal(err)}
        if err:=os.WriteFile(peerPath,data,0600);err!=nil{t.Fatal(err)}
    }
    write([]string{"10.77.0.2/32"})
    cfg.Instances[0].Peers=peerPath
    before,err:=prepareServer(cfg)
    if err!=nil{t.Fatal(err)}
    write([]string{"10.77.0.2/32","192.168.20.0/24"})
    after,err:=prepareServer(cfg)
    if err!=nil{t.Fatal(err)}
    oldP:=before.instances["edge-a"]
    newP:=after.instances["edge-a"]
    if oldP.staticHash!=newP.staticHash{t.Fatal("peer-only YAML edit would restart listener")}
    if oldP.peerHash==newP.peerHash{t.Fatal("peer YAML edit was not detected")}
    if len(newP.peers.Peers[0].Routes)!=2{t.Fatal("new YAML routes were not loaded")}
}

func TestYAMLServerRejectsUnknownFields(t *testing.T){
    path:=filepath.Join(t.TempDir(),"server.yaml")
    raw:="instances:\n  - name: a\n    listen: ':4433'\n    tun: mq0\n    peers: peers.yaml\n    cert: cert.pem\n    key: key.pem\n    client_ca: ca.pem\n    unsupported_field: true\n"
    if err:=os.WriteFile(path,[]byte(raw),0600);err!=nil{t.Fatal(err)}
    if _,err:=loadServerConfig(path);err==nil{t.Fatal("unrecognized YAML field accepted")}
}
