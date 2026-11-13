package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testServerFiles(t *testing.T)(ServerConfig,string){
	t.Helper()
	dir:=t.TempDir()
	pub,priv,err:=ed25519.GenerateKey(rand.Reader)
	if err!=nil{t.Fatal(err)}
	tpl:=&x509.Certificate{
		SerialNumber:big.NewInt(1),
		NotBefore:time.Now().Add(-time.Hour),
		NotAfter:time.Now().Add(time.Hour),
		BasicConstraintsValid:true,IsCA:true,
		KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature,
	}
	der,err:=x509.CreateCertificate(rand.Reader,tpl,tpl,pub,priv)
	if err!=nil{t.Fatal(err)}
	keyDER,err:=x509.MarshalPKCS8PrivateKey(priv)
	if err!=nil{t.Fatal(err)}
	cert:=filepath.Join(dir,"server.crt")
	key:=filepath.Join(dir,"server.key")
	peers:=filepath.Join(dir,"peers.json")
	write:=func(path string,p []byte){
		if err:=os.WriteFile(path,p,0600);err!=nil{t.Fatal(err)}
	}
	write(cert,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}))
	write(key,pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:keyDER}))
	sum:=sha256.Sum256([]byte("client"))
	data,err:=json.Marshal(map[string]any{
		"peers":[]map[string]any{{
			"id":"peer-a","certificate_sha256":hex.EncodeToString(sum[:]),
			"routes":[]string{"10.77.0.2/32"},
		}},
	})
	if err!=nil{t.Fatal(err)}
	write(peers,data)
	return ServerConfig{Instances:[]ServerInstance{{
		Name:"edge-a",Listen:":4433",TUN:"mq0",
		Cert:cert,Key:key,ClientCA:cert,Peers:peers,
	}}},peers
}

func TestPrepareServerDetectsPeerMapChangeWithoutListenerRestart(t *testing.T){
	cfg,peersFile:=testServerFiles(t)
	initial,err:=prepareServer(cfg)
	if err!=nil{t.Fatal(err)}
	p:=initial.instances["edge-a"]
	content,err:=os.ReadFile(peersFile)
	if err!=nil{t.Fatal(err)}
	var payload map[string]any
	if err:=json.Unmarshal(content,&payload);err!=nil{t.Fatal(err)}
	peers:=payload["peers"].([]any)
	peer:=peers[0].(map[string]any)
	peer["routes"]=[]string{"10.77.0.2/32","192.168.20.0/24"}
	content,err=json.Marshal(payload)
	if err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(peersFile,content,0600);err!=nil{t.Fatal(err)}
	after,err:=prepareServer(cfg)
	if err!=nil{t.Fatal(err)}
	q:=after.instances["edge-a"]
	if initial.fingerprint==after.fingerprint{t.Fatal("configuration change not detected")}
	if p.staticHash!=q.staticHash{t.Fatal("peer-only change would restart QUIC listener")}
	if p.peerHash==q.peerHash{t.Fatal("peer mapping change was not detected")}
	if len(q.peers.Peers[0].Routes)!=2{t.Fatal("reloaded prefix not present")}
}

func TestPrepareServerRejectsInvalidPeerUpdate(t *testing.T){
	cfg,peersFile:=testServerFiles(t)
	first,err:=prepareServer(cfg)
	if err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(peersFile,[]byte(`{"peers":[{"bad":"missing valid auth"}]}`),0600);err!=nil{t.Fatal(err)}
	if _,err:=prepareServer(cfg);err==nil{t.Fatal("invalid peer data passed validation")}
	if len(first.instances["edge-a"].peers.Peers)!=1{t.Fatal("last valid snapshot mutated")}
}

func TestValidateCommandUsesConfigWithoutTUN(t *testing.T){
	cfg,_:=testServerFiles(t)
	path:=filepath.Join(t.TempDir(),"server.json")
	payload,err:=json.Marshal(cfg)
	if err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(path,payload,0600);err!=nil{t.Fatal(err)}
	if err:=validateServerCLI([]string{"--config",path},nil);err!=nil{t.Fatal(err)}
}

func TestReloadCommandRejectsInvalidPID(t *testing.T){
	if err:=reloadServerCLI([]string{"--pid","0"},nil);err==nil{
		t.Fatal("unsafe PID accepted")
	}
}
