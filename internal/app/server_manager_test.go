package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/configfile"
	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
	"github.com/roseshot/mqvpn-ebpf/internal/tcebpf"
)

func testServerFiles(t *testing.T) (ServerConfig, string) {
	t.Helper()
	dir := t.TempDir()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames: []string{"edge-a.example.test", "edge-b.example.test", "customer-a.example.test", "customer-b.example.test", "vpn-a.example.test", "vpn-b.example.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, pub, private)
	if err != nil { t.Fatal(err) }
	derKey, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil { t.Fatal(err) }
	certPath, keyPath, peerPath := filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"), filepath.Join(dir, "peers.yaml")
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0600); err != nil { t.Fatal(err) }
	}
	write(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	write(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: derKey}))
	sum := sha256.Sum256([]byte("test-client"))
	peers := p2mp.FileConfig{Peers: []p2mp.PeerConfig{{
		ID: "site-a", CertificateSHA256: hex.EncodeToString(sum[:]),
		Routes: []string{"10.77.0.2/32"},
	}}}
	data, err := configfile.Marshal(peerPath, peers)
	if err != nil { t.Fatal(err) }
	write(peerPath, data)
	return ServerConfig{
		Listen: "0.0.0.0:4433",
		Instances: []ServerInstance{{
			Name: "edge-a", ServerName: "edge-a.example.test", TUN: "mq0",
			Address:"10.77.0.1/24",MTU:1400,MaxFrame:1414,
			Peers: peerPath, Cert: certPath, Key: keyPath, ClientCA: certPath,
		}},
	}, peerPath
}

func TestPrepareServerPeerHotReloadKeepsListenerAndTLS(t *testing.T) {
	cfg, path := testServerFiles(t)
	first, err := prepareServer(cfg)
	if err != nil { t.Fatal(err) }
	before := first.instances["edge-a"]
	sum := sha256.Sum256([]byte("test-client"))
	data, err := configfile.Marshal(path, p2mp.FileConfig{Peers: []p2mp.PeerConfig{{
		ID: "site-a", CertificateSHA256: hex.EncodeToString(sum[:]),
		Routes: []string{"10.77.0.2/32", "192.168.20.0/24"},
	}}})
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, data, 0600); err != nil { t.Fatal(err) }
	next, err := prepareServer(cfg)
	if err != nil { t.Fatal(err) }
	after := next.instances["edge-a"]
	if first.listen != next.listen || before.staticHash != after.staticHash {
		t.Fatal("peer-only update changed shared UDP listener or per-SNI TLS identity")
	}
	if before.peerHash == after.peerHash || len(after.peers.Peers[0].Routes) != 2 {
		t.Fatal("new YAML peer routes not reloaded")
	}
	if first.fingerprint == next.fingerprint { t.Fatal("configuration digest unchanged") }
}

func TestPrepareRejectsBadPeerYAML(t *testing.T) {
	cfg, path := testServerFiles(t)
	old, err := prepareServer(cfg)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, []byte("peers:\n  - bad: true\n"), 0600); err != nil { t.Fatal(err) }
	if _, err := prepareServer(cfg); err == nil { t.Fatal("invalid peer update accepted") }
	if len(old.instances["edge-a"].peers.Peers) != 1 { t.Fatal("old validated snapshot modified") }
}

func TestPrepareRejectsHostnameCertificateMismatch(t *testing.T) {
	cfg, _ := testServerFiles(t)
	cfg.Instances[0].ServerName = "not-in-san.example.test"
	if _, err := prepareServer(cfg); err == nil { t.Fatal("SNI certificate SAN mismatch accepted") }
}

func TestValidateCLIUsesYAMLWithoutTUN(t *testing.T) {
	cfg, _ := testServerFiles(t)
	path := filepath.Join(t.TempDir(), "server.yaml")
	data, err := configfile.Marshal(path, cfg)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, data, 0600); err != nil { t.Fatal(err) }
	if err := validateServerCLI([]string{"--config", path}, nil); err != nil { t.Fatal(err) }
}
func TestReloadCommandRejectsInvalidPID(t *testing.T) {
	if err := reloadServerCLI([]string{"--pid", "0"}, nil); err == nil { t.Fatal("invalid PID accepted") }
}


func TestBundledTCDoesNotDependOnFilesystem(t *testing.T) {
	cfg,_:=testServerFiles(t)
	first,err:=prepareServer(cfg)
	if err!=nil{t.Fatal(err)}
	if first.instances["edge-a"].spec.TC==nil || first.instances["edge-a"].spec.TC.Object!="" {t.Fatal("server default is not embedded TCX")}
	second,err:=prepareServer(cfg)
	if err!=nil{t.Fatal(err)}
	if first.instances["edge-a"].staticHash != second.instances["edge-a"].staticHash {t.Fatal("embedded TC object changed across reload")}
}

func TestAutoTCMissingELFAndELFInstallationOnReload(t *testing.T) {
	cfg,_:=testServerFiles(t)
	object:=filepath.Join(t.TempDir(),"tun_tc.o")
	cfg.Instances[0].TC=&tcebpf.Config{Mode:"auto",Object:object,MSSClamp:"auto",Stats:true}
	missing,err:=prepareServer(cfg)
	if err!=nil {t.Fatalf("auto must tolerate missing ELF: %v",err)}
	if err:=os.WriteFile(object,[]byte("simulated-new-object"),0600);err!=nil{t.Fatal(err)}
	present,err:=prepareServer(cfg)
	if err!=nil{t.Fatal(err)}
	if missing.instances["edge-a"].staticHash==present.instances["edge-a"].staticHash {t.Fatal("auto did not notice installed ELF")}
	cfg.Instances[0].TC.Mode="required"
	if err:=os.Remove(object);err!=nil{t.Fatal(err)}
	if _,err:=prepareServer(cfg);err==nil{t.Fatal("required policy must reject missing ELF")}
}

func TestServerTunnelPoolRequiresAuthorizedPeers(t *testing.T) {
	cfg,peerPath:=testServerFiles(t)
	cfg.Instances[0].TunnelPool="10.77.0.0/24"
	if _,err:=prepareServer(cfg);err==nil{t.Fatal("tunnel pool without dynamic peers accepted")}
	fp:=sha256.Sum256([]byte("test-client"))
	file:=p2mp.FileConfig{Peers:[]p2mp.PeerConfig{{ID:"site-a",CertificateSHA256:hex.EncodeToString(fp[:]),DynamicTunnelIP:true}}}
	raw,err:=configfile.Marshal(peerPath,file)
	if err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(peerPath,raw,0600);err!=nil{t.Fatal(err)}
	p,err:=prepareServer(cfg)
	if err!=nil{t.Fatal(err)}
	if p.instances["edge-a"].pool==nil{t.Fatal("validated pool not prepared")}
	if p.instances["edge-a"].spec.TunnelPool!="10.77.0.0/24"{t.Fatal("pool config lost")}
	cfg.Instances[0].TunnelPool=""
	if _,err:=prepareServer(cfg);err==nil{t.Fatal("dynamic peer without pool accepted")}
	cfg.Instances[0].TunnelPool="10.78.0.0/24"
	if _,err:=prepareServer(cfg);err==nil{t.Fatal("off-link tunnel pool accepted")}
}

func TestTCObjectReloadUpdatesOnlyInstanceHash(t *testing.T) {
	cfg,_:=testServerFiles(t)
	object:=filepath.Join(t.TempDir(),"tun_tc.o")
	if err:=os.WriteFile(object,[]byte("tc-object-v1"),0600);err!=nil{t.Fatal(err)}
	cfg.Instances[0].TC=&tcebpf.Config{Object:object,MSSClamp:"auto",Stats:true}
	first,err:=prepareServer(cfg)
	if err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(object,[]byte("tc-object-v2"),0600);err!=nil{t.Fatal(err)}
	second,err:=prepareServer(cfg)
	if err!=nil{t.Fatal(err)}
	if first.instances["edge-a"].staticHash==second.instances["edge-a"].staticHash{
		t.Fatal("TC ELF replacement failed to trigger instance restart")
	}
	if first.listen!=second.listen{t.Fatal("TC ELF change modified shared UDP listener")}
}

func TestPreparedSingleIPCertAndTLSWithoutSNI(t *testing.T){
	cfg,_:=testServerFiles(t)
	cfg.Instances[0].ServerName="198.51.100.7"
	// The certificate contains IP SAN only, deliberately no DNS SAN.
	pub,private,err:=ed25519.GenerateKey(rand.Reader)
	if err!=nil{t.Fatal(err)}
	leaf:=&x509.Certificate{
		SerialNumber:big.NewInt(37),
		NotBefore:time.Now().Add(-time.Minute),
		NotAfter:time.Now().Add(time.Hour),
		BasicConstraintsValid:true,IsCA:true,
		KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature,
		ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth,x509.ExtKeyUsageClientAuth},
		IPAddresses:[]net.IP{net.ParseIP("198.51.100.7")},
	}
	der,err:=x509.CreateCertificate(rand.Reader,leaf,leaf,pub,private)
	if err!=nil{t.Fatal(err)}
	pk,err:=x509.MarshalPKCS8PrivateKey(private)
	if err!=nil{t.Fatal(err)}
	for _,file:=range []struct{path string;content []byte}{
		{cfg.Instances[0].Cert,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der})},
		{cfg.Instances[0].Key,pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:pk})},
	}{if err:=os.WriteFile(file.path,file.content,0600);err!=nil{t.Fatal(err)}}
	prepared,err:=prepareServer(cfg)
	if err!=nil{t.Fatalf("IP SAN single instance preparation: %v",err)}
	mux:=newServerMux()
	live:=&liveInstance{prepared:prepared.instances["edge-a"]}
	mux.Publish(map[string]*liveInstance{"edge-a":live})
	root,err:=certPool(cfg.Instances[0].ClientCA)
	if err!=nil{t.Fatal(err)}
	cert,err:=keyPair(cfg.Instances[0].Cert,cfg.Instances[0].Key)
	if err!=nil{t.Fatal(err)}
	serverSide,clientSide:=net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()
	_ = serverSide.SetDeadline(time.Now().Add(3*time.Second))
	_ = clientSide.SetDeadline(time.Now().Add(3*time.Second))
	served:=make(chan error,1)
	go func(){
		s:=tls.Server(serverSide,&tls.Config{MinVersion:tls.VersionTLS13,GetConfigForClient:mux.TLSConfigFor})
		served<-s.Handshake()
	}()
	c:=tls.Client(clientSide,&tls.Config{MinVersion:tls.VersionTLS13,ServerName:"198.51.100.7",RootCAs:root,
		Certificates:[]tls.Certificate{cert}})
	if err:=c.Handshake();err!=nil{t.Fatalf("client must verify IP SAN without SNI: %v",err)}
	if err:=<-served;err!=nil{t.Fatalf("server TLS mTLS failed: %v",err)}
	if got:=c.ConnectionState().ServerName;got!=""{
		t.Fatalf("IP identity unexpectedly emitted SNI %q",got)
	}
}
