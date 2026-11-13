package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/capsule"
	"github.com/roseshot/mqvpn-ebpf/internal/l3"
	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
	"github.com/roseshot/mqvpn-ebpf/internal/configfile"
	"encoding/pem"
)

type tcpMockTun struct{
	out chan []byte
}
func(d *tcpMockTun)Read([]byte)(int,error){return 0,io.EOF}
func(d *tcpMockTun)Write(packet []byte)(int,error){
	select{case d.out<-append([]byte(nil),packet...):default:}
	return len(packet),nil
}
func(d *tcpMockTun)Close()error{return nil}

func TestTCPFallbackStrictHTTP1UpgradeAndCapsules(t *testing.T) {
	cfg,_:=testServerFiles(t)
	certBytes,err:=os.ReadFile(cfg.Instances[0].Cert)
	if err!=nil{t.Fatal(err)}
	block,_:=pem.Decode(certBytes)
	if block==nil{t.Fatal("bad fixture certificate")}
	sum:=sha256.Sum256(block.Bytes)
	data,err:=configfile.Marshal(cfg.Instances[0].Peers,p2mp.FileConfig{Peers:[]p2mp.PeerConfig{{
		ID:"site-a",CertificateSHA256:hex.EncodeToString(sum[:]),
		Routes:[]string{"10.77.0.2/32"},
	}}})
	if err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(cfg.Instances[0].Peers,data,0600);err!=nil{t.Fatal(err)}
	prepared,err:=prepareServer(cfg)
	if err!=nil{t.Fatal(err)}
	p:=prepared.instances["edge-a"]
	device:=&tcpMockTun{out:make(chan []byte,2)}
	hub,err:=p2mp.New(device,p.peers,p.spec.MaxFrame,slog.Default())
	if err!=nil{t.Fatal(err)}
	mgr:=newServerManager(context.Background(),slog.Default())
	mgr.tcpListen="127.0.0.1:0"
	mgr.mux.Publish(map[string]*liveInstance{
		"edge-a":{prepared:p,hub:hub,logger:slog.Default()},
	})
	if err:=mgr.startTCPListener();err!=nil{t.Fatal(err)}
	defer func(){
		hub.CloseSessions()
		_ = mgr.tcpServer.Close()
		_ = mgr.tcpListener.Close()
		<-mgr.tcpDone
	}()
	cert,err:=tls.LoadX509KeyPair(cfg.Instances[0].Cert,cfg.Instances[0].Key)
	if err!=nil{t.Fatal(err)}
	ca,err:=certPool(cfg.Instances[0].ClientCA)
	if err!=nil{t.Fatal(err)}
	conn,err:=tls.DialWithDialer(&net.Dialer{Timeout:3*time.Second},"tcp",mgr.tcpListener.Addr().String(),&tls.Config{
		MinVersion:tls.VersionTLS13,
		ServerName:"edge-a.example.test",
		RootCAs:ca,
		Certificates:[]tls.Certificate{cert},
		NextProtos:[]string{"http/1.1"},
	})
	if err!=nil{t.Fatal(err)}
	defer conn.Close()
	if conn.ConnectionState().NegotiatedProtocol!="http/1.1" {t.Fatal("ALPN")}
	request,err:=http.NewRequest(http.MethodGet,"https://edge-a.example.test/.well-known/masque/ethernet/",nil)
	if err!=nil{t.Fatal(err)}
	request.Header.Set("Connection","Upgrade")
	request.Header.Set("Upgrade","connect-ethernet")
	request.Header.Set("Capsule-Protocol","?1")
	if err:=request.Write(conn);err!=nil{t.Fatal(err)}
	reader:=bufio.NewReader(conn)
	response,err:=http.ReadResponse(reader,request)
	if err!=nil{t.Fatal(err)}
	if response.StatusCode!=101{t.Fatalf("expected Upgrade 101, got %s",response.Status)}
	stream,err:=capsule.New(conn,reader,1160)
	if err!=nil{t.Fatal(err)}
	// Valid IPv4 packet, intentionally no per-peer source-address ACL.
	packet:=make([]byte,20)
	packet[0]=0x45;packet[2]=0;packet[3]=20
	copy(packet[12:16],[]byte{203,0,113,5})
	copy(packet[16:20],[]byte{10,77,0,1})
	frame,err:=l3.Wrap(packet)
	if err!=nil{t.Fatal(err)}
	if err:=stream.SendDatagram(frame);err!=nil{t.Fatal(err)}
	select{
	case got:=<-device.out:
		if !bytes.Equal(packet,got){t.Fatal("IP packet changed in TCP fallback")}
	case <-time.After(3*time.Second):t.Fatal("TCP datagram not delivered to the tenant TUN")
	}
}

func TestTCPFallbackHTTPAndAuthRejection(t *testing.T){
	mux:=newServerMux()
	for _,tc:=range []struct{host,sni,method,upgrade string;want int}{
		{"other.example.test","edge-a.example.test","GET","connect-ethernet",421},
		{"edge-a.example.test","edge-a.example.test","POST","connect-ethernet",400},
	}{
		req,err:=http.NewRequest(tc.method,"https://"+tc.host+"/.well-known/masque/ethernet/",nil)
		if err!=nil{t.Fatal(err)}
		req.Host=tc.host
		req.ProtoMajor=1;req.ProtoMinor=1
		req.Header.Set("Connection","Upgrade")
		req.Header.Set("Upgrade",tc.upgrade)
		req.Header.Set("Capsule-Protocol","?1")
		req.TLS=&tls.ConnectionState{ServerName:tc.sni}
		rr:=httptest.NewRecorder()
		mux.ServeTCP(rr,req)
		if rr.Code!=tc.want{t.Fatalf("wrong error: got %d want %d",rr.Code,tc.want)}
	}
}
