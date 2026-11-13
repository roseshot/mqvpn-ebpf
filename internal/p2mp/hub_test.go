package p2mp

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/l3"
)

type fakeDevice struct {
	mu sync.Mutex
	out [][]byte
}
func (d *fakeDevice)Read([]byte)(int,error){return 0,io.EOF}
func (d *fakeDevice)Write(p []byte)(int,error){
	d.mu.Lock();defer d.mu.Unlock()
	d.out=append(d.out,append([]byte(nil),p...))
	return len(p),nil
}
func (d *fakeDevice)Close()error{return nil}
func (d *fakeDevice)count()int{d.mu.Lock();defer d.mu.Unlock();return len(d.out)}

type fakeStream struct{out chan []byte}
func (f *fakeStream)SendDatagram(p []byte)error{
	f.out<-append([]byte(nil),p...);return nil
}
func (f *fakeStream)ReceiveDatagram(ctx context.Context)([]byte,error){
	<-ctx.Done();return nil,ctx.Err()
}

func ip4(src,dst [4]byte)[]byte{
	p:=make([]byte,20);p[0]=0x45
	binary.BigEndian.PutUint16(p[2:4],20)
	copy(p[12:16],src[:]);copy(p[16:20],dst[:])
	return p
}

func prepare(t *testing.T)(*Hub,*fakeDevice,*Session,*Session,*fakeStream,*fakeStream,context.CancelFunc){
	t.Helper()
	a:=sha256.Sum256([]byte("A"))
	b:=sha256.Sum256([]byte("B"))
	cfg,err:=Parse(FileConfig{MulticastPPS:20,Peers:[]PeerConfig{
		{ID:"A",CertificateSHA256:hex.EncodeToString(a[:]),Routes:[]string{"10.77.0.2/32"},MulticastGroups:[]string{"224.0.0.251"}},
		{ID:"B",CertificateSHA256:hex.EncodeToString(b[:]),Routes:[]string{"10.77.0.3/32"}},
	}})
	if err!=nil{t.Fatal(err)}
	dev:=&fakeDevice{}
	h,err:=New(dev,cfg,1160,nil);if err!=nil{t.Fatal(err)}
	ctx,cancel:=context.WithCancel(context.Background())
	sa:=&fakeStream{out:make(chan []byte,8)}
	sb:=&fakeStream{out:make(chan []byte,8)}
	A,err:=h.Attach(ctx,cfg.Peers[0],sa);if err!=nil{t.Fatal(err)}
	B,err:=h.Attach(ctx,cfg.Peers[1],sb);if err!=nil{t.Fatal(err)}
	return h,dev,A,B,sa,sb,cancel
}

func TestP2MPUnicastAndNoBroadcastFlood(t *testing.T){
	h,dev,a,b,as,bs,cancel:=prepare(t);defer cancel()
	defer h.Detach(a);defer h.Detach(b)
	h.egress(ip4([4]byte{10,77,0,1},[4]byte{10,77,0,3}))
	select{
	case frame:=<-bs.out:
		raw,err:=l3.Unwrap(frame);if err!=nil || len(raw)!=20{t.Fatal(err)}
	case <-time.After(time.Second):t.Fatal("unicast B not delivered")
	}
	select{case <-as.out:t.Fatal("unicast leaked to A");default:}
	h.egress(ip4([4]byte{10,77,0,1},[4]byte{255,255,255,255}))
	select{case <-as.out:t.Fatal("broadcast leaked to A");case <-bs.out:t.Fatal("broadcast leaked to B");default:}
	h.ingress(a,mustFrame(t,ip4([4]byte{10,77,0,3},[4]byte{10,77,0,1})))
	if dev.count()!=0{t.Fatal("A spoofed B source accepted")}
	h.ingress(a,mustFrame(t,ip4([4]byte{10,77,0,2},[4]byte{10,77,0,1})))
	if dev.count()!=1{t.Fatal("valid unicast not delivered to kernel TUN")}
}

func TestMulticastOnlySubscribedAndRateLimited(t *testing.T){
	h,dev,a,b,as,bs,cancel:=prepare(t);defer cancel()
	defer h.Detach(a);defer h.Detach(b)
	p:=make([]byte,28);p[0]=0x45;p[8]=255;p[9]=17
	binary.BigEndian.PutUint16(p[2:4],28)
	copy(p[12:16],[]byte{10,77,0,2})
	copy(p[16:20],[]byte{224,0,0,251})
	binary.BigEndian.PutUint16(p[22:24],5353)
	h.ingress(a,mustFrame(t,p))
	if dev.count()!=1 {t.Fatal("hub local mDNS was not delivered")}
	select{case <-as.out:t.Fatal("reflected to source");case <-bs.out:t.Fatal("unsuscribed peer received group");default:}
	// A subscribed site can receive server-originated mDNS.
	p[12]=10;p[13]=77;p[14]=0;p[15]=1
	h.egress(p)
	select{
	case <-as.out:
	case <-time.After(time.Second):t.Fatal("subscribed site missed mDNS")
	}
	select{case <-bs.out:t.Fatal("unsubscribed site got mDNS");default:}
	if h.cfg.Destination(netip.MustParseAddr("224.0.0.251"))!=nil{t.Fatal("multicast must not resolve to unicast route")}
}

func mustFrame(t *testing.T,p []byte)[]byte{
	t.Helper();f,err:=l3.Wrap(p);if err!=nil{t.Fatal(err)};return f
}
