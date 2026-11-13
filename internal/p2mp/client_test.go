package p2mp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/l3"
)

type testTun struct{
	in chan []byte
	stop chan struct{}
	once sync.Once
	mu sync.Mutex
	out [][]byte
}
func newTestTun()*testTun{return &testTun{in:make(chan []byte,8),stop:make(chan struct{})}}
func(d *testTun)Read(buf []byte)(int,error){
	select{
	case <-d.stop:return 0,io.EOF
	case packet:=<-d.in:
		return copy(buf,packet),nil
	}
}
func(d *testTun)Write(packet []byte)(int,error){
	d.mu.Lock();defer d.mu.Unlock()
	d.out=append(d.out,append([]byte(nil),packet...))
	return len(packet),nil
}
func(d *testTun)Close()error{d.once.Do(func(){close(d.stop)});return nil}
func(d *testTun)hasOutput()bool{d.mu.Lock();defer d.mu.Unlock();return len(d.out)>0}

type testDatagrams struct{
	in chan []byte
	out chan []byte
}
func(s *testDatagrams)SendDatagram(p []byte)error{
	s.out<-append([]byte(nil),p...)
	return nil
}
func(s *testDatagrams)ReceiveDatagram(ctx context.Context)([]byte,error){
	select{
	case <-ctx.Done():return nil,ctx.Err()
	case data:=<-s.in:return data,nil
	}
}

func TestClientForwardsMulticastWithoutFiltering(t *testing.T){
	device:=newTestTun()
	stream:=&testDatagrams{in:make(chan []byte,2),out:make(chan []byte,2)}
	ctx,cancel:=context.WithCancel(context.Background())
	defer cancel()
	done:=make(chan error,1)
	go func(){done<-ClientPump(ctx,device,stream,1160,slog.New(slog.NewTextHandler(io.Discard,nil)))}()
	// Deliberately not UDP/5353, not TTL 255: transport must not impose
	// an mDNS/port/TTL-specific policy on tunnel contents.
	multicast:=ip4([4]byte{10,77,0,2},[4]byte{224,0,0,251})
	multicast[8]=3
	multicast[9]=1
	device.in<-multicast
	var encoded []byte
	select{
	case encoded=<-stream.out:
	case <-time.After(time.Second):t.Fatal("client filtered outgoing multicast")
	}
	roundtrip,err:=l3.Unwrap(encoded)
	if err!=nil||string(roundtrip)!=string(multicast){t.Fatalf("packet changed %v",err)}
	stream.in<-encoded
	deadline:=time.After(time.Second)
	for !device.hasOutput(){
		select{
		case <-deadline:t.Fatal("client filtered incoming multicast")
		default:time.Sleep(time.Millisecond)
		}
	}
	cancel()
	select{
	case err:=<-done:
		if err!=nil&&!errors.Is(err,context.Canceled){t.Fatal(err)}
	case <-time.After(time.Second):t.Fatal("client shutdown stuck")
	}
}
