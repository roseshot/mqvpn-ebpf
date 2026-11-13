package forward

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/ethernet"
)

type fakeTAP struct { r *io.PipeReader; w *io.PipeWriter; mx sync.Mutex; received [][]byte }
func newFakeTAP() *fakeTAP { r, w := io.Pipe(); return &fakeTAP{r:r, w:w} }
func (f *fakeTAP) Read(p []byte) (int,error) { return f.r.Read(p) }
func (f *fakeTAP) Write(p []byte) (int,error) { f.mx.Lock(); defer f.mx.Unlock(); f.received=append(f.received, append([]byte(nil),p...));return len(p),nil }
func (f *fakeTAP) Close() error { _=f.w.Close();return f.r.Close() }
type fakeDatagrams struct { inbound chan []byte; outbound chan []byte }
func (f *fakeDatagrams) SendDatagram(p []byte) error { f.outbound<-append([]byte(nil),p...); return nil }
func (f *fakeDatagrams) ReceiveDatagram(ctx context.Context) ([]byte,error) { select {case p:= <-f.inbound:return p,nil;case <-ctx.Done():return nil,ctx.Err()} }

func TestPump(t *testing.T) {
	dev:=newFakeTAP()
	dg:=&fakeDatagrams{inbound:make(chan []byte,2),outbound:make(chan []byte,2)}
	var stats Counters
	ctx,cancel:=context.WithCancel(context.Background())
	done:=make(chan error,1)
	go func(){done<-Run(ctx,dev,dg,1160,&stats,slog.New(slog.NewTextHandler(io.Discard,nil)))}()
	frame:=make([]byte,60)
	if _,err:=dev.w.Write(frame);err!=nil {t.Fatal(err)}
	select {
	case payload:= <-dg.outbound:
		got,err:=ethernet.Decode(payload)
		if err!=nil||len(got)!=len(frame) {t.Fatalf("bad datagram: %v",err)}
	case <-time.After(time.Second): t.Fatal("forwarding timed out")
	}
	payload,_:=ethernet.Encode(frame)
	dg.inbound<-payload
	deadline:=time.After(time.Second)
	for {
		dev.mx.Lock(); count:=len(dev.received); dev.mx.Unlock()
		if count!=0 {break}
		select {case <-deadline: t.Fatal("reverse forwarding timed out");default:time.Sleep(time.Millisecond)}
	}
	cancel()
	select {case err:=<-done:if err!=nil && !errors.Is(err,context.Canceled){t.Fatal(err)};case <-time.After(time.Second):t.Fatal("pump did not stop")}
	if got:=stats.Snapshot();got.TXFrames!=1||got.RXFrames!=1 {t.Fatalf("unexpected counters: %+v",got)}
}
