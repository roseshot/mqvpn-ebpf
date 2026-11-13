package capsule

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestVarintBoundaries(t *testing.T) {
	for _,v:=range []uint64{0,1,63,64,16383,16384,1<<30-1,1<<30,1<<62-1}{
		enc:=appendVarint(nil,v)
		got,err:=readVarint(bufio.NewReader(bytes.NewReader(enc)))
		if err!=nil||got!=v{t.Fatalf("%d=>%d err=%v",v,got,err)}
	}
}

func TestCapsuleBidirectionalFrames(t *testing.T){
	a,b:=net.Pipe()
	defer a.Close();defer b.Close()
	left,_:=New(a,nil,1160)
	right,_:=New(b,nil,1160)
	packet:=append([]byte{0},bytes.Repeat([]byte{0x5a},96)...)
	go func(){_ = left.SendDatagram(packet)}()
	got,err:=right.ReceiveDatagram(context.Background())
	if err!=nil||!bytes.Equal(packet,got){t.Fatalf("A=>B: %v",err)}
	go func(){_ = right.SendDatagram(packet)}()
	got,err=left.ReceiveDatagram(context.Background())
	if err!=nil||!bytes.Equal(packet,got){t.Fatalf("B=>A: %v",err)}
}

func TestUnknownCapsuleSkipped(t *testing.T){
	a,b:=net.Pipe()
	defer a.Close();defer b.Close()
	s,_:=New(b,nil,1160)
	go func(){
		p:=appendVarint(nil,0x42)
		p=appendVarint(p,5)
		p=append(p,1,2,3,4,5)
		p=append(p,0,2,0,42) // type 0, length 2, payload [0,42]
		_,_ = a.Write(p)
	}()
	data,err:=s.ReceiveDatagram(context.Background())
	if err!=nil||!bytes.Equal(data,[]byte{0,42}){t.Fatalf("unknown capsule not skipped: %v %v",data,err)}
}

func TestOversizedDatagramRejected(t *testing.T){
	a,b:=net.Pipe()
	defer a.Close();defer b.Close()
	s,_:=New(b,nil,1160)
	go func(){
		p:=appendVarint([]byte{0},1500)
		_,_ = a.Write(p)
	}()
	if _,err:=s.ReceiveDatagram(context.Background());err==nil{t.Fatal("oversize capsule accepted")}
	if err:=s.SendDatagram(bytes.Repeat([]byte{1},2000));err==nil{t.Fatal("oversize send accepted")}
}

func TestReadCancellationClosesStream(t *testing.T){
	a,b:=net.Pipe()
	defer a.Close();defer b.Close()
	s,_:=New(b,nil,1160)
	ctx,cancel:=context.WithCancel(context.Background())
	ends:=make(chan error,1)
	go func(){_,err:=s.ReceiveDatagram(ctx);ends<-err}()
	cancel()
	select {
	case err:=<-ends:
		if err==nil||errors.Is(err,io.EOF){t.Fatalf("expected canceled read error, got %v",err)}
	case <-time.After(time.Second):t.Fatal("blocked capsule read did not cancel")
	}
}
