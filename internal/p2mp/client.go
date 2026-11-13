package p2mp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/roseshot/mqvpn-ebpf/internal/l3"
)

// GroupList is a comma-separated list of exact IPv4/IPv6 multicast
// destinations permitted over the routed tunnel. No group is enabled by
// default. Configure the same set on the server's peer entry.
func GroupList(raw string) (map[netip.Addr]bool,error) {
	groups:=map[netip.Addr]bool{}
	if strings.TrimSpace(raw)==""{return groups,nil}
	for _,item:=range strings.Split(raw,","){
		a,err:=netip.ParseAddr(strings.TrimSpace(item))
		if err!=nil || !a.IsMulticast(){return nil,fmt.Errorf("invalid multicast address %q",item)}
		groups[a]=true
	}
	return groups,nil
}

// ClientPump presents a single IP-addressed Linux TUN to the client OS,
// but encodes a complete synthetic Ethernet frame for each QUIC DATAGRAM.
// A standalone client never learns other sites' MACs or bridges broadcasts.
func ClientPump(ctx context.Context,device io.ReadWriteCloser,stream Stream,maxFrame int,groups map[netip.Addr]bool,pps int,logger *slog.Logger)error{
	if maxFrame<64 || maxFrame>65535{return fmt.Errorf("invalid maxFrame %d",maxFrame)}
	if pps<1 || pps>1000{return errors.New("multicast pps must be 1..1000")}
	if logger==nil{logger=slog.Default()}
	ctx,cancel:=context.WithCancel(ctx);defer cancel()
	limiter:=newRateLimit(pps)
	ends:=make(chan error,2)
	go func(){
		buffer:=make([]byte,65535)
		for {
			n,err:=device.Read(buffer)
			if err!=nil{ends<-err;return}
			if n+l3.EthernetLen>maxFrame{continue}
			_,dst,_,err:=l3.Inspect(buffer[:n])
			if err!=nil || !allowedDestination(dst,buffer[:n],groups,limiter){continue}
			payload,err:=l3.Wrap(buffer[:n])
			if err!=nil{continue}
			if err:=stream.SendDatagram(payload);err!=nil{
				logger.Debug("client QUIC datagram drop","error",err)
			}
		}
	}()
	go func(){
		for {
			payload,err:=stream.ReceiveDatagram(ctx)
			if err!=nil{ends<-err;return}
			pkt,err:=l3.Unwrap(payload)
			if err!=nil || len(pkt)+l3.EthernetLen>maxFrame{continue}
			_,dst,_,err:=l3.Inspect(pkt)
			if err!=nil || !allowedDestination(dst,pkt,groups,limiter){continue}
			n,err:=device.Write(pkt)
			if err!=nil{ends<-err;return}
			if n!=len(pkt){ends<-fmt.Errorf("short TUN write: %d / %d",n,len(pkt));return}
		}
	}()
	var err error
	select {
	case <-ctx.Done():err=ctx.Err()
	case err=<-ends:
	}
	cancel()
	_ = device.Close()
	if errors.Is(err,context.Canceled)||errors.Is(err,io.EOF){return nil}
	return err
}

func allowedDestination(dst netip.Addr,packet []byte,groups map[netip.Addr]bool,limiter *rateLimit)bool{
	if dst.IsMulticast(){
		return groups[dst] && validMulticastPacket(dst,packet) && limiter.Allow()
	}
	return !l3.IsBroadcastOrMulticastIP(dst)
}
