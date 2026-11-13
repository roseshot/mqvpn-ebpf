package p2mp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/roseshot/mqvpn-ebpf/internal/l3"
)

// Stream is a CONNECT-ETHERNET HTTP/3 DATAGRAM stream.
type Stream interface{
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context)([]byte,error)
}

type Session struct{
	rule *Rule
	stream Stream
	tx chan []byte
	done chan struct{}
	ctx context.Context
	cancel context.CancelFunc
}
func(s *Session)ID()string{return s.rule.ID}

type Hub struct{
	device io.ReadWriteCloser
	cfg *Config
	maxFrame int
	log *slog.Logger
	mu sync.RWMutex
	peers map[string]*Session
	writer sync.Mutex
	txFrames atomic.Uint64
	rxFrames atomic.Uint64
	drops atomic.Uint64
}

func New(device io.ReadWriteCloser,cfg *Config,maxFrame int,logger *slog.Logger)(*Hub,error){
	if device==nil||cfg==nil||len(cfg.Peers)==0{return nil,errors.New("hub requires TUN and peer destinations")}
	if maxFrame<64||maxFrame>65535{return nil,fmt.Errorf("invalid maxFrame %d",maxFrame)}
	if logger==nil{logger=slog.Default()}
	return &Hub{device:device,cfg:cfg,maxFrame:maxFrame,log:logger,peers:make(map[string]*Session)},nil
}

// Authentication is applied only while establishing a tunnel session.
func(h *Hub)Authorize(certDER []byte)(*Rule,error){
	if len(certDER)==0{return nil,errors.New("missing client certificate")}
	h.mu.RLock()
	rule:=h.cfg.PeerByCertificate(certDER)
	h.mu.RUnlock()
	if rule==nil{return nil,errors.New("certificate not associated with a P2MP session")}
	return rule,nil
}

func(h *Hub)Attach(ctx context.Context,rule *Rule,stream Stream)(*Session,error){
	if rule==nil||stream==nil{return nil,errors.New("peer and stream required")}
	h.mu.Lock()
	// An authorization result may have been computed just before a reload.
	// Verify it against the live config while holding the same lock as reload.
	valid:=false
	for _,current:=range h.cfg.Peers{
		if current.ID==rule.ID && current.Fingerprint==rule.Fingerprint {valid=true;break}
	}
	if !valid{h.mu.Unlock();return nil,fmt.Errorf("peer %s authentication changed during reload",rule.ID)}
	if _,exists:=h.peers[rule.ID];exists{h.mu.Unlock();return nil,fmt.Errorf("peer %s already connected",rule.ID)}
	sessionCtx,sessionCancel:=context.WithCancel(ctx)
	s:=&Session{rule:rule,stream:stream,tx:make(chan []byte,256),done:make(chan struct{}),ctx:sessionCtx,cancel:sessionCancel}
	h.peers[rule.ID]=s
	h.mu.Unlock()
	go func(){
		for{
			select{
			case <-ctx.Done():return
			case <-s.done:return
			case payload:=<-s.tx:
				if err:=s.stream.SendDatagram(payload);err!=nil{
					h.drops.Add(1)
					h.log.Debug("QUIC DATAGRAM rejected","peer",s.ID(),"error",err)
				}else{h.txFrames.Add(1)}
			}
		}
	}()
	return s,nil
}

func(h *Hub)Detach(s *Session){
	if s==nil{return}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peers[s.ID()]==s{
		delete(h.peers,s.ID())
		s.cancel()
		close(s.done)
	}
}

func(h *Hub)Receive(ctx context.Context,s *Session)error{
	for{
		payload,err:=s.stream.ReceiveDatagram(s.ctx)
		if err!=nil{
			if s.ctx.Err()!=nil||ctx.Err()!=nil||errors.Is(err,io.EOF){return nil}
			return err
		}
		h.ingress(s,payload)
	}
}

// A single TUN reader handles packets the Linux routing stack emitted on
// the VPN interface. No daemon-managed routes, ACLs or multicast memberships.
func(h *Hub)Run(ctx context.Context)error{
	stopRead:=context.AfterFunc(ctx,func(){_ = h.device.Close()})
	defer stopRead()
	defer h.device.Close()
	buf:=make([]byte,65535)
	for{
		n,err:=h.device.Read(buf)
		if err!=nil{
			if ctx.Err()!=nil||errors.Is(err,io.EOF){return nil}
			return fmt.Errorf("read TUN: %w",err)
		}
		h.egress(buf[:n])
	}
}

func(h *Hub)writeTUN(packet []byte){
	h.writer.Lock()
	n,err:=h.device.Write(packet)
	h.writer.Unlock()
	if err!=nil||n!=len(packet){h.drops.Add(1);return}
	h.rxFrames.Add(1)
}

// Ingress never examines a peer's inner source or port. Network policy is
// owned by the Linux IP stack and firewall after writing to the TUN.
func(h *Hub)ingress(origin *Session,payload []byte){
	packet,err:=l3.Unwrap(payload)
	if err!=nil||len(packet)+l3.EthernetLen>h.maxFrame{h.drops.Add(1);return}
	_,dst,_,err:=l3.Inspect(packet)
	if err!=nil{h.drops.Add(1);return}
	if dst.IsMulticast()||l3.IsBroadcastOrMulticastIP(dst){
		// P2MP IP multicast/broadcast delivered to every other connected
		// tunnel endpoint, without group allowlists, TTL rewriting or PPS caps.
		h.fanout(origin,packet)
	}
	h.writeTUN(packet)
}

func(h *Hub)egress(packet []byte){
	_,dst,_,err:=l3.Inspect(packet)
	if err!=nil||len(packet)+l3.EthernetLen>h.maxFrame{h.drops.Add(1);return}
	if dst.IsMulticast()||l3.IsBroadcastOrMulticastIP(dst){
		h.fanout(nil,packet)
		return
	}
	h.mu.RLock()
	rule:=h.cfg.Destination(dst)
	if rule==nil{
		h.mu.RUnlock()
		// No remote session owns this destination; the daemon cannot
		// infer a next hop from an IP packet emitted by the shared TUN.
		h.drops.Add(1)
		h.log.Debug("no P2MP destination","destination",dst)
		return
	}
	peer:=h.peers[rule.ID]
	h.mu.RUnlock()
	if peer==nil{h.drops.Add(1);return}
	h.send(peer,packet)
}

// Replicate IP multicast/broadcast to peers in this VPN instance only.
// Physical LAN Ethernet frames cannot enter via a Layer-3 TUN.
func(h *Hub)fanout(origin *Session,packet []byte){
	h.mu.RLock()
	targets:=make([]*Session,0,len(h.peers))
	for _,s:=range h.peers{
		if s!=origin{targets=append(targets,s)}
	}
	h.mu.RUnlock()
	for _,s:=range targets{h.send(s,packet)}
}

func(h *Hub)send(s *Session,packet []byte){
	payload,err:=l3.Wrap(packet)
	if err!=nil{h.drops.Add(1);return}
	select{
	case <-s.done:h.drops.Add(1)
	case s.tx<-payload:
	default:
		// Only bounded I/O queue pressure can drop an otherwise valid
		// packet. This is not a protocol/group/source traffic policy.
		h.drops.Add(1)
	}
}
func(h *Hub)Counters()(tx,rx,drops uint64){
	return h.txFrames.Load(),h.rxFrames.Load(),h.drops.Load()
}


// ReplaceConfig atomically swaps the peer-to-session destination map.
// Established connections with unchanged (peer ID, certificate fingerprint)
// remain up, including when their destination prefixes change. A revoked or
// rotated certificate cancels its old session. No Linux routes, addresses,
// multicast memberships, or TUN state are changed here.
func (h *Hub) ReplaceConfig(next *Config) error {
	if next==nil || len(next.Peers)==0 {return errors.New("replacement peers configuration is empty")}
	h.mu.Lock()
	defer h.mu.Unlock()
	accepted:=make(map[string][32]byte,len(next.Peers))
	for _,rule:=range next.Peers{accepted[rule.ID]=rule.Fingerprint}
	for id,s:=range h.peers {
		fingerprint,ok:=accepted[id]
		if !ok || fingerprint!=s.rule.Fingerprint {
			delete(h.peers,id)
			s.cancel()
			close(s.done)
			h.log.Info("peer session revoked by config reload","peer",id)
		}
	}
	h.cfg=next
	h.log.Info("P2MP forwarding table reloaded","peers",len(next.Peers))
	return nil
}
