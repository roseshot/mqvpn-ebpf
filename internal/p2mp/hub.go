package p2mp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/l3"
)

// Stream is a CONNECT-ETHERNET HTTP/3 request stream. Each peer uses its
// own MPQUIC connection; multiple WAN paths are internal to that connection.
type Stream interface {
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte,error)
}

type Session struct {
	rule *Rule
	stream Stream
	tx chan []byte
	done chan struct{}
	limiter *rateLimit
}

func (s *Session) ID() string { return s.rule.ID }

type Hub struct {
	device io.ReadWriteCloser
	cfg *Config
	maxFrame int
	log *slog.Logger
	mu sync.RWMutex
	peers map[string]*Session
	writer sync.Mutex
	localLimiter *rateLimit
	txFrames atomic.Uint64
	rxFrames atomic.Uint64
	drops atomic.Uint64
}

func New(device io.ReadWriteCloser,cfg *Config,maxFrame int,logger *slog.Logger) (*Hub,error) {
	if device==nil || cfg==nil || len(cfg.Peers)==0 {
		return nil,errors.New("hub requires TUN and explicit peer configuration")
	}
	if maxFrame<64 || maxFrame>65535 {
		return nil,fmt.Errorf("invalid maximum Ethernet frame size %d",maxFrame)
	}
	if logger==nil{logger=slog.Default()}
	return &Hub{device:device,cfg:cfg,maxFrame:maxFrame,log:logger,peers:make(map[string]*Session),localLimiter:newRateLimit(cfg.MulticastPPS)},nil
}

func (h *Hub) Authorize(certDER []byte) (*Rule,error) {
	if len(certDER)==0{return nil,errors.New("missing verified TLS client certificate")}
	r:=h.cfg.PeerByCertificate(certDER)
	if r==nil{return nil,errors.New("client certificate not assigned to a permitted site")}
	return r,nil
}

// Attach associates one configured peer with one CONNECT-ETHERNET stream.
// A second connection with the same identity is rejected, not allowed to
// hijack the established session or influence another site.
func (h *Hub) Attach(ctx context.Context,rule *Rule,stream Stream) (*Session,error) {
	if rule==nil || stream==nil{return nil,errors.New("peer rule and stream required")}
	h.mu.Lock()
	if _,exists:=h.peers[rule.ID];exists {h.mu.Unlock();return nil,fmt.Errorf("peer %s is already connected",rule.ID)}
	s:=&Session{rule:rule,stream:stream,tx:make(chan []byte,256),done:make(chan struct{}),limiter:newRateLimit(h.cfg.MulticastPPS)}
	h.peers[rule.ID]=s
	h.mu.Unlock()
	go func(){
		for {
			select {
			case <-ctx.Done():return
			case <-s.done:return
			case packet:=<-s.tx:
				if err:=s.stream.SendDatagram(packet);err!=nil {
					h.drops.Add(1)
					h.log.Debug("QUIC DATAGRAM dropped", "site",s.rule.ID,"error",err)
				}else{h.txFrames.Add(1)}
			}
		}
	}()
	return s,nil
}

func (h *Hub) Detach(s *Session) {
	if s==nil{return}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peers[s.rule.ID]==s {
		delete(h.peers,s.rule.ID)
		close(s.done)
	}
}

func (h *Hub) Receive(ctx context.Context,s *Session) error {
	for {
		payload,err:=s.stream.ReceiveDatagram(ctx)
		if err!=nil {
			if ctx.Err()!=nil || errors.Is(err,io.EOF){return nil}
			return err
		}
		h.ingress(s,payload)
	}
}

// Run is the sole reader of the server's one TUN device. Its IPv4/IPv6
// routes in the Linux main routing table decide which IP packets are emitted;
// the userspace prefix table then resolves the destination peer session.
func (h *Hub) Run(ctx context.Context) error {
	cancelRead:=context.AfterFunc(ctx,func(){_ = h.device.Close()})
	defer cancelRead()
	defer h.device.Close()
	buffer:=make([]byte,65535)
	for {
		n,err:=h.device.Read(buffer)
		if err!=nil {
			if ctx.Err()!=nil || errors.Is(err,io.EOF){return nil}
			return fmt.Errorf("read TUN: %w",err)
		}
		h.egress(buffer[:n])
	}
}

func (h *Hub) ingress(s *Session,payload []byte) {
	packet,err:=l3.Unwrap(payload)
	if err!=nil || len(packet)+l3.EthernetLen>h.maxFrame {
		h.drops.Add(1);return
	}
	src,dst,_,err:=l3.Inspect(packet)
	if err!=nil || !s.rule.Owns(src) {
		// Protect the hub from clients spoofing another site's tunnel IP
		// or advertised LAN prefixes.
		h.drops.Add(1);return
	}
	if dst.IsMulticast() {
		h.multicast(s,dst,packet)
		return
	}
	if l3.IsBroadcastOrMulticastIP(dst) {
		h.drops.Add(1);return
	}
	// Only kernel IP forwarding / firewall rules can route between sites;
	// this path never bypasses them to directly switch peer Ethernet frames.
	h.writer.Lock()
	n,err:=h.device.Write(packet)
	h.writer.Unlock()
	if err!=nil || n!=len(packet) {h.drops.Add(1);return}
	h.rxFrames.Add(1)
}

func (h *Hub) egress(packet []byte) {
	_,dst,_,err:=l3.Inspect(packet)
	if err!=nil || len(packet)+l3.EthernetLen>h.maxFrame {
		h.drops.Add(1);return
	}
	if dst.IsMulticast() {
		h.multicast(nil,dst,packet)
		return
	}
	if l3.IsBroadcastOrMulticastIP(dst) {
		h.drops.Add(1);return
	}
	rule:=h.cfg.Destination(dst)
	if rule==nil{h.drops.Add(1);return}
	h.mu.RLock();s:=h.peers[rule.ID];h.mu.RUnlock()
	if s==nil {h.drops.Add(1);return}
	h.send(s,packet)
}

// multicast is an explicit IP group replication service, NOT L2 flooding.
// Sites not subscribed in the peers JSON never receive a copy. Each site
// is rate-limited before replication; there is no unknown-destination flood.
func (h *Hub) multicast(origin *Session,group netip.Addr,packet []byte) {
	if !validMulticastPacket(group,packet) {
		h.drops.Add(1);return
	}
	var limiter *rateLimit
	if origin==nil{limiter=h.localLimiter}else{
		if !origin.rule.Groups[group]{h.drops.Add(1);return}
		limiter=origin.limiter
	}
	if !limiter.Allow(){h.drops.Add(1);return}
	h.mu.RLock()
	targets:=make([]*Session,0,len(h.peers))
	for _,p:=range h.peers {
		if p!=origin && p.rule.Groups[group]{targets=append(targets,p)}
	}
	h.mu.RUnlock()
	for _,p:=range targets{h.send(p,packet)}
	if origin!=nil {
		// Also deliver to the hub's local TUN as received IP multicast.
		// This does not bridge its physical LAN or forward L2 broadcasts.
		h.writer.Lock()
		n,err:=h.device.Write(packet)
		h.writer.Unlock()
		if err!=nil || n!=len(packet){h.drops.Add(1)}
	}
}

func (h *Hub) send(s *Session,ip []byte) {
	if len(ip)+l3.EthernetLen>h.maxFrame {h.drops.Add(1);return}
	datagram,err:=l3.Wrap(ip)
	if err!=nil {h.drops.Add(1);return}
	select {
	case <-s.done:h.drops.Add(1)
	case s.tx<-datagram:
	default:h.drops.Add(1)
	}
}

func (h *Hub) Counters() (tx,rx,drops uint64){
	return h.txFrames.Load(),h.rxFrames.Load(),h.drops.Load()
}

// mDNS is link-local and must never be treated like arbitrary IP multicast.
// Preserve TTL/HopLimit 255 and require UDP 5353. Only explicit group
// subscribers get a copy; physical LAN mDNS still needs a site-local proxy.
func validMulticastPacket(group netip.Addr,ip []byte) bool {
	if !group.IsMulticast(){return false}
	if group==netip.MustParseAddr("224.0.0.251") {
		if len(ip)<28 || ip[0]>>4!=4 || ip[8]!=255 || ip[9]!=17{return false}
		ihl:=int(ip[0]&0xf)*4
		if len(ip)<ihl+8{return false}
		return ip[ihl+2]==0x14 && ip[ihl+3]==0xe9 // UDP 5353
	}
	if group==netip.MustParseAddr("ff02::fb") {
		if len(ip)<48 || ip[0]>>4!=6 || ip[7]!=255 || ip[6]!=17{return false}
		return ip[42]==0x14 && ip[43]==0xe9
	}
	return true
}

type rateLimit struct {
	mu sync.Mutex
	rate float64
	tokens float64
	last time.Time
}

func newRateLimit(pps int)*rateLimit {
	return &rateLimit{rate:float64(pps),tokens:float64(pps),last:time.Now()}
}

func (b *rateLimit)Allow()bool{
	b.mu.Lock();defer b.mu.Unlock()
	now:=time.Now()
	b.tokens+=now.Sub(b.last).Seconds()*b.rate
	if b.tokens>b.rate {b.tokens=b.rate}
	b.last=now
	if b.tokens<1{return false}
	b.tokens--
	return true
}
