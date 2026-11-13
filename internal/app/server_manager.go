package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/p2mp"
	"github.com/roseshot/mqvpn-ebpf/internal/xdp"
)

type preparedInstance struct {
	spec ServerInstance
	peers *p2mp.Config
	peerHash [32]byte
	staticHash [32]byte
}

type preparedServer struct {
	instances map[string]preparedInstance
	xdp xdp.Config
	fingerprint [32]byte
}

// prepareServer validates all referenced peer and mTLS files before attempting
// to modify any running instance. Neither preparing nor applying changes Linux
// interfaces, routes, multicast state, or firewall rules.
func prepareServer(config ServerConfig)(preparedServer,error){
	if err:=config.Validate();err!=nil{return preparedServer{},err}
	next:=preparedServer{instances:make(map[string]preparedInstance,len(config.Instances))}
	digest:=sha256.New()
	if config.XDP!=nil{
		next.xdp=*config.XDP
		if len(next.xdp.Interfaces)>0{
			object,err:=os.ReadFile(next.xdp.Object)
			if err!=nil{return preparedServer{},fmt.Errorf("XDP object %q: %w",next.xdp.Object,err)}
			hashRecord(digest,object)
		}
		xdpSpec,err:=json.Marshal(next.xdp)
		if err!=nil{return preparedServer{},err}
		hashRecord(digest,xdpSpec)
	}
	for _,spec:=range config.Instances{
		peersRaw,err:=os.ReadFile(spec.Peers)
		if err!=nil{return preparedServer{},fmt.Errorf("instance %s peers: %w",spec.Name,err)}
		var peerFile p2mp.FileConfig
		if err:=json.Unmarshal(peersRaw,&peerFile);err!=nil{
			return preparedServer{},fmt.Errorf("instance %s peers JSON: %w",spec.Name,err)
		}
		peers,err:=p2mp.Parse(peerFile)
		if err!=nil{return preparedServer{},fmt.Errorf("instance %s peers validation: %w",spec.Name,err)}
		if _,err:=keyPair(spec.Cert,spec.Key);err!=nil{
			return preparedServer{},fmt.Errorf("instance %s TLS keypair: %w",spec.Name,err)
		}
		if _,err:=certPool(spec.ClientCA);err!=nil{
			return preparedServer{},fmt.Errorf("instance %s client CA: %w",spec.Name,err)
		}
		staticHasher:=sha256.New()
		fields,err:=json.Marshal(spec)
		if err!=nil{return preparedServer{},err}
		hashRecord(staticHasher,fields)
		for _,path:=range []string{spec.Cert,spec.Key,spec.ClientCA}{
			b,err:=os.ReadFile(path)
			if err!=nil{return preparedServer{},fmt.Errorf("instance %s read TLS file %q: %w",spec.Name,path,err)}
			hashRecord(staticHasher,b)
		}
		var staticHash [32]byte
		copy(staticHash[:],staticHasher.Sum(nil))
		p:=preparedInstance{spec:spec,peers:peers,peerHash:sha256.Sum256(peersRaw),staticHash:staticHash}
		next.instances[spec.Name]=p
	}
	names:=make([]string,0,len(next.instances))
	for name:=range next.instances{names=append(names,name)}
	sort.Strings(names)
	for _,name:=range names{
		p:=next.instances[name]
		hashRecord(digest,[]byte(name))
		hashRecord(digest,p.staticHash[:])
		hashRecord(digest,p.peerHash[:])
	}
	copy(next.fingerprint[:],digest.Sum(nil))
	return next,nil
}

func hashRecord(h hash.Hash,data []byte){
	// Prefix lengths keep neighboring fields unambiguous in the digest.
	fmt.Fprintf(h,"%016x",len(data))
	_,_=h.Write(data)
}

func prepareConfigFile(path string)(preparedServer,error){
	cfg,err:=loadServerConfig(path)
	if err!=nil{return preparedServer{},err}
	return prepareServer(cfg)
}

// liveInstance represents a QUIC listener, one attached TUN, and its P2MP
// in-memory session selector. Changes to peer routes are applied in place.
type liveInstance struct {
	prepared preparedInstance
	hub *p2mp.Hub
	cancel context.CancelFunc
	done chan struct{}
	err error // written before done is closed
}

type serverManager struct{
	ctx context.Context
	logger *slog.Logger
	xdp *xdp.Controller
	instances map[string]*liveInstance
	exits chan *liveInstance
}

func newServerManager(ctx context.Context,logger *slog.Logger)*serverManager{
	return &serverManager{
		ctx:ctx,logger:logger,
		instances:make(map[string]*liveInstance),
		xdp:xdp.NewController(),
		exits:make(chan *liveInstance,256),
	}
}

func(m *serverManager)start(p preparedInstance)error{
	ctx,cancel:=context.WithCancel(m.ctx)
	ready:=make(chan *p2mp.Hub,1)
	live:=&liveInstance{prepared:p,cancel:cancel,done:make(chan struct{})}
	go func(){
		live.err=runServerInstance(ctx,p.spec,m.logger.With("instance",p.spec.Name,"tun",p.spec.TUN),ready)
		close(live.done)
		select{
		case m.exits<-live:
		case <-m.ctx.Done():
		}
	}()
	select{
	case hub:=<-ready:
		live.hub=hub
		m.instances[p.spec.Name]=live
		m.logger.Info("VPN instance started","instance",p.spec.Name,"listen",p.spec.Listen,"tun",p.spec.TUN)
		return nil
	case <-live.done:
		cancel()
		return fmt.Errorf("instance %s start failed: %w",p.spec.Name,live.err)
	case <-m.ctx.Done():
		cancel()
		<-live.done
		return m.ctx.Err()
	}
}

func(m *serverManager)stop(name string){
	live:=m.instances[name]
	if live==nil{return}
	delete(m.instances,name)
	live.cancel()
	<-live.done
	m.logger.Info("VPN instance stopped","instance",name)
}

func(m *serverManager)stopAll(){
	for name:=range m.instances{m.stop(name)}
	if m.xdp!=nil{_ = m.xdp.Close()}
}

// apply updates only changed instances. For unchanged listener/TUN/TLS
// configuration, peer route changes are swapped in without closing MPQUIC
// connections. Changed TLS/listener/TUN configuration requires a targeted
// instance restart. Existing unaffected instances remain connected.
func(m *serverManager)apply(next preparedServer)error{
	// All server instance ports are in one map per WAN NIC. This is the
	// *outer* UDP listener table, independent of inner VPN data and peers.
	var listeners []string
	for _,inst:=range next.instances{listeners=append(listeners,inst.spec.Listen)}
	ports,err:=xdp.ListenersToPorts(listeners)
	if err!=nil{return err}
	if m.xdp!=nil{
		if err:=m.xdp.Reconcile(next.xdp,ports);err!=nil{
			return fmt.Errorf("reconcile multi-instance XDP dispatcher: %w",err)
		}
		if len(next.xdp.Interfaces)>0{
			m.logger.Info("XDP instance port maps updated",
				"interfaces",next.xdp.Interfaces,"ports",ports)
		}
	}
	names:=make([]string,0,len(m.instances))
	for name:=range m.instances{names=append(names,name)}
	sort.Strings(names)
	for _,name:=range names{
		old:=m.instances[name]
		newValue,exists:=next.instances[name]
		if !exists{
			m.stop(name)
			continue
		}
		if old.prepared.staticHash!=newValue.staticHash{
			previous:=old.prepared
			m.stop(name)
			if err:=m.start(newValue);err!=nil{
				// Restore the old instance if the replacement cannot start.
				if restoreErr:=m.start(previous);restoreErr!=nil{
					return errors.Join(fmt.Errorf("instance %s replacement: %w",name,err),fmt.Errorf("rollback: %w",restoreErr))
				}
				return fmt.Errorf("instance %s rejected new settings; previous instance restored: %w",name,err)
			}
			continue
		}
		if old.prepared.peerHash!=newValue.peerHash{
			if err:=old.hub.ReplaceConfig(newValue.peers);err!=nil{return err}
			old.prepared=newValue
			m.logger.Info("VPN peer map hot-reloaded","instance",name,"peers",len(newValue.peers.Peers))
		}
	}
	newNames:=make([]string,0,len(next.instances))
	for name:=range next.instances{newNames=append(newNames,name)}
	sort.Strings(newNames)
	for _,name:=range newNames{
		if _,exists:=m.instances[name];exists{continue}
		if err:=m.start(next.instances[name]);err!=nil{return err}
	}
	return nil
}

// runManagedServer supports both signal-driven and optional polling-based
// hot reload. SIGHUP only requests a reload; it never stops the daemon.
// An invalid update is rejected while existing sessions stay connected.
func runManagedServer(ctx context.Context,load func()(preparedServer,error),interval time.Duration,logger *slog.Logger)error{
	if interval<0{return errors.New("--reload-interval cannot be negative")}
	initial,err:=load()
	if err!=nil{return err}
	manager:=newServerManager(ctx,logger)
	defer manager.stopAll()
	if err:=manager.apply(initial);err!=nil{return err}
	applied:=initial.fingerprint
	signals:=make(chan os.Signal,1)
	signal.Notify(signals,syscall.SIGHUP)
	defer signal.Stop(signals)
	var tick <-chan time.Time
	var ticker *time.Ticker
	if interval>0{
		ticker=time.NewTicker(interval)
		defer ticker.Stop()
		tick=ticker.C
	}
	for{
		select{
		case <-ctx.Done():
			return nil
		case live:=<-manager.exits:
			if active:=manager.instances[live.prepared.spec.Name];active==live{
				return fmt.Errorf("VPN instance %s exited unexpectedly: %w",live.prepared.spec.Name,live.err)
			}
		case <-signals:
			next,err:=load()
			if err!=nil{logger.Warn("configuration reload rejected","error",err);continue}
			if next.fingerprint==applied{logger.Debug("configuration reload unchanged");continue}
			if err:=manager.apply(next);err!=nil{logger.Error("configuration reload failed; unaffected instances remain active","error",err);continue}
			applied=next.fingerprint
			logger.Info("configuration hot reload applied","instances",len(next.instances))
		case <-tick:
			next,err:=load()
			if err!=nil{logger.Warn("configuration watch validation failed; keeping running config","error",err);continue}
			if next.fingerprint==applied{continue}
			if err:=manager.apply(next);err!=nil{logger.Error("watched configuration reload failed","error",err);continue}
			applied=next.fingerprint
			logger.Info("watched configuration hot reload applied","instances",len(next.instances))
		}
	}
}
