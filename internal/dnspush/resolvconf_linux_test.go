//go:build linux

package dnspush

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

type resolvconfCall struct{exe string;args []string;body string}

func TestResolvconfFallbackUsesInterfaceScopedEntriesAndRollback(t *testing.T){
	var calls []resolvconfCall
	run:=func(exe string,args []string,body []byte)error{
		calls=append(calls,resolvconfCall{exe:exe,args:append([]string(nil),args...),body:string(body)})
		return nil
	}
	lease,err:=applyWithResolvconf("mq0",[]netip.Addr{netip.MustParseAddr("10.77.0.1"),netip.MustParseAddr("fd77::53")},"/usr/sbin/resolvconf",run)
	if err!=nil{t.Fatal(err)}
	if len(calls)!=1||len(calls[0].args)!=2||calls[0].args[0]!="-a" ||
		!strings.HasPrefix(calls[0].args[1],"mq0.mqvpn-") ||
		calls[0].body!="nameserver 10.77.0.1\nnameserver fd77::53\n"{
		t.Fatalf("DNS was not registered as an interface source: %+v",calls)
	}
	if err:=lease.Close();err!=nil{t.Fatal(err)}
	if err:=lease.Close();err!=nil{t.Fatal(err)}
	if len(calls)!=2||calls[1].args[0]!="-d"||calls[1].args[1]!=calls[0].args[1]{
		t.Fatalf("DNS interface source not removed exactly once: %+v",calls)
	}
}
func TestResolvconfFallbackCleanupFailureStopsReconnection(t *testing.T){
	run:=func(_ string,args []string,_ []byte)error{
		if args[0]=="-d"{return errors.New("permission denied")}
		return nil
	}
	lease,err:=applyWithResolvconf("mq0",[]netip.Addr{netip.MustParseAddr("10.77.0.1")},"resolvconf",run)
	if err!=nil{t.Fatal(err)}
	if err:=lease.Close();!errors.Is(err,ErrCleanup){t.Fatalf("cleanup failure not fatal: %v",err)}
}
func TestResolvconfPartialFailureFailsClosed(t *testing.T){
	for _,failedRollback:=range []bool{false,true}{
		run:=func(_ string,args []string,_ []byte)error{
			if args[0]=="-a"{return errors.New("unable to register DNS")}
			if failedRollback{return errors.New("unable to remove entry")}
			return nil
		}
		lease,err:=applyWithResolvconf("mq0",[]netip.Addr{netip.MustParseAddr("10.77.0.1")},"resolvconf",run)
		if lease!=nil||err==nil{t.Fatal("failed interface DNS registration accepted")}
		if errors.Is(err,ErrCleanup)!=failedRollback{t.Fatalf("rollback classification mismatch: %v",err)}
	}
}
func TestFallbackSelectionOnlyWhenSystemdResolvedUnavailable(t *testing.T){
	servers:=[]netip.Addr{netip.MustParseAddr("10.77.0.1")}
	var count int
	alternate:=func(_ string,_ []netip.Addr)(*Lease,error){count++;return &Lease{},nil}
	_,err:=applyWithResolvers("mq0",servers,func(string)(resolverBackend,error){
		return nil,fmt.Errorf("%w: no service owner",errResolvedUnavailable)
	},alternate)
	if err!=nil||count!=1{t.Fatalf("missing systemd-resolved did not fall back: %v count=%d",err,count)}
	_,err=applyWithResolvers("mq0",servers,func(string)(resolverBackend,error){
		return nil,errors.New("systemd-resolved access denied")
	},alternate)
	if err==nil||count!=1{t.Fatalf("active resolver errors must not silently fall back: %v count=%d",err,count)}
}
