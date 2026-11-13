//go:build linux

package xdp

import (
	"reflect"
	"testing"
)

func TestConfigNormalize(t *testing.T){
	cfg,err:=(Config{Interfaces:[]string{"enp2s0","enp1s0"},Object:"/tmp/xdp.o"}).Normalize()
	if err!=nil{t.Fatal(err)}
	if cfg.Mode!="driver"||!reflect.DeepEqual(cfg.Interfaces,[]string{"enp1s0","enp2s0"}){
		t.Fatalf("normalize returned %+v",cfg)
	}
	embedded,err:=(Config{Interfaces:[]string{"enp1s0"}}).Normalize()
	if err!=nil||embedded.Object!=""||embedded.Mode!="driver" {
		t.Fatalf("embedded XDP ELF should be default when interfaces are set: %+v %v",embedded,err)
	}
	for _,bad:=range []Config{
		{Object:"xdp.o"},
		{Interfaces:[]string{"eth0","eth0"},Object:"xdp.o"},
		{Interfaces:[]string{"eth0"},Object:"xdp.o",Mode:"offload"},
	}{
		if _,err:=bad.Normalize();err==nil{t.Fatalf("accepted %+v",bad)}
	}
}

func TestListenersToPorts(t *testing.T){
	got,err:=ListenersToPorts([]string{":4435","0.0.0.0:4433","[::]:4435"})
	if err!=nil{t.Fatal(err)}
	if !reflect.DeepEqual(got,[]uint16{4433,4435}){t.Fatal(got)}
	for _,bad:=range []string{":0","bad","127.0.0.1:not-a-port"}{
		if _,err:=ListenersToPorts([]string{bad});err==nil{t.Fatal("accepted",bad)}
	}
}
