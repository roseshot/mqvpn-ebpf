package l3

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func v4(src, dst [4]byte) []byte {
	p:=make([]byte,20)
	p[0]=0x45
	binary.BigEndian.PutUint16(p[2:4],20)
	copy(p[12:16],src[:]); copy(p[16:20],dst[:])
	return p
}

func TestWrapUnwrapIPv4(t *testing.T){
	p:=v4([4]byte{10,77,0,1},[4]byte{10,77,0,2})
	w,err:=Wrap(p)
	if err!=nil{t.Fatal(err)}
	if len(w)!=len(p)+15 || w[0]!=0 || w[13]!=0x08 || w[14]!=0x00{t.Fatalf("wrong frame header %x",w[:15])}
	u,err:=Unwrap(w)
	if err!=nil || string(u)!=string(p){t.Fatalf("roundtrip %x: %v",u,err)}
	s,d,_,_:=Inspect(u)
	if s.String()!="10.77.0.1" || d.String()!="10.77.0.2"{t.Fatal(s,d)}
}

func TestWrapIPv6(t *testing.T){
	p:=make([]byte,40);p[0]=0x60
	src:=netip.MustParseAddr("fd42::2").As16()
	dst:=netip.MustParseAddr("fd42::3").As16()
	copy(p[8:24],src[:]);copy(p[24:40],dst[:])
	w,err:=Wrap(p);if err!=nil{t.Fatal(err)}
	if w[13]!=0x86 || w[14]!=0xdd{t.Fatal(w[:15])}
	if _,err:=Unwrap(w);err!=nil{t.Fatal(err)}
}

func TestRejectNonIP(t *testing.T) {
	p:=v4([4]byte{10,77,0,1},[4]byte{10,77,0,2})
	w,_:=Wrap(p)
	w[14]=6
	if _,err:=Unwrap(w);err==nil{t.Fatal("ARP should be rejected")}
	if _,err:=Wrap([]byte{0});!errors.Is(err,ErrInvalidIP){t.Fatal(err)}
}
