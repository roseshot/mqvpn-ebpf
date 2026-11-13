package mtu

import (
	"strings"
	"testing"
)

func TestAutoWANBudgets(t *testing.T) {
	cases := []struct {
		name,address string
		paths []Underlay
		wantMTU, wantFrame int
	}{
		{"v4-1500","10.77.0.1/24",[]Underlay{{"enp1s0",1500,false}},1400,1414},
		{"v6-1500","10.77.0.1/24",[]Underlay{{"enp1s0",1500,true}},1380,1394},
		{"pppoe","10.77.0.1/24",[]Underlay{{"ppp0",1492,false}},1392,1406},
		{"mobile","10.77.0.1/24",[]Underlay{{"wwan0",1420,false}},1320,1334},
		{"dual-min","10.77.0.1/24",[]Underlay{{"enp1s0",1500,false},{"wwan0",1420,true}},1300,1314},
		{"jumboframe-capped","10.77.0.1/24",[]Underlay{{"enp1s0",9000,false}},1400,1414},
		{"inner-v6","fd77::1/64",[]Underlay{{"enp1s0",1500,false}},1400,1414},
	}
	for _, tc := range cases {
		got,err:=Plan("mq0",tc.address,0,0,tc.paths)
		if err!=nil {t.Fatalf("%s: %v",tc.name,err)}
		if got.TUNMTU!=tc.wantMTU || got.MaxFrame!=tc.wantFrame || !got.Auto {
			t.Fatalf("%s: %+v",tc.name,got)
		}
	}
}

func TestExplicitOverridesWANDetection(t *testing.T) {
	got,err:=Plan("mq0","10.77.0.1/24",1360,0,nil)
	if err!=nil||got.TUNMTU!=1360||got.MaxFrame!=1374||got.Auto {
		t.Fatalf("explicit MTU should not require WAN lookup: %+v %v",got,err)
	}
	got,err=Plan("mq0","10.77.0.1/24",1400,1430,nil)
	if err!=nil||got.MaxFrame!=1430{t.Fatalf("larger explicit frame rejected: %+v %v",got,err)}
}

func TestPlanRejectsInsufficientWANAndFrame(t *testing.T) {
	for _,tc:=range []struct{address string;mtu,frame int;paths []Underlay}{
		{"10.77.0.1/24",0,0,nil},
		{"10.77.0.1/24",0,0,[]Underlay{{"bad",0,false}}},
		{"10.77.0.1/24",0,1410,[]Underlay{{"nic",1500,false}}},
		{"fd77::1/64",0,0,[]Underlay{{"ppp0",1350,true}}},
		{"10.77.0.1/24",1400,1400,nil},
	}{
		if _,err:=Plan("mq0",tc.address,tc.mtu,tc.frame,tc.paths);err==nil{
			t.Fatalf("accepted MTU %d, frame %d, paths %+v",tc.mtu,tc.frame,tc.paths)
		}
	}
	if _,err:=Plan("mq0","fd77::1/64",0,0,[]Underlay{{"low",1350,true}});err==nil||!strings.Contains(err.Error(),"MTU"){
		t.Fatalf("unexpected low IPv6 WAN error %v",err)
	}
}

func TestValidateRequestDefersWANLookups(t *testing.T) {
	if err:=ValidateRequest("mq0","10.77.0.1/24",0,0);err!=nil{t.Fatal(err)}
	if err:=ValidateRequest("mq0","fd77::1/64",0,0);err!=nil{t.Fatal(err)}
	if err:=ValidateRequest("mq0","10.77.0.1/24",0,1200);err!=nil{t.Fatalf("runtime WAN plan should decide auto frame budget: %v",err)}
	for _,tc:=range []struct{address string;mtu,frame int}{
		{"10.77.0.1/24",-1,0},
		{"10.77.0.1/24",1400,-1},
		{"10.77.0.1/24",1400,1400},
		{"fd77::1/64",1000,0},
		{"",0,0},
	}{
		if err:=ValidateRequest("mq0",tc.address,tc.mtu,tc.frame);err==nil{t.Fatalf("accepted %+v",tc)}
	}
}
