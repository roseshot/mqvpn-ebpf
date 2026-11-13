package tcebpf

import "testing"

func TestClampLimits(t *testing.T){
	for _,tc:=range []struct{mode string;mtu int;v4,v6 uint16;enabled uint32}{
		{"off",1400,0,0,0},
		{"auto",1400,1360,1340,1},
		{"",1400,0,0,0},
		{"1300",1400,1300,1300,1},
		{"1360",1400,1360,1340,1},
		{"auto",1280,1240,1220,1},
		{"auto",1360,1320,1300,1},
	}{
		got,err:=EffectiveLimits(tc.mtu,tc.mode)
		if err!=nil{t.Fatalf("%+v: %v",tc,err)}
		if got.MSS4!=tc.v4||got.MSS6!=tc.v6||got.Clamp!=tc.enabled{
			t.Fatalf("%+v got %+v",tc,got)
		}
	}
}

func TestNormalizeRejectsMissingELFAndInvalidMode(t *testing.T){
	for _,tc:=range []Config{
		{MSSClamp:"auto"},{Stats:true},{Object:"file.o",MSSClamp:"abc"},
		{Object:"file.o",MSSClamp:"-2"},{Object:"file.o",MSSClamp:"65536"},
		{Object:"file.o",MSSClamp:"250"},
	}{
		if _,err:=tc.Normalize();err==nil{t.Fatalf("invalid TC config accepted: %+v",tc)}
	}
	for _,tc:=range []Config{{},{Object:"file.o",Stats:true},{Object:"file.o",MSSClamp:"auto"},{Object:"file.o",MSSClamp:"1280"}}{
		if _,err:=tc.Normalize();err!=nil{t.Fatalf("valid TC config rejected %+v: %v",tc,err)}
	}
}
