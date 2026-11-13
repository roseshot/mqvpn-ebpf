//go:build linux

package tcebpf

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEmbeddedTCXCollectionSpec(t *testing.T) {
	if !bytes.HasPrefix(embeddedTC, []byte{0x7f, 'E', 'L', 'F'}) {
		t.Fatal("TCX ELF is not embedded in Go binary")
	}
	spec,err:=LoadSpec("")
	if err!=nil {t.Fatalf("parse embedded TCX ELF: %v",err)}
	for _,name:=range []string{"tc_mqvpn_ingress","tc_mqvpn_egress"}{
		if spec.Programs[name]==nil {t.Fatalf("embedded TCX program %s missing",name)}
	}
	for _,name:=range []string{"tun_config","tun_stats"}{
		if spec.Maps[name]==nil {t.Fatalf("embedded TCX map %s missing",name)}
	}
	path:=filepath.Join(t.TempDir(),"override.o")
	if err:=os.WriteFile(path,embeddedTC,0600);err!=nil{t.Fatal(err)}
	if _,err:=LoadSpec(path);err!=nil{t.Fatalf("external override not loadable: %v",err)}
	if _,err:=LoadSpec(path+".missing");err==nil{t.Fatal("invalid external override silently fell back to embedded program")}
}
