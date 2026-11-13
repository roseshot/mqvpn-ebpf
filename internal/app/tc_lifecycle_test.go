package app

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/roseshot/mqvpn-ebpf/internal/tcebpf"
)

func TestAutoTCFailureFallsBackButRequiredFails(t *testing.T) {
	logger:=slog.New(slog.NewTextHandler(io.Discard,nil))
	missing:=filepath.Join(t.TempDir(),"missing-tun-tc.o")
	for _,mode:=range []string{"auto","required","off"} {
		cfg:=tcebpf.Config{Mode:mode,Object:missing,MSSClamp:"auto",Stats:true}
		// This missing-interface attach error exercises the same policy path
		// as a missing ELF or unsupported TCX kernel without requiring root.
		got,err:=attachConfiguredTC("mqvpn-no-such-tun",cfg,1400,logger)
		if got!=nil {t.Fatalf("%s: unexpected attached TCX",mode)}
		if (err!=nil)!=(mode=="required"){t.Fatalf("%s: unexpected error %v",mode,err)}
	}
}
