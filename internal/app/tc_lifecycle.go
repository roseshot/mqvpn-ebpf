package app

import (
	"log/slog"

	"github.com/roseshot/mqvpn-ebpf/internal/tcebpf"
)

// Log counters after the forwarding pump exits and detach TCX before
// shutdown. Both QUIC and TCP fallback share the same attachment lifecycle.
func reportAndCloseTC(tc *tcebpf.Attachment,logger *slog.Logger) {
	if tc==nil{return}
	if counters,err:=tc.Snapshot();err==nil{
		logger.Info("TUN TC eBPF counters","ingress",counters.Ingress,"egress",counters.Egress)
	}else{logger.Warn("read TUN TC eBPF counters","error",err)}
	if err:=tc.Close();err!=nil{logger.Warn("detach TUN TC eBPF","error",err)}
}
