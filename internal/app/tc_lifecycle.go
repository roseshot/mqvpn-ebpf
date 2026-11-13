package app

import (
	"log/slog"

	"github.com/roseshot/mqvpn-ebpf/internal/tcebpf"
)

// attachConfiguredTC fails open only in auto mode. Required remains strict.
func attachConfiguredTC(ifname string, policy tcebpf.Config, mtu int, logger *slog.Logger) (*tcebpf.Attachment,error) {
	if logger==nil {logger=slog.Default()}
	norm,err:=policy.Normalize()
	if err!=nil{return nil,err}
	if !norm.Enabled(){return nil,nil}
	attached,err:=tcebpf.Attach(ifname,norm,mtu)
	if err!=nil {
		if norm.Mode=="auto" {
			logger.Warn("TUN TC eBPF unavailable; using ordinary TUN forwarding", "tun",ifname,"object",norm.Object,"error",err)
			return nil,nil
		}
		return nil,err
	}
	logger.Info("TUN TC eBPF attached", "tun",ifname,"mode",norm.Mode,"mss_clamp",norm.MSSClamp,"stats",norm.Stats)
	return attached,nil
}

// Log counters after the forwarding pump exits and detach TCX before
// shutdown. Both QUIC and TCP fallback share the same attachment lifecycle.
func reportAndCloseTC(tc *tcebpf.Attachment,logger *slog.Logger) {
	if tc==nil{return}
	if counters,err:=tc.Snapshot();err==nil{
		logger.Info("TUN TC eBPF counters","ingress",counters.Ingress,"egress",counters.Egress)
	}else{logger.Warn("read TUN TC eBPF counters","error",err)}
	if err:=tc.Close();err!=nil{logger.Warn("detach TUN TC eBPF","error",err)}
}
