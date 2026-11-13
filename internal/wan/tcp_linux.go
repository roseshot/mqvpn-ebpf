//go:build linux

package wan

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

// DialTCP preserves primary-WAN source/interface pinning for TLS fallback.
// Linux still manages the underlay routes; this code only binds a socket.
func DialTCP(ctx context.Context,sourceIP,interfaceName string,peer *net.TCPAddr)(net.Conn,net.IP,error){
	if peer==nil||peer.IP==nil{return nil,nil,fmt.Errorf("resolved TCP peer IP is required")}
	ip,err:=ResolveSource(sourceIP,interfaceName,&net.UDPAddr{IP:peer.IP})
	if err!=nil{return nil,nil,err}
	network:="tcp4"
	if ip.To4()==nil{network="tcp6"}
	dialer:=&net.Dialer{LocalAddr:&net.TCPAddr{IP:ip}}
	if interfaceName!=""{
		dialer.Control=func(network,address string,raw syscall.RawConn)error{
			var setErr error
			if err:=raw.Control(func(fd uintptr){
				setErr=syscall.SetsockoptString(int(fd),syscall.SOL_SOCKET,syscall.SO_BINDTODEVICE,interfaceName)
			});err!=nil{return err}
			if setErr!=nil{return fmt.Errorf("SO_BINDTODEVICE %q: %w",interfaceName,setErr)}
			return nil
		}
	}
	conn,err:=dialer.DialContext(ctx,network,peer.String())
	if err!=nil{return nil,nil,fmt.Errorf("dial TCP fallback via %s: %w",ip,err)}
	return conn,ip,nil
}
